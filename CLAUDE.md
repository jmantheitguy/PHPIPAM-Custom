# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Docker-based IP Address Management (IPAM) system combining PHPIPAM 1.6.0 with Active Directory authentication, network scanning (ICMP/ARP/NDP), and a network intelligence pipeline (DNS reconciliation, DHCP correlation, change detection, IP conflict detection, utilization tracking).

## Development Commands

```bash
# Initial setup (generates passwords, SSL certs, downloads PHPIPAM v1.6.0)
./setup.sh

# Start/stop all containers
docker compose up -d
docker compose down

# Rebuild specific container after Dockerfile changes
docker compose build php-fpm && docker compose up -d php-fpm

# View logs
docker compose logs -f
docker compose logs -f php-fpm

# Access container shell
docker compose exec php-fpm sh
docker compose exec mysql mysql -u root -p

# Import database schema (if needed)
docker compose exec -T mysql mysql -u root -p<password> phpipam < phpipam/db/SCHEMA.sql
docker compose exec -T mysql mysql -u root -p<password> phpipam < database/init/01-schema-extensions.sql
docker compose exec -T mysql mysql -u root -p<password> phpipam < database/init/02-network-intelligence.sql

# Scanning scripts (run inside scanner or php-fpm container)
./scripts/subnet-scan.sh 192.168.1.0/24 [scan_id]
./scripts/ip-ping.sh 192.168.1.1                    # single IP
./scripts/ip-ping.sh 192.168.1.1-192.168.1.50       # IP range
./scripts/ip-ping.sh -f ip_list.txt -j              # file input, JSON output
./scripts/mac-arp-scanner.sh eth0 192.168.1.0/24     # ARP/MAC discovery
```

## Architecture

```
           ipam-network (172.28.0.0/16)          scanner-internal (172.29.0.0/16, no external routing)
          ┌──────────────────────────────┐      ┌──────────────────────────┐
          │                              │      │                          │
nginx:443 ──► php-fpm:9000 ──► mysql:3306 ◄─────── subnet-scanner
          │                       │      │      │       │                  │
          │                   redis:6379 ◄──────────────┘                  │
          │                              │      │                          │
          └──────────────────────────────┘      └──────────────────────────┘
```

**Two isolated Docker networks** enforce security boundaries:
- `ipam-network` (bridge, 172.28.0.0/16) — nginx, php-fpm, mysql, redis. Public-facing.
- `scanner-internal` (bridge, 172.29.0.0/16, `internal: true`) — subnet-scanner, mysql, redis. No host-level routing. Isolates the scanner (which has `NET_RAW`/`NET_ADMIN` capabilities) from the web-facing network.

The scanner has **no access** to `ipam-network` and cannot be reached from outside. It communicates with mysql and redis only via `scanner-internal`.

### Key Configuration Files

- `docker-compose.yml` — Container orchestration (no version field, Compose v5+)
- `.env` — Credentials and config (generated from `.env.example` by `setup.sh`)
- `config/phpipam/config.php` — PHPIPAM database, Redis, AD, and custom subpage registration
- `config/phpipam/ldap_settings.php` — AD/LDAP authentication helpers (`ldap_authenticate_user()`, `ldap_is_admin()`, `ldap_get_role()`)
- `docker/scanner/scanner.py` — Python scanner service main loop
- `docker/scanner/collectors/` — 6 Python collector modules (see Scanner section)
- `nginx/conf.d/default.conf` — Virtual host with rate limiting, security headers, denied paths

### Redis Usage

Redis serves dual purposes with separate databases:
- **db 0** — Application cache (`$cache_type = 'redis'` in config.php)
- **db 1** — PHP session storage (`session.save_handler = redis`)
- **Queues** — Scanner uses Redis lists (`ipam:scan_queue`, `ipam:ping_queue`, `ipam:ad_sync_queue`, `ipam:dns_check_queue`, `ipam:dhcp_sync_queue`, `ipam:conflict_queue`) and publishes results to corresponding `ipam:*_results` channels

## Scanner Service (docker/scanner/)

The scanner is a long-running Python service with two operating modes:

1. **Scheduled polling** — Uses the `schedule` library to run periodic jobs (subnet scans every `SCAN_INTERVAL` seconds, AD sync, DNS checks, DHCP sync, daily utilization aggregation)
2. **Redis queue processing** — Polls Redis lists on a 0.1s loop for on-demand scan/ping/sync requests

**Core scanning flow:** `ping_host(ip)` executes system `ping`, parses response time, runs `arp -n` for MAC, `socket.gethostbyaddr()` for reverse DNS. `scan_subnet(cidr, scan_id)` fans out to `ThreadPoolExecutor(max_workers=SCAN_CONCURRENT)`.

**Post-scan pipeline:** Every scan triggers change detection, conflict detection, and utilization snapshot capture.

### Collector Modules (`docker/scanner/collectors/`)

| Module | Purpose |
|--------|---------|
| `ad_collector.py` | LDAP/AD computer object sync |
| `dns_collector.py` | DNS forward/reverse reconciliation |
| `dhcp_collector.py` | DHCP lease correlation (supports Kea, ISC, Windows, Infoblox) |
| `utilization_collector.py` | Subnet utilization snapshots + daily aggregation |
| `change_detector.py` | Network state change detection + alerting |
| `conflict_detector.py` | IP conflict detection via ARP (multiple MACs per IP) |

### Scanner Environment Variables

Key tuning parameters in `.env`: `SCAN_INTERVAL` (default 300s), `SCAN_TIMEOUT` (2s), `SCAN_CONCURRENT` (50 threads), `AD_SYNC_INTERVAL` (14400s), `DNS_CHECK_INTERVAL` (3600s), `DHCP_SYNC_INTERVAL` (600s), `AD_STALE_THRESHOLD_DAYS` (30).

## Database Schema

PHPIPAM's base schema (`phpipam/db/SCHEMA.sql`) plus two custom extension files loaded automatically via `docker-entrypoint-initdb.d`:

### `01-schema-extensions.sql` — Core IPAM extensions (7 tables)

`ad_config`, `subnet_scans`, `host_discovery`, `ping_operations`, `ping_batches`, `scanner_agents`, `ipam_audit_log`

### `02-network-intelligence.sql` — Network intelligence (14 tables)

- **AD sync:** `ad_computers` (with `phpipam_address_id` cross-ref), `ad_sync_history`, `ad_ou_cache`
- **DNS:** `dns_checks` (mismatch types: no_ptr, no_a_record, forward/reverse/both mismatch), `dns_check_batches`
- **DHCP:** `dhcp_servers`, `dhcp_leases` (correlation status: matched/lease_only/ipam_only/mac_mismatch), `dhcp_sync_history`
- **Utilization:** `subnet_utilization_snapshots`, `subnet_utilization_daily` (daily aggregation with avg/max/min)
- **Alerting:** `network_alerts` (11 alert types, 3 severities), `alert_rules` (per-type notification config, seeded with defaults), `network_state_history`
- **Conflicts:** `ip_conflicts` (dual MAC tracking, detection method, links to `network_alerts`)

## Nginx Configuration

`nginx/conf.d/default.conf` defines:
- HTTP port 80: `/health` returns 200 (used by health check), everything else 301-redirects to HTTPS
- HTTPS port 443: TLS 1.2/1.3, HSTS (2 years), security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy)
- Rate limiting: login endpoints (5r/s, burst 10), API endpoints (30r/s, burst 50), connection limit (20 per IP)
- Denied paths: dot files, `config.php`, `.env`, `.git`, `composer.*`, backup extensions (`.bak`, `.swp`, `.tmp`)
- Static asset caching: 1 month expiry for js/css/images/fonts
- FastCGI to `php-fpm:9000` with 300s timeouts

## Environment Variables

Required in `.env` (generated by `setup.sh`):
- `MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD` — Database credentials (auto-generated)
- `AD_SERVER`, `AD_BASE_DN`, `AD_BIND_USER`, `AD_BIND_PASSWORD` — AD config (if `AD_ENABLED=true`)
- `DHCP_ENABLED`, `DHCP_SERVER_TYPE` (kea/isc-dhcpd/windows/infoblox), `DHCP_ACCESS_METHOD` (file/api/database/ssh) — DHCP correlation
- `ALERT_WEBHOOK_URL`, `SMTP_HOST/PORT/USER/PASS` — Alert notifications

## Debugging

```bash
# PHP errors
docker compose exec php-fpm cat /var/log/php/error.log

# Test MySQL from PHP container
docker compose exec php-fpm php -r "new PDO('mysql:host=mysql;dbname=phpipam', 'phpipam', 'password');"

# Test Redis
docker compose exec php-fpm php -r "\$r = new Redis(); var_dump(\$r->connect('redis', 6379));"

# Nginx upstream issues
docker compose logs nginx | grep -E "(error|upstream)"

# Scanner logs
docker compose logs -f subnet-scanner
```

## Common Issues

- **502 Bad Gateway**: PHP-FPM not ready; check `docker compose logs php-fpm`
- **500 Error**: Check `/var/log/php/error.log` inside php-fpm container
- **Database tables missing**: Run schema imports (see Development Commands above)
- **SSL cert errors**: Regenerate with `cd ssl && ./generate-certs.sh`
- **Scanner not finding hosts**: Ensure `NET_RAW` capability is granted (set in docker-compose.yml), check firewall allows ICMP, verify subnet reachability from scanner-internal network
