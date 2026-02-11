# Network Intelligence Features - Implementation Plan

## Context

The IPAM system wraps PHPIPAM v1.6.0 in a Docker stack with custom scanning, AD authentication, and Redis-based job queues. The user wants six read-only network intelligence features added. **Critical constraint: all features are strictly READ-ONLY against external systems (AD, DNS, DHCP, network). Writes go only to the local MySQL database.**

The existing codebase has clear extension points: custom PHP tools (`phpipam/app/tools/custom/`), custom API controllers (`phpipam/api/controllers/custom/`), database migrations (`database/init/`), and the Python scanner service (`docker/scanner/scanner.py`) with Redis queue processing.

---

## Features

1. **AD Computers Integration** - Sync computer objects from AD OUs, ping them, cross-reference with PHPIPAM
2. **DNS Reconciliation** - Forward/reverse DNS checks against PHPIPAM hostnames, flag mismatches
3. **DHCP Lease Correlation** - Read active leases, compare against PHPIPAM allocations
4. **Subnet Utilization Trends** - Historical snapshots, daily aggregates, capacity projections
5. **Network Change Alerting** - Detect new MACs, devices moving subnets, hosts going offline
6. **IP Conflict Detection** - ARP-based detection of multiple MACs claiming the same IP

## Architecture

All features follow the same pattern:

```
External System ──(read-only)──> Python Collector ──(write)──> MySQL ──(read)──> PHP Tool / API
                                       ↕
                                  Redis Queues
```

New Redis queues: `ipam:ad_sync_queue`, `ipam:dns_check_queue`, `ipam:dhcp_sync_queue`, `ipam:conflict_queue`
New Redis channels: `ipam:ad_sync_results`, `ipam:dns_check_results`, `ipam:dhcp_sync_results`, `ipam:conflict_results`, `ipam:alert_results`

---

## Implementation Phases

### Phase 1: Foundation
- Database migration with all new tables
- Scanner framework: modular collector pattern with `collectors/` package
- Environment variables and config registration

### Phase 2: AD Computers + IP Conflict Detection
- These have no external dependencies beyond existing LDAP config and ARP capability

### Phase 3: DNS Reconciliation + Subnet Utilization Trends
- DNS uses existing `bind-tools` in scanner container + `dnspython` library
- Utilization builds on existing scan data

### Phase 4: Network Change Alerting + DHCP Lease Correlation
- Change alerting consumes data from Phases 2-3
- DHCP requires configuring DHCP server read access

---

## Phase 1: Foundation

### 1.1 Database Migration

**New file**: `database/init/02-network-intelligence.sql`

All 14 tables across 6 features in a single migration:

**AD Computers (3 tables)**:
- `ad_computers` - Synced computer objects (name, DN, OU, OS, IP, MAC, ping status, PHPIPAM cross-ref, stale flag)
- `ad_sync_history` - Sync operation tracking (type, status, counts, timestamps)
- `ad_ou_cache` - OU tree structure (DN, name, parent, computer count)

**DNS Reconciliation (2 tables)**:
- `dns_checks` - Individual check results (IP, forward/reverse results, mismatch type)
- `dns_check_batches` - Batch operation tracking

**DHCP Correlation (3 tables)**:
- `dhcp_servers` - Server config (type: isc-dhcpd/kea/windows/infoblox, access method: file/api/database/ssh)
- `dhcp_leases` - Collected leases with correlation status
- `dhcp_sync_history` - Sync tracking

**Subnet Utilization (2 tables)**:
- `subnet_utilization_snapshots` - Per-scan snapshots (total, used, active, free, utilization %)
- `subnet_utilization_daily` - Daily aggregates (avg/max/min utilization)

**Network Alerting (3 tables)**:
- `network_alerts` - All alerts (type, severity, IP, MAC, acknowledged/resolved flags)
- `alert_rules` - Configurable rules (type, enabled, severity, notification method, cooldown)
- `network_state_history` - Per-scan state for change comparison

**IP Conflicts (1 table)**:
- `ip_conflicts` - Detected conflicts (IP, two MACs, vendors, detection method, status)

### 1.2 Scanner Framework Extension

**Modify**: `docker/scanner/scanner.py`

Add to main loop:
```python
# Import collectors
from collectors.ad_collector import ADCollector
from collectors.dns_collector import DNSReconciler
from collectors.dhcp_collector import DHCPCollector
from collectors.utilization_collector import UtilizationCollector
from collectors.change_detector import ChangeDetector
from collectors.conflict_detector import ConflictDetector

# In main loop, add queue processors:
process_ad_sync_queue()
process_dns_check_queue()
process_dhcp_sync_queue()
process_conflict_queue()
```

Add scheduled jobs:
```python
schedule.every(AD_SYNC_INTERVAL).seconds.do(scheduled_ad_sync)
schedule.every(DNS_CHECK_INTERVAL).seconds.do(scheduled_dns_check)
schedule.every(DHCP_SYNC_INTERVAL).seconds.do(scheduled_dhcp_sync)
schedule.every().day.at("00:05").do(utilization_daily_aggregate)
schedule.every().week.do(utilization_cleanup)
```

**New directory**: `docker/scanner/collectors/` with `__init__.py` and 6 collector modules.

### 1.3 Scanner Dockerfile Updates

**Modify**: `docker/scanner/Dockerfile`

Add build dependencies for `python-ldap`:
```dockerfile
RUN apk add --no-cache openldap-dev gcc musl-dev python3-dev
```

Add collectors directory copy:
```dockerfile
COPY collectors/ /app/collectors/
```

### 1.4 Dependencies

**Modify**: `docker/scanner/requirements.txt`

Add:
```
python-ldap>=3.4.0
dnspython>=2.4.0
```

### 1.5 PHPIPAM Config

**Modify**: `config/phpipam/config.php`

Add before closing `?>`:
```php
// Network Intelligence custom tools
$private_subpages = array(
    'ad-computers',
    'dns-reconciliation',
    'dhcp-correlation',
    'subnet-trends',
    'network-alerts',
    'ip-conflicts'
);
```

This hooks into `tools-menu-config.php:57-68` which reads `Config::ValueOf('private_subpages')` and auto-registers them in the Tools menu under "Custom tools".

### 1.6 Docker Compose Updates

**Modify**: `docker-compose.yml` - Add env vars to `subnet-scanner` service:

```yaml
environment:
  # ... existing ...
  AD_ENABLED: ${AD_ENABLED:-false}
  AD_SERVER: ${AD_SERVER:-}
  AD_BASE_DN: ${AD_BASE_DN:-}
  AD_BIND_USER: ${AD_BIND_USER:-}
  AD_BIND_PASSWORD: ${AD_BIND_PASSWORD:-}
  AD_USE_TLS: ${AD_USE_TLS:-true}
  AD_SYNC_INTERVAL: ${AD_SYNC_INTERVAL:-14400}
  AD_STALE_THRESHOLD_DAYS: ${AD_STALE_THRESHOLD_DAYS:-30}
  DNS_CHECK_INTERVAL: ${DNS_CHECK_INTERVAL:-3600}
  DNS_SERVERS: ${DNS_SERVERS:-}
  DHCP_ENABLED: ${DHCP_ENABLED:-false}
  DHCP_SERVER_TYPE: ${DHCP_SERVER_TYPE:-kea}
  DHCP_ACCESS_METHOD: ${DHCP_ACCESS_METHOD:-file}
  DHCP_LEASE_FILE: ${DHCP_LEASE_FILE:-}
  DHCP_DB_HOST: ${DHCP_DB_HOST:-}
  DHCP_DB_USER: ${DHCP_DB_USER:-}
  DHCP_DB_PASSWORD: ${DHCP_DB_PASSWORD:-}
  DHCP_DB_NAME: ${DHCP_DB_NAME:-}
  DHCP_SYNC_INTERVAL: ${DHCP_SYNC_INTERVAL:-600}
  ALERT_WEBHOOK_URL: ${ALERT_WEBHOOK_URL:-}
  SCAN_TIMEOUT: ${SCAN_TIMEOUT:-2}
  SCAN_CONCURRENT: ${SCAN_CONCURRENT:-50}
```

### 1.7 Environment Template

**Modify**: `.env.example` - Add new section:

```bash
# ----- Network Intelligence -----
AD_SYNC_INTERVAL=14400
AD_STALE_THRESHOLD_DAYS=30
DNS_CHECK_INTERVAL=3600
DNS_SERVERS=
DHCP_ENABLED=false
DHCP_SERVER_TYPE=kea
DHCP_ACCESS_METHOD=file
DHCP_LEASE_FILE=
DHCP_DB_HOST=
DHCP_DB_USER=
DHCP_DB_PASSWORD=
DHCP_DB_NAME=
DHCP_SYNC_INTERVAL=600
ALERT_WEBHOOK_URL=
```

---

## Phase 2: AD Computers Integration + IP Conflict Detection

### 2.1 AD Collector

**New file**: `docker/scanner/collectors/ad_collector.py`

Uses `python-ldap` for read-only LDAP queries. Key functions:

- `connect()` - LDAP bind with service account (read-only), TLS support
- `get_ou_tree(base_dn)` - Search `(objectClass=organizationalUnit)`, populate `ad_ou_cache`
- `get_computers(ou_dn)` - Paged search `(objectClass=computer)` with attributes: `cn`, `dNSHostName`, `distinguishedName`, `operatingSystem`, `operatingSystemVersion`, `lastLogonTimestamp`, `whenCreated`, `whenChanged`, `pwdLastSet`, `description`, `memberOf`, `userAccountControl`
- `resolve_computer_ip(dns_hostname)` - DNS forward lookup (read-only)
- `ping_computer(ip)` - Reuses existing `ping_host()` from scanner.py
- `cross_reference_phpipam(computer)` - Match against `ipaddresses` table by IP (`INET_ATON`), hostname, or MAC
- `detect_stale(threshold_days)` - Flag computers where `lastLogonTimestamp` converted to datetime is older than threshold
- `detect_rogue()` - LEFT JOIN `host_discovery` against `ad_computers` where no match exists
- `sync_computers(ou_dn)` - Full sync workflow: query AD, resolve IPs, ping, cross-reference, detect stale/rogue, update DB

**Key technical details**:
- Windows `lastLogonTimestamp` is 100-nanosecond intervals since 1601-01-01. Convert: `unix_ts = (win_ts / 10000000) - 11644473600`
- PHPIPAM stores IPs as decimal in `ipaddresses.ip_addr`. Use `INET_ATON()`/`INET_NTOA()` for matching
- Use `ldap.controls.SimplePagedResultsControl` with page size 500 for large directories
- `userAccountControl` bit 0x2 = disabled account

**Queue processor**: Pops from `ipam:ad_sync_queue`, calls `sync_computers()`, publishes to `ipam:ad_sync_results`

**Scheduled job**: Every `AD_SYNC_INTERVAL` seconds (default 14400 = 4 hours)

### 2.2 IP Conflict Detector

**New file**: `docker/scanner/collectors/conflict_detector.py`

Uses `scapy` (already available) for ARP-based conflict detection:

- `scan_for_conflicts(subnet_cidr)` - Send ARP requests via scapy, collect responses, flag IPs with multiple responding MACs
- `compare_with_previous(subnet_id, current_results)` - Compare current MAC-IP mappings against `network_state_history`
- `resolve_vendors(mac)` - OUI lookup from `/usr/share/arp-scan/ieee-oui.txt` (already in container)
- `store_conflict(conflict_data)` - INSERT/UPDATE `ip_conflicts`, create `network_alerts` entry
- `check_resolved()` - Re-scan active conflicts, mark resolved if only one MAC responds

**Integration**: Runs after each `scan_subnet()` completes in `process_scan_queue()`. Also available via `ipam:conflict_queue` for on-demand scanning.

### 2.3 PHP Custom Tool: AD Computers

**New directory**: `phpipam/app/tools/custom/ad-computers/`

Files:
- `index.php` - Tab router (all computers, by OU, stale, rogue, sync history, detail)
- `all-computers.php` - Sortable/filterable table from `ad_computers`
- `ou-browser.php` - OU tree from `ad_ou_cache`, click to filter
- `stale.php` - Computers with `is_stale=1`, sorted by `stale_days` DESC
- `rogue.php` - Network hosts not in AD (LEFT JOIN `host_discovery` against `ad_computers`)
- `sync-history.php` - History from `ad_sync_history`, manual sync trigger button
- `detail.php` - Single computer: AD attributes, ping status, PHPIPAM cross-reference

All pages follow the PHPIPAM pattern:
```php
$User->check_user_session();
// Permission check
// Query via $Database->getObjectsQuery($sql, $params)
// Render HTML tables
```

### 2.4 PHP Custom Tool: IP Conflicts

**New directory**: `phpipam/app/tools/custom/ip-conflicts/`

Files:
- `index.php` - Tab router
- `active.php` - Active conflicts table (IP, MAC1+vendor, MAC2+vendor, subnet, first/last detected)
- `resolved.php` - Historical resolved conflicts
- `detail.php` - Full conflict info, option to mark as false positive

### 2.5 API Controllers

**New file**: `phpipam/api/controllers/custom/ADComputers_controller.php`

Extends `Common_api_functions`. Endpoints:
- `GET /adcomputers/` - List all (paginated)
- `GET /adcomputers/{id}/` - Single computer
- `GET /adcomputers/stale/` - Stale computers
- `GET /adcomputers/rogue/` - Rogue devices
- `GET /adcomputers/ous/` - OU tree
- `GET /adcomputers/sync-history/` - Sync history
- `POST /adcomputers/sync/` - Trigger sync (enqueues to Redis)
- `POST /adcomputers/ping/{id}/` - Trigger ping of specific computer

**New file**: `phpipam/api/controllers/custom/IPConflicts_controller.php`

- `GET /ipconflicts/` - List conflicts (filterable by status)
- `GET /ipconflicts/{id}/` - Single conflict detail
- `POST /ipconflicts/scan/{subnet_id}/` - Trigger conflict scan

---

## Phase 3: DNS Reconciliation + Subnet Utilization Trends

### 3.1 DNS Collector

**New file**: `docker/scanner/collectors/dns_collector.py`

Uses `dnspython` for targeted DNS queries:

- `forward_lookup(hostname, dns_server)` - Resolve A/AAAA record (read-only)
- `reverse_lookup(ip, dns_server)` - Resolve PTR record (read-only)
- `check_address(ip, phpipam_hostname, dns_server)` - Full check, categorize mismatch type
- `reconcile_subnet(subnet_id, batch_id)` - Check all addresses in a subnet using ThreadPoolExecutor
- `reconcile_all(batch_id)` - Check all subnets where `resolveDNS=1`

**Mismatch types**: `none`, `no_ptr`, `no_a_record`, `forward_mismatch`, `reverse_mismatch`, `both_mismatch`, `no_phpipam_hostname`, `orphan_dns`

**Queue processor**: Pops from `ipam:dns_check_queue`
**Scheduled**: Every `DNS_CHECK_INTERVAL` seconds (default 3600 = 1 hour)

### 3.2 Utilization Collector

**New file**: `docker/scanner/collectors/utilization_collector.py`

- `capture_snapshot(subnet_id)` - Query PHPIPAM tables for current utilization, INSERT into `subnet_utilization_snapshots`
  - `total_hosts` = 2^(32-mask) - 2
  - `used_hosts` = COUNT from `ipaddresses` WHERE `subnetId`
  - `active_hosts` = from most recent scan results
  - `reserved_hosts` = COUNT WHERE state=3
  - Calculate percentages
- `capture_all_snapshots()` - All non-folder subnets
- `aggregate_daily(date)` - AVG/MAX/MIN from snapshots into `subnet_utilization_daily`
- `cleanup_old_snapshots(retention_days=90)` - Purge raw snapshots, keep daily aggregates

**Runs after each scan cycle** (piggybacks on `scheduled_subnet_scan`)
**Daily aggregate**: Scheduled at 00:05
**Cleanup**: Weekly

### 3.3 PHP Custom Tool: DNS Reconciliation

**New directory**: `phpipam/app/tools/custom/dns-reconciliation/`

- `index.php` - Router
- `dashboard.php` - Summary counts by mismatch type, pie chart
- `mismatches.php` - Filterable table by mismatch type and subnet
- `batch-history.php` - Past reconciliation runs, trigger button

### 3.4 PHP Custom Tool: Subnet Trends

**New directory**: `phpipam/app/tools/custom/subnet-trends/`

- `index.php` - Router
- `dashboard.php` - Top 10 most utilized, subnets >80% threshold
- `trend-graph.php` - Chart.js line graph (7d/30d/90d/1y), utilization % over time
- `projection.php` - Linear regression on 90-day data estimating exhaustion date

### 3.5 API Controllers

**New file**: `phpipam/api/controllers/custom/DNSReconciliation_controller.php`
- `GET /dnsreconciliation/` - Mismatches (paginated, filterable)
- `GET /dnsreconciliation/summary/` - Counts by type
- `GET /dnsreconciliation/subnet/{id}/` - Per-subnet mismatches
- `POST /dnsreconciliation/check/` - Trigger check

**New file**: `phpipam/api/controllers/custom/SubnetTrends_controller.php`
- `GET /subnettrends/` - Current utilization all subnets
- `GET /subnettrends/{subnet_id}/` - Current + historical
- `GET /subnettrends/{subnet_id}/history/?range=30d` - Time series
- `GET /subnettrends/top/` - Most utilized subnets

---

## Phase 4: Network Change Alerting + DHCP Lease Correlation

### 4.1 Change Detector

**New file**: `docker/scanner/collectors/change_detector.py`

- `load_alert_rules()` - Read enabled rules from `alert_rules` table
- `get_previous_state(subnet_id)` - Most recent `network_state_history` entries
- `compare_scan_results(subnet_id, current_results)` - Diff current vs previous:
  - New IP+MAC not seen before -> `new_device`
  - MAC not seen before -> `new_mac`
  - Same MAC in different subnet -> `device_moved`
  - Was online, now offline -> `host_offline`
  - Was offline, now online -> `host_online`
- `create_alert(alert_type, data)` - Check rules, respect cooldown, INSERT into `network_alerts`
- `send_webhook(url, alert_data)` - Optional HTTP POST notification
- `send_email(recipients, alert_data)` - Optional email notification

**Integration**: Called in `process_scan_queue()` after scan completes and results are saved. Also receives alerts from other collectors (AD rogue detection, DNS mismatches, IP conflicts, DHCP mismatches).

### 4.2 DHCP Collector

**New file**: `docker/scanner/collectors/dhcp_collector.py`

Supports read-only access to multiple DHCP server types:

| Type | Read Method |
|------|-------------|
| ISC DHCPD | Parse `dhcpd.leases` file (mounted volume) |
| Kea | Read-only MySQL query against lease DB, or lease file |
| Windows | Parse exported JSON/CSV (mounted volume from scheduled PowerShell export) |
| Infoblox | REST API `GET /lease` |

- `collect_leases_file(path)` - Parse ISC/Kea lease files
- `collect_leases_database(config)` - Read-only SQL against Kea lease DB
- `collect_leases_api(config)` - HTTP GET from DHCP API
- `correlate_with_phpipam(leases)` - Match each lease against `ipaddresses` by IP, compare MAC/hostname
- `sync_leases(server_id)` - Full sync: collect, correlate, store in `dhcp_leases`, create alerts for mismatches

**Correlation statuses**: `matched`, `lease_only` (in DHCP but not PHPIPAM), `ipam_only` (in PHPIPAM but no lease), `mac_mismatch`, `hostname_mismatch`

### 4.3 PHP Custom Tool: Network Alerts

**New directory**: `phpipam/app/tools/custom/network-alerts/`

- `index.php` - Router
- `dashboard.php` - Unacknowledged counts by type/severity, timeline
- `alert-list.php` - Filterable table, acknowledge/resolve buttons
- `alert-rules.php` - View/configure rules (enable/disable, severity, notification method, cooldown)
- `alert-detail.php` - Full alert context with links to related PHPIPAM objects

### 4.4 PHP Custom Tool: DHCP Correlation

**New directory**: `phpipam/app/tools/custom/dhcp-correlation/`

- `index.php` - Router
- `dashboard.php` - Lease count, matched, unmatched, conflicts
- `leases.php` - All leases with correlation status
- `mismatches.php` - Only mismatched entries
- `servers.php` - Configured DHCP servers and sync status

### 4.5 API Controllers

**New file**: `phpipam/api/controllers/custom/NetworkAlerts_controller.php`
- `GET /networkalerts/` - List (filterable by type, severity, acknowledged)
- `GET /networkalerts/{id}/` - Detail
- `GET /networkalerts/summary/` - Counts
- `GET /networkalerts/rules/` - List rules
- `POST /networkalerts/{id}/acknowledge/` - Acknowledge alert
- `POST /networkalerts/{id}/resolve/` - Resolve alert

**New file**: `phpipam/api/controllers/custom/DHCPCorrelation_controller.php`
- `GET /dhcpcorrelation/` - All leases
- `GET /dhcpcorrelation/mismatches/` - Only mismatches
- `GET /dhcpcorrelation/servers/` - Server status
- `POST /dhcpcorrelation/sync/{server_id}/` - Trigger sync

---

## Complete File Inventory

### New Files (45 files)

**Database (1)**:
- `database/init/02-network-intelligence.sql`

**Scanner Collectors (7)**:
- `docker/scanner/collectors/__init__.py`
- `docker/scanner/collectors/ad_collector.py`
- `docker/scanner/collectors/dns_collector.py`
- `docker/scanner/collectors/dhcp_collector.py`
- `docker/scanner/collectors/utilization_collector.py`
- `docker/scanner/collectors/change_detector.py`
- `docker/scanner/collectors/conflict_detector.py`

**PHP Custom Tools (31)**:
- `phpipam/app/tools/custom/ad-computers/index.php`
- `phpipam/app/tools/custom/ad-computers/all-computers.php`
- `phpipam/app/tools/custom/ad-computers/ou-browser.php`
- `phpipam/app/tools/custom/ad-computers/stale.php`
- `phpipam/app/tools/custom/ad-computers/rogue.php`
- `phpipam/app/tools/custom/ad-computers/sync-history.php`
- `phpipam/app/tools/custom/ad-computers/detail.php`
- `phpipam/app/tools/custom/dns-reconciliation/index.php`
- `phpipam/app/tools/custom/dns-reconciliation/dashboard.php`
- `phpipam/app/tools/custom/dns-reconciliation/mismatches.php`
- `phpipam/app/tools/custom/dns-reconciliation/batch-history.php`
- `phpipam/app/tools/custom/dhcp-correlation/index.php`
- `phpipam/app/tools/custom/dhcp-correlation/dashboard.php`
- `phpipam/app/tools/custom/dhcp-correlation/leases.php`
- `phpipam/app/tools/custom/dhcp-correlation/mismatches.php`
- `phpipam/app/tools/custom/dhcp-correlation/servers.php`
- `phpipam/app/tools/custom/subnet-trends/index.php`
- `phpipam/app/tools/custom/subnet-trends/dashboard.php`
- `phpipam/app/tools/custom/subnet-trends/trend-graph.php`
- `phpipam/app/tools/custom/subnet-trends/projection.php`
- `phpipam/app/tools/custom/network-alerts/index.php`
- `phpipam/app/tools/custom/network-alerts/dashboard.php`
- `phpipam/app/tools/custom/network-alerts/alert-list.php`
- `phpipam/app/tools/custom/network-alerts/alert-rules.php`
- `phpipam/app/tools/custom/network-alerts/alert-detail.php`
- `phpipam/app/tools/custom/ip-conflicts/index.php`
- `phpipam/app/tools/custom/ip-conflicts/active.php`
- `phpipam/app/tools/custom/ip-conflicts/resolved.php`
- `phpipam/app/tools/custom/ip-conflicts/detail.php`

**API Controllers (6)**:
- `phpipam/api/controllers/custom/ADComputers_controller.php`
- `phpipam/api/controllers/custom/DNSReconciliation_controller.php`
- `phpipam/api/controllers/custom/DHCPCorrelation_controller.php`
- `phpipam/api/controllers/custom/SubnetTrends_controller.php`
- `phpipam/api/controllers/custom/NetworkAlerts_controller.php`
- `phpipam/api/controllers/custom/IPConflicts_controller.php`

### Modified Files (7)

- `docker/scanner/scanner.py` - Add collector imports, queue processors, scheduled jobs
- `docker/scanner/Dockerfile` - Add `openldap-dev` build deps, COPY `collectors/`
- `docker/scanner/requirements.txt` - Add `python-ldap`, `dnspython`
- `config/phpipam/config.php` - Add `$private_subpages` array
- `docker-compose.yml` - Add env vars to scanner service
- `.env.example` - Add new env var templates
- `.env` - Add new env var values (if exists)

---

## Verification

### After Phase 1:
```bash
# Rebuild scanner container
docker-compose build subnet-scanner

# Verify database tables created
docker-compose exec mysql mysql -u root -p phpipam -e "SHOW TABLES LIKE '%ad_%'; SHOW TABLES LIKE '%dns_%'; SHOW TABLES LIKE '%dhcp_%'; SHOW TABLES LIKE '%conflict%'; SHOW TABLES LIKE '%alert%'; SHOW TABLES LIKE '%utilization%';"

# Verify scanner starts without errors
docker-compose up -d subnet-scanner && docker-compose logs -f subnet-scanner

# Verify custom tools appear in PHPIPAM UI
# Navigate to https://localhost/phpipam/?page=tools and check "Custom tools" section
```

### After Phase 2:
```bash
# Trigger AD sync via Redis (if AD_ENABLED=true)
docker-compose exec redis redis-cli RPUSH ipam:ad_sync_queue '{"ou_dn":null}'

# Check sync results
docker-compose exec mysql mysql -u root -p phpipam -e "SELECT COUNT(*) FROM ad_computers; SELECT * FROM ad_sync_history ORDER BY id DESC LIMIT 1;"

# Trigger conflict scan
docker-compose exec redis redis-cli RPUSH ipam:conflict_queue '{"subnet_cidr":"172.28.0.0/16"}'

# Check for conflicts
docker-compose exec mysql mysql -u root -p phpipam -e "SELECT * FROM ip_conflicts;"
```

### After Phase 3:
```bash
# Trigger DNS check
docker-compose exec redis redis-cli RPUSH ipam:dns_check_queue '{"scope":"all"}'

# Check results
docker-compose exec mysql mysql -u root -p phpipam -e "SELECT mismatch_type, COUNT(*) FROM dns_checks GROUP BY mismatch_type;"

# Check utilization snapshots
docker-compose exec mysql mysql -u root -p phpipam -e "SELECT * FROM subnet_utilization_snapshots ORDER BY id DESC LIMIT 10;"
```

### After Phase 4:
```bash
# Check alerts
docker-compose exec mysql mysql -u root -p phpipam -e "SELECT alert_type, severity, COUNT(*) FROM network_alerts GROUP BY alert_type, severity;"

# If DHCP configured, trigger sync
docker-compose exec redis redis-cli RPUSH ipam:dhcp_sync_queue '{"server_id":1}'
```

### API verification:
```bash
# Test API endpoints (requires API app configured in PHPIPAM)
curl -k -H "token: <api_token>" https://localhost/api/<app_id>/adcomputers/
curl -k -H "token: <api_token>" https://localhost/api/<app_id>/ipconflicts/
curl -k -H "token: <api_token>" https://localhost/api/<app_id>/dnsreconciliation/summary/
curl -k -H "token: <api_token>" https://localhost/api/<app_id>/subnettrends/top/
curl -k -H "token: <api_token>" https://localhost/api/<app_id>/networkalerts/summary/
```

---

## Known Considerations

1. **python-ldap on Alpine**: Requires `openldap-dev`, `gcc`, `musl-dev` build deps. Install at build time, can be removed after pip install to reduce image size.
2. **Large AD directories**: Use paged LDAP queries (page size 500). LDAP queries are single-threaded; ping parallelism via ThreadPoolExecutor.
3. **PHPIPAM IP format**: IPs stored as decimal (`INET_ATON`). All cross-referencing must convert.
4. **Utilization data growth**: ~28,800 rows/day with 100 subnets at 5-min intervals. Weekly cleanup retains 90 days of raw snapshots; daily aggregates kept indefinitely.
5. **Conflict false positives**: VRRP/HSRP floating IPs, VM migrations, NIC bonding can trigger false alerts. "False positive" status and cooldown mechanism handle this.
6. **DHCP access**: Most common challenge. File-based (mounted volume) is simplest. For Windows DHCP, recommend scheduled PowerShell export to JSON.
