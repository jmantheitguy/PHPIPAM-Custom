# IPAM System

Docker-based IP Address Management system combining PHPIPAM with Active Directory authentication and network scanning capabilities.

## Features

- **IP Address Management** - Full PHPIPAM functionality for subnet/VLAN/VRF management
- **Active Directory Integration** - LDAP authentication with group-based role mapping
- **Subnet Scanner** - ICMP/ARP/NDP network discovery
- **IP Ping Tool** - Single and batch ping operations with live status
- **Redis Caching** - Fast session and data caching
- **SSL/TLS** - Secure HTTPS access

## Quick Start

```bash
# 1. Run setup script
./setup.sh

# 2. Review and update configuration
nano .env

# 3. Start containers
docker compose up -d

# 4. Access web interface
open https://localhost
```

Default PHPIPAM credentials: `admin` / `ipamadmin`

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Compose Stack                      │
├─────────────────────────────────────────────────────────────┤
│  nginx:443 ──► php-fpm:9000 ──► mysql:3306                  │
│       │                              │                        │
│       └──────────────────────────────┼─── redis:6379         │
│                                      │                        │
│  subnet-scanner ─────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
ipam-system/
├── docker-compose.yml      # Container orchestration
├── .env                    # Environment configuration
├── setup.sh                # Initial setup script
├── docker/
│   ├── php/                # PHP-FPM container
│   ├── nginx/              # Nginx reverse proxy
│   └── scanner/            # Network scanner service
├── nginx/
│   ├── nginx.conf          # Main nginx config
│   └── conf.d/             # Virtual host configs
├── ssl/                    # SSL certificates
├── phpipam/                # PHPIPAM application
├── scripts/                # Scanning scripts
├── database/
│   └── init/               # Database initialization
└── config/
    └── phpipam/            # PHPIPAM configuration
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MYSQL_ROOT_PASSWORD` | MySQL root password | - |
| `MYSQL_PASSWORD` | PHPIPAM DB password | - |
| `AD_ENABLED` | Enable AD authentication | `false` |
| `AD_SERVER` | LDAP server URL | - |
| `AD_BASE_DN` | LDAP base DN | - |
| `SCAN_INTERVAL` | Auto-scan interval (seconds) | `300` |

### Active Directory

1. Update `.env` with AD settings:
   ```
   AD_ENABLED=true
   AD_SERVER=ldap://ad.example.com
   AD_BASE_DN=dc=example,dc=com
   AD_BIND_USER=svc_phpipam@example.com
   AD_BIND_PASSWORD=secure_password
   AD_ADMIN_GROUP=IPAM-Admins
   ```

2. Restart containers:
   ```bash
   docker compose restart php-fpm
   ```

## Commands

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Stop services
docker compose down

# Rebuild containers
docker compose build --no-cache

# Run subnet scan
docker compose exec subnet-scanner python scanner.py

# Manual ping test
docker compose exec php-fpm /scripts/ip-ping.sh 192.168.1.1
```

## Scanning

### Subnet Scan

```bash
# Scan a subnet
./scripts/subnet-scan.sh 192.168.1.0/24

# With scan ID for database tracking
./scripts/subnet-scan.sh 192.168.1.0/24 123
```

### IP Ping

```bash
# Single IP
./scripts/ip-ping.sh 192.168.1.1

# IP range
./scripts/ip-ping.sh 192.168.1.1-192.168.1.50

# From file
./scripts/ip-ping.sh -f ip_list.txt

# JSON output
./scripts/ip-ping.sh -j 192.168.1.0/24
```

### ARP Discovery

```bash
# Discover hosts on local network
./scripts/mac-arp-scanner.sh eth0 192.168.1.0/24
```

## SSL Certificates

### Development (self-signed)

```bash
cd ssl && ./generate-certs.sh
```

### Production

Replace `ssl/server.crt` and `ssl/server.key` with certificates from your CA.

## Troubleshooting

### Containers not starting

```bash
# Check container status
docker compose ps

# View detailed logs
docker compose logs mysql
docker compose logs php-fpm
```

### Database connection issues

```bash
# Test MySQL connectivity
docker compose exec php-fpm mysql -h mysql -u phpipam -p

# Check database status
docker compose exec mysql mysqladmin status -p
```

### Scanner not finding hosts

- Ensure scanner container has `NET_RAW` capability
- Check firewall allows ICMP
- Verify subnet is reachable from Docker network

## License

See PHPIPAM license at https://phpipam.net/
