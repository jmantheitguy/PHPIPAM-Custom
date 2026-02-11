# IPAM System - Docker Implementation Plan

## Overview
Build a Docker-based IP Address Management (IPAM) system combining PHPIPAM features with Active Directory authentication and advanced IP operations.

## Architecture

### Technology Stack (Custom Docker Stack)
```
┌────────────────────────────────────────────────────────────────┐
│                        Custom Docker Stack                       │
├────────────────────────────────────────────────────────────────┤
│  nginx (custom image)                                            │
│  php-fpm (custom image with extensions)                         │
│  mysql:8.0                                                      │
│  redis:alpine                                                   │
│  phpipam (application code)                                      │
│  subnet-scanner (custom scanner container)                      │
└────────────────────────────────────────────────────────────────┘
```

### Docker Compose Structure (Custom Stack)
```yaml
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: phpipam
      MYSQL_USER: phpipam
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
    volumes:
      - mysql_data:/var/lib/mysql

  redis:
    image: redis:alpine
    volumes:
      - redis_data:/data

  php-fpm:
    build:
      context: ./docker/php
      dockerfile: Dockerfile
    depends_on:
      - mysql
      - redis
    volumes:
      - ./phpipam:/var/www/html/phpipam
      - ./scripts:/scripts
    environment:
      PHPIPAM_DB_HOST: mysql
      PHPIPAM_DB_PASS: ${MYSQL_PASSWORD}
      PHPIPAM_DB_NAME: phpipam
      REDIS_HOST: redis
      AD_ENABLED: "true"
      XDEBUG_ENABLED: "0"

  nginx:
    build:
      context: ./docker/nginx
      dockerfile: Dockerfile
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
      - ./phpipam:/var/www/html/phpipam
    depends_on:
      - php-fpm

  subnet-scanner:
    build:
      context: ./docker/scanner
      dockerfile: Dockerfile
    volumes:
      - ./scripts:/scripts
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      MYSQL_HOST: mysql
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
      REDIS_HOST: redis

volumes:
  mysql_data
  redis_data
```

## Core Features

### PHPIPAM Core Features
1. **IP Address Management**
   - Subnet hierarchy (VLAN, VLAN ID)
   - IP allocation (free/used/failed)
   - Custom fields per subnet
   - IP request and approval workflow

2. **IPAM Structure**
   - Networks and subnets with CIDR notation
   - VLAN and VRF management
   - IP range ranges
   - AD/MAC tracking

3. **DNS Integration**
   - Reverse DNS records
   - Dynamic DNS updates
   - DNS record management
   - Dynamic updates via BIND/DNSSEC

4. **API Access**
   - RESTful API for integration
   - API keys and permissions
   - Web services for external apps

5. **User Management**
   - Role-based access control (RBAC)
   - User authentication
   - Group permissions
   - Audit logging

6. **Reporting**
   - Subnet usage reports
   - IP usage charts
   - Export to CSV/JSON
   - Custom report builder

### Additional Features

### Active Directory Integration
```
┌─────────────┐    LDAP Bind    ┌─────────────────┐
│   User      │◄──────────────►│   Active Directory│
│   Interface  │   Authentication │    Domain Controller │
└─────────────┘                 └─────────────────┘
      ▲
      │ LDAP Authentication
      │
┌─────────────┐
│  PHPIPAM    │
│  Application │
└─────────────┘
```

**Implementation:**
- LDAP/AD authentication backend
- LDAP group mapping to IPAM roles
- SSO integration
- Two-factor authentication option
- LDAP schema validation

### Subnet Scanner
```
┌─────────────┐    ICMP Ping    ┌─────────────────┐
│   Scan      │◄──────────────►│   Network        │
│   Interface  │   Results      │   Scan           │
└─────────────┘                 └─────────────────┘
      ▲
      │
┌─────────────┐
│   PHPIPAM    │
│  Application │
└─────────────┘
```

**Features:**
- Subnet scan by CIDR
- ICMP ping detection
- ARP table scanning (Linux)
- Neighbor discovery (Windows)
- Identify active hosts
- Automatic MAC address capture
- DNS reverse lookup
- Save scan results to database

### IP Ping Operation
**UI Component:**
```
[IP Address Input] [PING] [SCAN ALL]
         │           │         │
         └───────────┴─────────┘
                    │
            ┌───────▼────────┐
            │   Background   │
            │   Process      │
            └───────┬────────┘
                    │
            ┌───────▼────────┐
            │   Status       │
            │   Display      │
            │   (Live Results)│
            └────────────────┘
```

**Features:**
- Single IP ping test
- Batch IP ping (range input)
- Live status display
- Response time logging
- Down host notification
- Export ping results
- Add host to database after ping

## Database Schema Extensions

### New Tables for Extensions

```sql
-- Active Directory Config
CREATE TABLE ad_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server VARCHAR(255) NOT NULL,
    base_dn VARCHAR(255) NOT NULL,
    bind_user VARCHAR(255) NOT NULL,
    bind_password VARCHAR(255) NOT NULL,
    group_field VARCHAR(255) DEFAULT 'memberOf',
    active INT DEFAULT 1,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Subnet Scans
CREATE TABLE subnet_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    subnet_id INT NOT NULL,
    start_time TIMESTAMP NULL,
    end_time TIMESTAMP NULL,
    total_hosts INT NOT NULL,
    active_hosts INT NOT NULL DEFAULT 0,
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    scan_type ENUM('ping','arp','ndp') DEFAULT 'ping',
    results JSON NULL,
    created_by INT NOT NULL,
    FOREIGN KEY (subnet_id) REFERENCES subnets(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Host Discovery
CREATE TABLE host_discovery (
    id INT AUTO_INCREMENT PRIMARY KEY,
    subnet_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(17) NULL,
    status ENUM('active','inactive','unknown') DEFAULT 'unknown',
    device_type VARCHAR(50) NULL,
    os_family VARCHAR(50) NULL,
    last_seen TIMESTAMP NULL,
    notes TEXT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (subnet_id) REFERENCES subnets(id) ON DELETE CASCADE
);

-- Ping Operations
CREATE TABLE ping_operations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    subnet_id INT NOT NULL,
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    response_time INT NULL,
    success BOOLEAN NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    results JSON NULL,
    FOREIGN KEY (subnet_id) REFERENCES subnets(id) ON DELETE CASCADE
);
```

## File Structure
```
ipam-system/
├── docker-compose.yml
├── .env
├── nginx/
│   └── nginx.conf
├── ssl/
│   ├── server.crt
│   └── server.key
├── phpipam/
│   ├── config.php
│   └── ldap_settings.php
├── scripts/
│   ├── subnet-scan.sh
│   ├── ip-ping.sh
│   └── mac-arp-scanner.sh
└── docker/
    └── phpipam/
        ├── Dockerfile
        └── entrypoint.sh
```

## Implementation Phases

### Phase 1: Base Infrastructure
- [ ] Docker Compose setup
- [ ] MySQL database initialization
- [ ] Redis caching layer
- [ ] Nginx reverse proxy with SSL

### Phase 2: Core IPAM (PHPIPAM)
- [ ] Install and configure PHPIPAM
- [ ] Database schema installation
- [ ] Basic IPAM functionality
- [ ] VLAN/VRF management
- [ ] User authentication

### Phase 3: Active Directory Integration
- [ ] LDAP/AD backend configuration
- [ ] Authentication module
- [ ] Group mapping
- [ ] SSO implementation

### Phase 4: Subnet Scanner
- [ ] Scan API endpoints
- [ ] ICMP ping scanner
- [ ] ARP neighbor scanner
- [ ] Scan results integration

### Phase 5: IP Ping Feature
- [ ] Ping API endpoints
- [ ] Batch ping operation
- [ ] Live status display UI
- [ ] Response time tracking

### Phase 6: UI Enhancements
- [ ] Dashboard improvements
- [ ] Scan results page
- [ ] Ping results page
- [ ] Notification system

## UI Components

### Dashboard
```
+------------------+------------------+------------------+
| Subnet Overview  | Active Hosts     | Recent Activity  |
+------------------+------------------+------------------+
| Usage Charts     | Quick Ping       | Scan Status      |
+------------------+------------------+------------------+
```

### Subnet Scanner Page
- Subnet CIDR input
- Scan type selection (ping/arp/ndp)
- Start/Stop scan buttons
- Live progress indicator
- Results table with:
  - IP Address
  - MAC Address
  - Hostname (via reverse DNS)
  - Response Time
  - Status
  - Actions

### IP Ping Tool
- Single IP input with ping button
- Range input for batch ping (192.168.1.1-50)
- Scan subnet buttons
- Live results panel
- CSV export option

## Security Considerations

1. **Authentication**
   - LDAP encryption (TLS)
   - Password hashing
   - Session management
   - CSRF protection

2. **Data Security**
   - Database encryption
   - SSL/TLS for all traffic
   - API key management
   - Audit logging

3. **Access Control**
   - RBAC implementation
   - Role-based permissions
   - Audit trail
   - IP whitelisting

## Configuration Variables (.env)

```bash
MYSQL_ROOT_PASSWORD=your_root_password
MYSQL_PASSWORD=your_phpipam_password
MYSQL_DATABASE=phpipam

# AD Configuration
AD_SERVER=ldap://ad.example.com
AD_BASE_DN=dc=example,dc=com
AD_BIND_USER=phpipam_admin
AD_BIND_PASSWORD=secure_password

# Application
APP_ENV=production
APP_DEBUG=false
APP_URL=https://ipam.example.com
```

## Deployment Steps

1. Create project directory
2. Copy docker-compose.yml and configuration files
3. Create SSL certificates
4. Edit .env with credentials
5. Start containers: `docker-compose up -d`
6. Access web UI at https://ipam.example.com
7. Run database migrations
8. Configure Active Directory settings
9. Test authentication
10. Configure first subnet
11. Start subnet scanning

## Verification Steps

1. **Infrastructure Test**
   - Verify all containers are running
   - Check database connectivity
   - Test Redis caching

2. **Authentication Test**
   - Test LDAP login
   - Verify group mapping
   - Test SSO flow

3. **IPAM Functionality Test**
   - Create subnet
   - Add IP addresses
   - Test VLAN/VRF

4. **Scanner Test**
   - Run subnet scan
   - Verify active host detection
   - Check MAC address capture

5. **Ping Feature Test**
   - Single IP ping
   - Batch ping test
   - Response time logging

## Dependencies

- Docker Engine 20.10+
- Docker Compose 2.0+
- PHP 7.4+ / 8.0+ (PHPIPAM)
- MySQL 8.0+
- Redis 6.0+
- Active Directory domain controller

## Future Enhancements

1. Grafana integration for metrics
2. REST API documentation
3. Mobile responsive UI
4. Webhooks for automation
5. Backup/restore functionality
6. Multiple AD server support
7. Advanced reporting engine
8. SLA tracking per subnet