# Test Device Inventory

Mock devices for testing the IPAM scanner without touching real infrastructure.
All devices are minimal Alpine Linux containers (~5MB each) on isolated Docker networks with `internal: true` (no external routing).

## Quick Start

```bash
./scripts/test-env.sh start   # Launch 30 devices, register 3 subnets
./scripts/test-env.sh scan    # Trigger immediate scan of all subnets
./scripts/test-env.sh status  # Show device status + recent scan results
./scripts/test-env.sh stop    # Tear down devices, keep IPAM running
```

## Network Topology

```
  scanner-internal (172.29.0.0/16)     test-servers (172.30.1.0/24)
 ┌──────────────────────┐            ┌──────────────────────────┐
 │  mysql   redis       │            │  10 server devices       │
 │                      │            │  (.2 - .70)              │
 └──────────┬───────────┘            └──────────┬───────────────┘
            │                                   │
            ├───────────── scanner ──────────────┤
            │                                   │
 ┌──────────┴───────────┐            ┌──────────┴───────────────┐
 │  test-workstations   │            │  test-iot                │
 │  (172.30.2.0/24)     │            │  (172.30.3.0/24)         │
 │  10 workstations     │            │  10 IoT devices          │
 │  (.2 - .201)         │            │  (.2 - .50)              │
 └──────────────────────┘            └──────────────────────────┘
```

The scanner has interfaces on all three test networks plus `scanner-internal` (for MySQL/Redis access). Each test network is fully isolated — devices cannot reach the internet or other Docker networks.

## Subnet 1: Servers & Infrastructure — 172.30.1.0/24

| IP | Hostname | Container Name | Role |
|---|---|---|---|
| 172.30.1.2 | gw-core-01 | mock-gw-core | Core gateway/router |
| 172.30.1.10 | web-srv-01 | mock-web-srv-01 | Web server (primary) |
| 172.30.1.11 | web-srv-02 | mock-web-srv-02 | Web server (secondary) |
| 172.30.1.20 | db-srv-01 | mock-db-srv-01 | Database server (primary) |
| 172.30.1.21 | db-srv-02 | mock-db-srv-02 | Database server (replica) |
| 172.30.1.30 | app-srv-01 | mock-app-srv-01 | Application server |
| 172.30.1.40 | file-srv-01 | mock-file-srv-01 | File server |
| 172.30.1.50 | mail-srv-01 | mock-mail-srv-01 | Mail server |
| 172.30.1.60 | dns-srv-01 | mock-dns-srv-01 | DNS server |
| 172.30.1.70 | dc-01 | mock-dc-01 | Domain controller |

## Subnet 2: Workstations & End Users — 172.30.2.0/24

| IP | Hostname | Container Name | Role |
|---|---|---|---|
| 172.30.2.2 | gw-floor2 | mock-gw-floor2 | Floor 2 gateway |
| 172.30.2.100 | ws-pc-01 | mock-ws-pc-01 | Desktop workstation |
| 172.30.2.101 | ws-pc-02 | mock-ws-pc-02 | Desktop workstation |
| 172.30.2.102 | ws-pc-03 | mock-ws-pc-03 | Desktop workstation |
| 172.30.2.103 | ws-pc-04 | mock-ws-pc-04 | Desktop workstation |
| 172.30.2.104 | ws-pc-05 | mock-ws-pc-05 | Desktop workstation |
| 172.30.2.110 | ws-laptop-01 | mock-ws-laptop-01 | Laptop (docked) |
| 172.30.2.111 | ws-laptop-02 | mock-ws-laptop-02 | Laptop (docked) |
| 172.30.2.200 | conf-room-01 | mock-conf-room-01 | Conference room PC |
| 172.30.2.201 | conf-room-02 | mock-conf-room-02 | Conference room PC |

## Subnet 3: IoT & Facilities — 172.30.3.0/24

| IP | Hostname | Container Name | Role |
|---|---|---|---|
| 172.30.3.2 | gw-iot | mock-gw-iot | IoT network gateway |
| 172.30.3.10 | printer-floor1 | mock-printer-floor1 | Network printer (Floor 1) |
| 172.30.3.11 | printer-floor2 | mock-printer-floor2 | Network printer (Floor 2) |
| 172.30.3.20 | cam-lobby | mock-cam-lobby | IP camera (lobby) |
| 172.30.3.21 | cam-parking | mock-cam-parking | IP camera (parking lot) |
| 172.30.3.22 | cam-server-room | mock-cam-server-room | IP camera (server room) |
| 172.30.3.30 | switch-mgmt-01 | mock-switch-mgmt-01 | Managed switch |
| 172.30.3.31 | switch-mgmt-02 | mock-switch-mgmt-02 | Managed switch |
| 172.30.3.40 | hvac-controller | mock-hvac-controller | HVAC controller |
| 172.30.3.50 | badge-reader-01 | mock-badge-reader-01 | Badge/access reader |

## Testing Scenarios

### Change Detection
Stop a device and trigger a scan to verify offline alerts:
```bash
docker stop mock-web-srv-01
./scripts/test-env.sh scan
docker compose logs -f subnet-scanner   # watch for "Host offline" alert
docker start mock-web-srv-01            # bring it back
./scripts/test-env.sh scan              # watch for "Host online" alert
```

### Conflict Detection
Docker assigns a new MAC when a container restarts, which the conflict detector picks up as two MACs claiming the same IP:
```bash
docker restart mock-cam-lobby
./scripts/test-env.sh scan
# Check: SELECT * FROM ip_conflicts;
```

### Utilization Tracking
Each scan captures a utilization snapshot. Check trends:
```bash
source .env
docker compose exec -T mysql mysql -u root -p"${MYSQL_ROOT_PASSWORD}" phpipam \
  -e "SELECT INET_NTOA(s.subnet) as subnet, u.active_hosts, u.active_percent, u.snapshot_time
      FROM subnet_utilization_snapshots u
      JOIN subnets s ON u.subnet_id = s.id
      ORDER BY u.id DESC LIMIT 10;"
```

## Notes

- `.1` on each subnet is reserved by Docker as the bridge gateway (responds to ping but is not a mock device)
- The scanner container also appears as a host on each subnet (gets a dynamic IP)
- Hostnames resolve via Docker's embedded DNS — reverse lookups return `<container_name>.<compose_network>`
- MAC addresses are auto-assigned by Docker and change on container restart
