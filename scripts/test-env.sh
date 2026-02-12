#!/bin/bash
# =============================================================================
# Test Environment Manager
# =============================================================================
# Spins up 30 mock devices on 3 isolated Docker subnets that the IPAM scanner
# can reach. No traffic touches your real internal network.
#
# Subnets:
#   172.30.1.0/24 — Servers & Infrastructure  (10 devices)
#   172.30.2.0/24 — Workstations & End Users  (10 devices)
#   172.30.3.0/24 — IoT & Facilities          (10 devices)
#
# Usage:
#   ./scripts/test-env.sh start   - Launch mock devices, register subnets
#   ./scripts/test-env.sh stop    - Remove mock devices (IPAM keeps running)
#   ./scripts/test-env.sh status  - Show mock device status
#   ./scripts/test-env.sh scan    - Trigger immediate scan of all test subnets
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Source .env for database credentials
if [ -f .env ]; then
    set -a
    source .env
    set +a
else
    echo "Error: .env file not found. Run ./setup.sh first."
    exit 1
fi

COMPOSE_TEST="docker compose -f docker-compose.yml -f docker-compose.test.yml"

# All mock container names
MOCK_CONTAINERS=(
    # Servers (172.30.1.0/24)
    mock-gw-core mock-web-srv-01 mock-web-srv-02
    mock-db-srv-01 mock-db-srv-02 mock-app-srv-01
    mock-file-srv-01 mock-mail-srv-01 mock-dns-srv-01 mock-dc-01
    # Workstations (172.30.2.0/24)
    mock-gw-floor2 mock-ws-pc-01 mock-ws-pc-02 mock-ws-pc-03
    mock-ws-pc-04 mock-ws-pc-05 mock-ws-laptop-01 mock-ws-laptop-02
    mock-conf-room-01 mock-conf-room-02
    # IoT (172.30.3.0/24)
    mock-gw-iot mock-printer-floor1 mock-printer-floor2
    mock-cam-lobby mock-cam-parking mock-cam-server-room
    mock-switch-mgmt-01 mock-switch-mgmt-02 mock-hvac-controller
    mock-badge-reader-01
)

# Subnet definitions: CIDR|Description
TEST_SUBNETS=(
    "172.30.1.0|24|Servers & Infrastructure"
    "172.30.2.0|24|Workstations & End Users"
    "172.30.3.0|24|IoT & Facilities"
)

usage() {
    cat <<'EOF'
Usage: ./scripts/test-env.sh {start|stop|status|scan}

Manage mock test devices for IPAM testing.
Creates 30 mock devices across 3 isolated subnets.

Commands:
  start   - Start mock devices and register test subnets in PHPIPAM
  stop    - Stop and remove mock devices (keeps IPAM running)
  status  - Show status of mock devices and test subnets
  scan    - Trigger immediate scan of all test subnets
EOF
}

register_test_subnets() {
    echo "Registering test subnets in PHPIPAM database..."

    docker compose exec -T mysql mysql -u root -p"${MYSQL_ROOT_PASSWORD}" phpipam 2>/dev/null <<'EOSQL'
-- Create test section if it doesn't exist
INSERT INTO sections (name, description, showVLAN, showVRF, showSupernetOnly)
SELECT 'Test Lab', 'Mock test devices for development', 0, 0, 0
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sections WHERE name = 'Test Lab');

SET @section_id = (SELECT id FROM sections WHERE name = 'Test Lab');

-- Subnet 1: Servers & Infrastructure
INSERT INTO subnets (subnet, mask, sectionId, description, scanAgent, pingSubnet, discoverSubnet, isFolder)
SELECT INET_ATON('172.30.1.0'), 24, @section_id, 'Servers & Infrastructure', 1, 1, 1, 0
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM subnets WHERE subnet = INET_ATON('172.30.1.0') AND mask = 24);

-- Subnet 2: Workstations & End Users
INSERT INTO subnets (subnet, mask, sectionId, description, scanAgent, pingSubnet, discoverSubnet, isFolder)
SELECT INET_ATON('172.30.2.0'), 24, @section_id, 'Workstations & End Users', 1, 1, 1, 0
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM subnets WHERE subnet = INET_ATON('172.30.2.0') AND mask = 24);

-- Subnet 3: IoT & Facilities
INSERT INTO subnets (subnet, mask, sectionId, description, scanAgent, pingSubnet, discoverSubnet, isFolder)
SELECT INET_ATON('172.30.3.0'), 24, @section_id, 'IoT & Facilities', 1, 1, 1, 0
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM subnets WHERE subnet = INET_ATON('172.30.3.0') AND mask = 24);

-- Show results
SELECT CONCAT('  ', INET_NTOA(subnet), '/', mask, ' (id=', id, ') — ', description) as 'Registered subnets:'
FROM subnets WHERE sectionId = @section_id ORDER BY subnet;
EOSQL
}

trigger_scan() {
    echo "Triggering scan of all test subnets..."

    for subnet_cidr in "172.30.1.0/24" "172.30.2.0/24" "172.30.3.0/24"; do
        SUBNET_IP="${subnet_cidr%/*}"
        SUBNET_ID=$(docker compose exec -T mysql mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -N -B phpipam \
            -e "SELECT id FROM subnets WHERE subnet = INET_ATON('${SUBNET_IP}') AND mask = 24 LIMIT 1" 2>/dev/null)

        if [ -z "$SUBNET_ID" ]; then
            echo "  Warning: Subnet ${subnet_cidr} not found in database. Run '$0 start' first."
            continue
        fi

        SCAN_ID=$(docker compose exec -T mysql mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -N -B phpipam \
            -e "INSERT INTO subnet_scans (subnet_id, status, scan_type, created_by) VALUES ($SUBNET_ID, 'pending', 'ping', 1); SELECT LAST_INSERT_ID()" 2>/dev/null)

        docker compose exec -T redis redis-cli RPUSH ipam:scan_queue \
            "{\"subnet\":\"${subnet_cidr}\",\"scan_id\":${SCAN_ID},\"subnet_id\":${SUBNET_ID}}" > /dev/null

        echo "  Queued ${subnet_cidr} (scan_id=$SCAN_ID, subnet_id=$SUBNET_ID)"
    done

    echo ""
    echo "Watch progress: docker compose logs -f subnet-scanner"
}

start_env() {
    echo "=== Starting Test Environment ==="
    echo ""

    echo "Starting services with 30 mock devices across 3 subnets..."
    $COMPOSE_TEST up -d

    echo ""
    echo "Waiting for services to be healthy..."
    sleep 5

    register_test_subnets

    echo ""
    echo "=== Test Environment Ready ==="
    echo ""
    echo "172.30.1.0/24 — Servers & Infrastructure (10 devices)"
    echo "  .2  gw-core-01       .10 web-srv-01       .11 web-srv-02"
    echo "  .20 db-srv-01        .21 db-srv-02        .30 app-srv-01"
    echo "  .40 file-srv-01      .50 mail-srv-01      .60 dns-srv-01"
    echo "  .70 dc-01"
    echo ""
    echo "172.30.2.0/24 — Workstations & End Users (10 devices)"
    echo "  .2   gw-floor2       .100 ws-pc-01        .101 ws-pc-02"
    echo "  .102 ws-pc-03        .103 ws-pc-04        .104 ws-pc-05"
    echo "  .110 ws-laptop-01    .111 ws-laptop-02    .200 conf-room-01"
    echo "  .201 conf-room-02"
    echo ""
    echo "172.30.3.0/24 — IoT & Facilities (10 devices)"
    echo "  .2  gw-iot           .10 printer-floor1   .11 printer-floor2"
    echo "  .20 cam-lobby        .21 cam-parking      .22 cam-server-room"
    echo "  .30 switch-mgmt-01   .31 switch-mgmt-02   .40 hvac-controller"
    echo "  .50 badge-reader-01"
    echo ""
    echo "Next steps:"
    echo "  Trigger scans:   ./scripts/test-env.sh scan"
    echo "  Watch scanner:   docker compose logs -f subnet-scanner"
    echo "  Check status:    ./scripts/test-env.sh status"
    echo "  Stop test env:   ./scripts/test-env.sh stop"
}

stop_env() {
    echo "=== Stopping Test Environment ==="
    echo ""

    for container in "${MOCK_CONTAINERS[@]}"; do
        if docker ps -aq -f name="^${container}$" | grep -q .; then
            echo "  Removing $container..."
            docker stop "$container" > /dev/null 2>&1 || true
            docker rm "$container" > /dev/null 2>&1 || true
        fi
    done

    echo ""
    echo "Reconnecting scanner to base network only..."
    docker compose up -d subnet-scanner

    echo ""
    echo "Mock devices removed. Core IPAM services still running."
    echo "Test subnet data remains in database (harmless)."
}

show_status() {
    echo "=== Mock Device Status ==="
    echo ""

    for subnet_label in "Servers (172.30.1.x)" "Workstations (172.30.2.x)" "IoT (172.30.3.x)"; do
        echo "--- $subnet_label ---"
        case "$subnet_label" in
            *172.30.1*) prefix="mock-gw-core mock-web-srv mock-db-srv mock-app-srv mock-file-srv mock-mail-srv mock-dns-srv mock-dc" ;;
            *172.30.2*) prefix="mock-gw-floor mock-ws-pc mock-ws-laptop mock-conf-room" ;;
            *172.30.3*) prefix="mock-gw-iot mock-printer mock-cam mock-switch-mgmt mock-hvac mock-badge" ;;
        esac
        for partial in $prefix; do
            for container in $(docker ps -a --format '{{.Names}}' --filter "name=${partial}" 2>/dev/null); do
                STATUS=$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || echo "?")
                IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$container" 2>/dev/null | xargs)
                printf "  %-28s %-10s %s\n" "$container" "$STATUS" "$IP"
            done
        done
        echo ""
    done

    # Check test subnet registration
    echo "--- PHPIPAM Subnets ---"
    docker compose exec -T mysql mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -N -B phpipam \
        -e "SELECT CONCAT('  ', INET_NTOA(subnet), '/', mask, '  id=', id, '  scanAgent=', scanAgent, '  ', description) FROM subnets WHERE sectionId = (SELECT id FROM sections WHERE name = 'Test Lab')" 2>/dev/null || echo "  (not registered)"

    echo ""

    # Recent scans
    echo "--- Recent Scans ---"
    docker compose exec -T mysql mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -N -B phpipam \
        -e "SELECT CONCAT('  scan #', ss.id, '  ', INET_NTOA(s.subnet), '/', s.mask, '  ', ss.status, '  ', COALESCE(ss.active_hosts,0), '/', COALESCE(ss.total_hosts,0), ' hosts  ', COALESCE(ss.end_time, ss.start_time, 'pending')) FROM subnet_scans ss JOIN subnets s ON ss.subnet_id = s.id WHERE s.sectionId = (SELECT id FROM sections WHERE name = 'Test Lab') ORDER BY ss.id DESC LIMIT 6" 2>/dev/null || echo "  (no scans)"
}

case "${1:-}" in
    start)  start_env ;;
    stop)   stop_env ;;
    status) show_status ;;
    scan)   trigger_scan ;;
    *)      usage; exit 1 ;;
esac
