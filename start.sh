#!/bin/bash
#
# IPAM System - Start
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if setup has been run
if [ ! -f .env ]; then
    echo -e "${RED}[ERROR]${NC} .env file not found. Run ./setup.sh first."
    exit 1
fi

if [ ! -f phpipam/index.php ]; then
    echo -e "${RED}[ERROR]${NC} PHPIPAM not found. Run ./setup.sh first."
    exit 1
fi

echo ""
echo "=========================================="
echo "  Starting IPAM System"
echo "=========================================="
echo ""

# Build if images don't exist yet
if ! docker compose images --quiet 2>/dev/null | grep -q .; then
    echo -e "${BLUE}[INFO]${NC} Building Docker images (first run)..."
    docker compose build
fi

# Start all services
echo -e "${BLUE}[INFO]${NC} Starting containers..."
docker compose up -d

# Wait for health checks
echo -e "${BLUE}[INFO]${NC} Waiting for services to become healthy..."

TIMEOUT=120
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    HEALTHY=$(docker compose ps --format json 2>/dev/null | grep -c '"healthy"' || true)
    TOTAL=$(docker compose ps --format json 2>/dev/null | grep -c '"running"\|"healthy"' || true)

    if [ "$HEALTHY" -ge 3 ] 2>/dev/null; then
        break
    fi

    sleep 2
    ELAPSED=$((ELAPSED + 2))
    printf "\r  Waiting... %ds" "$ELAPSED"
done
echo ""

# Show status
echo ""
docker compose ps
echo ""

# Check scanner network isolation
SCANNER_NETWORKS=$(docker inspect ipam-scanner --format '{{range $key, $val := .NetworkSettings.Networks}}{{$key}} {{end}}' 2>/dev/null || true)
if echo "$SCANNER_NETWORKS" | grep -q "scanner-internal"; then
    if ! echo "$SCANNER_NETWORKS" | grep -q "ipam-network"; then
        echo -e "${GREEN}[OK]${NC} Scanner container is network-isolated (scanner-internal only)"
    else
        echo -e "${YELLOW}[WARN]${NC} Scanner is on ipam-network — it may have external access"
    fi
fi

echo ""
echo -e "${GREEN}[SUCCESS]${NC} IPAM system is running."
echo ""
echo "  Web UI:  https://localhost:${HTTPS_PORT:-443}"
echo "  Logs:    docker compose logs -f"
echo "  Stop:    ./stop.sh"
echo ""
