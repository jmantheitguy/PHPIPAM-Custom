#!/bin/bash
#
# IPAM System - Stop
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "=========================================="
echo "  Stopping IPAM System"
echo "=========================================="
echo ""

echo -e "${BLUE}[INFO]${NC} Stopping containers..."
docker compose down

echo ""
echo -e "${GREEN}[SUCCESS]${NC} IPAM system stopped."
echo ""
echo "  Data volumes (mysql_data, redis_data) are preserved."
echo "  To remove volumes:  docker compose down -v"
echo "  To restart:         ./start.sh"
echo ""
