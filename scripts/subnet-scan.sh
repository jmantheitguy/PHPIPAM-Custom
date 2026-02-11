#!/bin/bash
#
# Subnet Scan Script
# Performs ICMP ping scans on a given subnet
#
# Usage: ./subnet-scan.sh <subnet_cidr> [scan_id]
# Example: ./subnet-scan.sh 192.168.1.0/24 123
#

set -e

# Configuration
TIMEOUT=${SCAN_TIMEOUT:-2}
CONCURRENT=${SCAN_CONCURRENT:-50}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-json}

# Database configuration (from environment)
DB_HOST=${MYSQL_HOST:-mysql}
DB_USER=${MYSQL_USER:-phpipam}
DB_PASS=${MYSQL_PASSWORD:-}
DB_NAME=${MYSQL_DATABASE:-phpipam}

# Redis configuration
REDIS_HOST=${REDIS_HOST:-redis}
REDIS_PORT=${REDIS_PORT:-6379}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Parse arguments
SUBNET=$1
SCAN_ID=$2

if [ -z "$SUBNET" ]; then
    echo "Usage: $0 <subnet_cidr> [scan_id]"
    echo "Example: $0 192.168.1.0/24"
    exit 1
fi

# Validate subnet format
if ! echo "$SUBNET" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
    echo "Error: Invalid subnet format. Use CIDR notation (e.g., 192.168.1.0/24)"
    exit 1
fi

# Calculate network parameters
IFS='/' read -r NETWORK MASK <<< "$SUBNET"
IFS='.' read -r a b c d <<< "$NETWORK"

# Calculate number of hosts
if [ "$MASK" -ge 31 ]; then
    TOTAL_HOSTS=$((2 ** (32 - MASK)))
else
    TOTAL_HOSTS=$((2 ** (32 - MASK) - 2))
fi

echo "Starting subnet scan: $SUBNET"
echo "Total hosts to scan: $TOTAL_HOSTS"
echo "Timeout: ${TIMEOUT}s, Concurrent: $CONCURRENT"

# Update scan status if scan_id provided
update_scan_status() {
    local status=$1
    local active_hosts=$2
    local results=$3

    if [ -n "$SCAN_ID" ] && [ -n "$DB_PASS" ]; then
        if [ "$status" = "running" ]; then
            mysql -h"$DB_HOST" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e \
                "UPDATE subnet_scans SET status='running', start_time=NOW(), total_hosts=$TOTAL_HOSTS WHERE id=$SCAN_ID"
        elif [ "$status" = "completed" ]; then
            mysql -h"$DB_HOST" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e \
                "UPDATE subnet_scans SET status='completed', end_time=NOW(), active_hosts=$active_hosts WHERE id=$SCAN_ID"
        fi
    fi
}

# Ping a single host
ping_host() {
    local ip=$1
    local result

    if ping -c 1 -W "$TIMEOUT" "$ip" > /dev/null 2>&1; then
        # Get response time
        local time=$(ping -c 1 -W "$TIMEOUT" "$ip" 2>/dev/null | grep -oP 'time=\K[0-9.]+' || echo "0")

        # Try to get MAC address
        local mac=$(arp -n "$ip" 2>/dev/null | grep -oP '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' || echo "")

        # Try reverse DNS
        local hostname=$(host "$ip" 2>/dev/null | grep -oP 'pointer \K.*' | sed 's/\.$//' || echo "")

        echo "{\"ip\":\"$ip\",\"alive\":true,\"response_time\":$time,\"mac\":\"$mac\",\"hostname\":\"$hostname\"}"
    else
        echo "{\"ip\":\"$ip\",\"alive\":false}"
    fi
}

export -f ping_host
export TIMEOUT

# Start scan
update_scan_status "running"

ACTIVE_HOSTS=0
RESULTS="["
FIRST=true

# Generate IP list and scan
# Using simple iteration for portability
BASE_IP=$((a * 16777216 + b * 65536 + c * 256 + d))

for ((i = 1; i <= TOTAL_HOSTS; i++)); do
    IP_NUM=$((BASE_IP + i))
    IP="$((IP_NUM >> 24 & 255)).$((IP_NUM >> 16 & 255)).$((IP_NUM >> 8 & 255)).$((IP_NUM & 255))"

    result=$(ping_host "$IP")

    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        RESULTS="$RESULTS,"
    fi
    RESULTS="$RESULTS$result"

    if echo "$result" | grep -q '"alive":true'; then
        ((ACTIVE_HOSTS++))
        echo -e "${GREEN}[ALIVE]${NC} $IP"
    fi

    # Progress indicator
    if [ $((i % 50)) -eq 0 ]; then
        echo "Progress: $i / $TOTAL_HOSTS hosts scanned, $ACTIVE_HOSTS active"
    fi
done

RESULTS="$RESULTS]"

# Complete scan
update_scan_status "completed" "$ACTIVE_HOSTS"

echo ""
echo "=========================================="
echo "Scan Complete"
echo "=========================================="
echo "Total hosts scanned: $TOTAL_HOSTS"
echo "Active hosts found: $ACTIVE_HOSTS"

if [ "$OUTPUT_FORMAT" = "json" ]; then
    echo ""
    echo "Results:"
    echo "$RESULTS" | python3 -m json.tool 2>/dev/null || echo "$RESULTS"
fi

# Publish results to Redis
if command -v redis-cli &> /dev/null; then
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" PUBLISH "ipam:scan_results" \
        "{\"scan_id\":$SCAN_ID,\"subnet\":\"$SUBNET\",\"active_hosts\":$ACTIVE_HOSTS}" > /dev/null 2>&1 || true
fi

exit 0
