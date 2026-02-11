#!/bin/bash
#
# MAC/ARP Scanner Script
# Discovers hosts on local network using ARP scanning
#
# Usage: ./mac-arp-scanner.sh <interface> [subnet]
# Example: ./mac-arp-scanner.sh eth0 192.168.1.0/24
#

set -e

# Configuration
TIMEOUT=${ARP_TIMEOUT:-2}
RETRIES=${ARP_RETRIES:-2}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-text}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse arguments
INTERFACE=$1
SUBNET=$2

usage() {
    echo "Usage: $0 <interface> [subnet]"
    echo ""
    echo "Arguments:"
    echo "  interface   Network interface to use (e.g., eth0)"
    echo "  subnet      Optional subnet in CIDR notation (auto-detected if not provided)"
    echo ""
    echo "Options:"
    echo "  -j          Output in JSON format"
    echo "  -o FILE     Write results to file"
    echo ""
    echo "Examples:"
    echo "  $0 eth0"
    echo "  $0 eth0 192.168.1.0/24"
    exit 1
}

if [ -z "$INTERFACE" ]; then
    usage
fi

# Check if running as root (required for ARP scanning)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: ARP scanning may require root privileges${NC}"
fi

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        exit 1
    fi
}

# Detect subnet if not provided
if [ -z "$SUBNET" ]; then
    # Get IP and netmask from interface
    IP_INFO=$(ip addr show "$INTERFACE" 2>/dev/null | grep "inet " | head -1 | awk '{print $2}')
    if [ -z "$IP_INFO" ]; then
        echo -e "${RED}Error: Could not detect subnet for interface $INTERFACE${NC}"
        exit 1
    fi
    SUBNET="$IP_INFO"
    echo -e "${BLUE}Auto-detected subnet: $SUBNET${NC}"
fi

echo -e "${BLUE}Starting ARP scan on $INTERFACE for $SUBNET${NC}"
echo ""

# Try different ARP scanning methods
scan_with_arp_scan() {
    check_tool arp-scan

    echo "Using arp-scan..."
    arp-scan --interface="$INTERFACE" --retry="$RETRIES" --timeout="$TIMEOUT" "$SUBNET" 2>/dev/null | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        while read -r ip mac vendor; do
            if [ "$OUTPUT_FORMAT" = "json" ]; then
                echo "{\"ip\":\"$ip\",\"mac\":\"$mac\",\"vendor\":\"$vendor\"}"
            else
                printf "%-16s %-18s %s\n" "$ip" "$mac" "$vendor"
            fi
        done
}

scan_with_nmap() {
    check_tool nmap

    echo "Using nmap ARP scan..."
    nmap -sn -PR "$SUBNET" 2>/dev/null | \
        grep -E 'Nmap scan report|MAC Address' | \
        paste - - | \
        while read -r line; do
            ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+')
            mac=$(echo "$line" | grep -oP '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
            vendor=$(echo "$line" | grep -oP '\(.*\)' | tr -d '()')

            if [ -n "$ip" ]; then
                if [ "$OUTPUT_FORMAT" = "json" ]; then
                    echo "{\"ip\":\"$ip\",\"mac\":\"${mac:-unknown}\",\"vendor\":\"${vendor:-unknown}\"}"
                else
                    printf "%-16s %-18s %s\n" "$ip" "${mac:-N/A}" "${vendor:-N/A}"
                fi
            fi
        done
}

scan_with_arping() {
    check_tool arping

    echo "Using arping..."
    IFS='/' read -r network mask <<< "$SUBNET"
    IFS='.' read -r a b c d <<< "$network"

    base=$((a * 16777216 + b * 65536 + c * 256 + d))
    hosts=$((2 ** (32 - mask) - 2))

    for ((i = 1; i <= hosts; i++)); do
        ip_num=$((base + i))
        ip="$((ip_num >> 24 & 255)).$((ip_num >> 16 & 255)).$((ip_num >> 8 & 255)).$((ip_num & 255))"

        result=$(arping -c 1 -w "$TIMEOUT" -I "$INTERFACE" "$ip" 2>/dev/null || true)
        if echo "$result" | grep -q "bytes from"; then
            mac=$(echo "$result" | grep -oP '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -1)
            if [ "$OUTPUT_FORMAT" = "json" ]; then
                echo "{\"ip\":\"$ip\",\"mac\":\"$mac\"}"
            else
                printf "%-16s %-18s\n" "$ip" "$mac"
            fi
        fi
    done
}

# Header
if [ "$OUTPUT_FORMAT" != "json" ]; then
    echo "=========================================="
    printf "%-16s %-18s %s\n" "IP Address" "MAC Address" "Vendor"
    echo "=========================================="
fi

RESULTS=""

# Try scanning methods in order of preference
if command -v arp-scan &> /dev/null; then
    RESULTS=$(scan_with_arp_scan)
elif command -v nmap &> /dev/null; then
    RESULTS=$(scan_with_nmap)
elif command -v arping &> /dev/null; then
    RESULTS=$(scan_with_arping)
else
    echo -e "${RED}Error: No ARP scanning tool available (arp-scan, nmap, or arping required)${NC}"
    exit 1
fi

if [ "$OUTPUT_FORMAT" = "json" ]; then
    echo "["
    echo "$RESULTS" | sed 's/$/,/' | sed '$ s/,$//'
    echo "]"
else
    echo "$RESULTS"
    COUNT=$(echo "$RESULTS" | grep -c "^" || echo "0")
    echo ""
    echo "=========================================="
    echo "Total hosts discovered: $COUNT"
    echo "=========================================="
fi

# Also update ARP cache
echo ""
echo -e "${BLUE}Current ARP cache:${NC}"
arp -an 2>/dev/null | head -20 || ip neigh show 2>/dev/null | head -20

exit 0
