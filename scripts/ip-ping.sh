#!/bin/bash
#
# IP Ping Script
# Performs ping tests on single or multiple IP addresses
#
# Usage:
#   ./ip-ping.sh <ip_address>              # Single IP ping
#   ./ip-ping.sh <start_ip>-<end_ip>       # IP range ping
#   ./ip-ping.sh -f <file>                 # Ping IPs from file
#
# Examples:
#   ./ip-ping.sh 192.168.1.1
#   ./ip-ping.sh 192.168.1.1-192.168.1.50
#   ./ip-ping.sh -f ip_list.txt
#

set -e

# Configuration
COUNT=${PING_COUNT:-3}
TIMEOUT=${PING_TIMEOUT:-2}
INTERVAL=${PING_INTERVAL:-0.2}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-text}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse arguments
usage() {
    echo "Usage: $0 [options] <target>"
    echo ""
    echo "Options:"
    echo "  -c COUNT     Number of ping attempts (default: 3)"
    echo "  -t TIMEOUT   Timeout in seconds (default: 2)"
    echo "  -f FILE      Read IP addresses from file"
    echo "  -j           Output in JSON format"
    echo "  -h           Show this help message"
    echo ""
    echo "Target formats:"
    echo "  Single IP:   192.168.1.1"
    echo "  IP Range:    192.168.1.1-192.168.1.50"
    echo "  CIDR:        192.168.1.0/24"
    exit 1
}

while getopts "c:t:f:jh" opt; do
    case $opt in
        c) COUNT=$OPTARG ;;
        t) TIMEOUT=$OPTARG ;;
        f) IP_FILE=$OPTARG ;;
        j) OUTPUT_FORMAT="json" ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND-1))

TARGET=$1

if [ -z "$TARGET" ] && [ -z "$IP_FILE" ]; then
    usage
fi

# IP to integer conversion
ip_to_int() {
    local ip=$1
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    echo $((a * 16777216 + b * 65536 + c * 256 + d))
}

# Integer to IP conversion
int_to_ip() {
    local num=$1
    echo "$((num >> 24 & 255)).$((num >> 16 & 255)).$((num >> 8 & 255)).$((num & 255))"
}

# Ping a single IP and return results
ping_single() {
    local ip=$1
    local output
    local success=0
    local total_time=0
    local min_time=99999
    local max_time=0
    local lost=0

    output=$(ping -c "$COUNT" -W "$TIMEOUT" -i "$INTERVAL" "$ip" 2>&1) || true

    if echo "$output" | grep -q "bytes from"; then
        success=1

        # Parse timing information
        times=$(echo "$output" | grep -oP 'time=\K[0-9.]+' || true)
        if [ -n "$times" ]; then
            count=0
            for t in $times; do
                total_time=$(echo "$total_time + $t" | bc)
                if (( $(echo "$t < $min_time" | bc -l) )); then
                    min_time=$t
                fi
                if (( $(echo "$t > $max_time" | bc -l) )); then
                    max_time=$t
                fi
                ((count++))
            done
            avg_time=$(echo "scale=2; $total_time / $count" | bc)
        else
            min_time=0
            max_time=0
            avg_time=0
        fi

        # Parse packet loss
        lost=$(echo "$output" | grep -oP '[0-9]+(?=% packet loss)' || echo "0")
    else
        min_time=0
        max_time=0
        avg_time=0
        lost=100
    fi

    if [ "$OUTPUT_FORMAT" = "json" ]; then
        echo "{\"ip\":\"$ip\",\"alive\":$( [ $success -eq 1 ] && echo 'true' || echo 'false'),\"min\":$min_time,\"max\":$max_time,\"avg\":${avg_time:-0},\"loss\":$lost}"
    else
        if [ $success -eq 1 ]; then
            echo -e "${GREEN}[ALIVE]${NC} $ip - min=${min_time}ms avg=${avg_time}ms max=${max_time}ms loss=${lost}%"
        else
            echo -e "${RED}[DOWN]${NC} $ip - no response"
        fi
    fi
}

# Generate IP list from range
generate_range() {
    local range=$1
    local start_ip end_ip
    IFS='-' read -r start_ip end_ip <<< "$range"

    local start_int=$(ip_to_int "$start_ip")
    local end_int=$(ip_to_int "$end_ip")

    for ((i = start_int; i <= end_int; i++)); do
        int_to_ip $i
    done
}

# Generate IP list from CIDR
generate_cidr() {
    local cidr=$1
    local network mask
    IFS='/' read -r network mask <<< "$cidr"

    local net_int=$(ip_to_int "$network")
    local host_bits=$((32 - mask))
    local num_hosts=$((2 ** host_bits - 2))

    for ((i = 1; i <= num_hosts; i++)); do
        int_to_ip $((net_int + i))
    done
}

# Main execution
IP_LIST=()

if [ -n "$IP_FILE" ]; then
    # Read IPs from file
    if [ ! -f "$IP_FILE" ]; then
        echo "Error: File not found: $IP_FILE"
        exit 1
    fi
    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        IP_LIST+=("$line")
    done < "$IP_FILE"
elif [[ "$TARGET" =~ - ]]; then
    # IP range
    while IFS= read -r ip; do
        IP_LIST+=("$ip")
    done < <(generate_range "$TARGET")
elif [[ "$TARGET" =~ / ]]; then
    # CIDR notation
    while IFS= read -r ip; do
        IP_LIST+=("$ip")
    done < <(generate_cidr "$TARGET")
else
    # Single IP
    IP_LIST+=("$TARGET")
fi

# Execute pings
TOTAL=${#IP_LIST[@]}
ALIVE=0
RESULTS="["
FIRST=true

echo -e "${BLUE}Starting ping test for $TOTAL host(s)${NC}"
echo "Count: $COUNT, Timeout: ${TIMEOUT}s"
echo ""

for ip in "${IP_LIST[@]}"; do
    result=$(ping_single "$ip")

    if [ "$OUTPUT_FORMAT" = "json" ]; then
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            RESULTS="$RESULTS,"
        fi
        RESULTS="$RESULTS$result"

        if echo "$result" | grep -q '"alive":true'; then
            ((ALIVE++))
        fi
    else
        echo "$result"
        if echo "$result" | grep -q "ALIVE"; then
            ((ALIVE++))
        fi
    fi
done

if [ "$OUTPUT_FORMAT" = "json" ]; then
    RESULTS="$RESULTS]"
    echo "$RESULTS" | python3 -m json.tool 2>/dev/null || echo "$RESULTS"
else
    echo ""
    echo "=========================================="
    echo "Summary: $ALIVE / $TOTAL hosts alive"
    echo "=========================================="
fi

exit 0
