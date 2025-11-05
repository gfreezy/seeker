#!/bin/bash

echo "================================"
echo "Telegram IP Connectivity Test"
echo "================================"
echo ""

# Telegram IP 列表
declare -a TELEGRAM_IPS=(
    "149.154.167.50"
    "149.154.167.51"
    "149.154.175.50"
    "149.154.175.51"
    "91.108.56.130"
    "91.108.56.131"
    "91.108.4.1"
    "91.108.8.1"
)

PORT=443

echo "1. Testing TCP connectivity..."
echo "----------------------------"
for ip in "${TELEGRAM_IPS[@]}"; do
    printf "%-20s : " "$ip:$PORT"
    if nc -zv -w 2 "$ip" "$PORT" 2>&1 | grep -q "succeeded"; then
        echo "✅ Connected"
    else
        echo "❌ Failed"
    fi
done

echo ""
echo "2. Checking routing..."
echo "----------------------------"
for ip in "${TELEGRAM_IPS[@]}"; do
    printf "%-20s : " "$ip"
    route_info=$(route -n get "$ip" 2>/dev/null | grep "interface:" | awk '{print $2}')
    gateway_info=$(route -n get "$ip" 2>/dev/null | grep "gateway:" | awk '{print $2}')

    if [[ "$route_info" == "utun"* ]]; then
        echo "✅ via $route_info (gateway: $gateway_info)"
    else
        echo "⚠️  via $route_info (Direct, not through proxy)"
    fi
done

echo ""
echo "3. Recent Telegram connections in seeker log..."
echo "----------------------------"
grep -E "149\.154|91\.108" seeker.log 2>/dev/null | grep "matched rule.*IpCidr" | tail -5 | while read line; do
    timestamp=$(echo "$line" | awk '{print $1}')
    ip=$(echo "$line" | grep -oE "149\.[0-9]+\.[0-9]+\.[0-9]+|91\.[0-9]+\.[0-9]+\.[0-9]+")
    echo "  [$timestamp] $ip → Proxy"
done

echo ""
echo "================================"
echo "Test completed!"
echo "================================"
