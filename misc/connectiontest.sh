#!/bin/bash

# === CONFIGURE THESE 3 ===
SERVER_IP="10.1.2.3"      # Target server you're connecting to
PORT=443                  # TCP port to test
OUT_IF="eth0"             # Interface towards that server
NEXT_HOP="10.1.2.1"       # Next-hop for ARP:
                          #   - If server is same subnet: use SERVER_IP
                          #   - If routed: use gateway IP on that interface
# =========================

LOG="conn_arp_${SERVER_IP}_$(date +%Y%m%d_%H%M%S).log"

echo "# Connectivity + ARP/neigh monitor" | tee -a "$LOG"
echo "# Server IP: $SERVER_IP  Port: $PORT" | tee -a "$LOG"
echo "# Outgoing interface: $OUT_IF"       | tee -a "$LOG"
echo "# Next-hop for ARP: $NEXT_HOP"       | tee -a "$LOG"
echo "# Started: $(date)"                  | tee -a "$LOG"
echo ""                                    | tee -a "$LOG"

while true; do
    TS=$(date "+%F %T.%3N")   # timestamp with ms

    # Silent TCP connect using /dev/tcp (bash built-in)
    if echo > /dev/tcp/${SERVER_IP}/${PORT} 2>/dev/null; then
        STATUS="OK"
    else
        STATUS="FAIL"
    fi

    # Compact screen output
    echo "$TS $STATUS"

    {
        echo "===== $TS STATUS=$STATUS ====="

        if [ -n "$NEXT_HOP" ]; then
            echo "# ip neigh for next-hop ($NEXT_HOP):"
            ip neigh show "$NEXT_HOP"
            echo "# ip -s neigh for next-hop ($NEXT_HOP):"
            ip -s neigh show "$NEXT_HOP"
        else
            echo "# NEXT_HOP not set, skipping per-host ARP"
        fi

        if [ -n "$OUT_IF" ]; then
            echo "# ip neigh on interface $OUT_IF:"
            ip neigh show dev "$OUT_IF"
        else
            echo "# OUT_IF not set, skipping per-interface neigh dump"
        fi

        echo
    } >> "$LOG"

    sleep 0.5
done
