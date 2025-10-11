#!/bin/sh
#
# netpoll_monitor_fullcsv.sh — Comprehensive Netpoll/NIC/Queue metrics → wide CSV
# Author: M.I
# Version: 2.0
#
# Collects:
#   - Netpoll CPU usage (from vsish)
#   - All NIC stats from esxcli network nic stats get
#   - All queue stats from esxcli network nic queue stats get
#
# Usage:
#   chmod +x netpoll_monitor_fullcsv.sh
#   ./netpoll_monitor_fullcsv.sh [interval_seconds] [output_dir]
#

INTERVAL=${1:-5}
OUTDIR=${2:-/tmp}
HOSTNAME=$(hostname)
CSVFILE="${OUTDIR}/netpoll_full_${HOSTNAME}_$(date '+%Y%m%d_%H%M%S').csv"
mkdir -p "$OUTDIR"

echo "------------------------------------------------------------"
echo " ESXi Netpoll/NIC/Queue Full Metrics Logger (Wide CSV)"
echo " Hostname : ${HOSTNAME}"
echo " Interval : ${INTERVAL}s"
echo " Output   : ${CSVFILE}"
echo "------------------------------------------------------------"

# ------------------------------
# 1. Build Dynamic Header
# ------------------------------
HEADER="timestamp"

# --- Netpoll worlds ---
NP_LIST=$(vsish -e ls /worlds | grep NetPoll | sed 's/\///g' | sed 's/NetPoll://' | sort)
for W in $NP_LIST; do
  HEADER="${HEADER},${W}-netpoll-cpuUsage,${W}-netpoll-readyTime,${W}-netpoll-sleepTime,${W}-netpoll-switchCount"
done

# --- NIC stats headers ---
NIC_LIST=$(esxcli network nic list | awk 'NR>1{print $1}')
for NIC in $NIC_LIST; do
  FIELDS=$(esxcli network nic stats get -n $NIC 2>/dev/null | awk -F: '/:/ {gsub(/^[ \t]+|[ \t]+$/,"",$1); gsub(/^[ \t]+|[ \t]+$/,"",$2); f=$1; gsub(" ", "_", f); print f}')
  for F in $FIELDS; do
    HEADER="${HEADER},${NIC}-${F}"
  done
done

# --- Queue stats headers ---
for NIC in $NIC_LIST; do
  QFIELDS=$(esxcli network nic queue stats get -n $NIC 2>/dev/null | awk -F: '/:/ {gsub(/^[ \t]+|[ \t]+$/,"",$1); gsub(/^[ \t]+|[ \t]+$/,"",$2); f=$1; gsub(" ", "_", f); print f}' | sort -u)
  for F in $QFIELDS; do
    HEADER="${HEADER},${NIC}-queue-${F}"
  done
done

echo "$HEADER" > "$CSVFILE"

# ------------------------------
# 2. Functions
# ------------------------------

get_netpoll_stats() {
  for W in $NP_LIST; do
    OUT=$(vsish -e get /worlds/NetPoll:$W/stats 2>/dev/null)
    CPU=$(echo "$OUT" | awk '/cpuUsage/ {print $3}')
    READY=$(echo "$OUT" | awk '/readyTime/ {print $3}')
    SLEEP=$(echo "$OUT" | awk '/sleepTime/ {print $3}')
    SWITCH=$(echo "$OUT" | awk '/switchCount/ {print $3}')
    echo -n ",${CPU:-0},${READY:-0},${SLEEP:-0},${SWITCH:-0}"
  done
}

get_nic_stats() {
  for NIC in $NIC_LIST; do
    OUT=$(esxcli network nic stats get -n $NIC 2>/dev/null)
    VALS=$(echo "$OUT" | awk -F: '/:/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); gsub(",","",$2); printf ",%s",$2}')
    echo -n "$VALS"
  done
}

get_queue_stats() {
  for NIC in $NIC_LIST; do
    OUT=$(esxcli network nic queue stats get -n $NIC 2>/dev/null)
    VALS=$(echo "$OUT" | awk -F: '/:/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); gsub(",","",$2); printf ",%s",$2}')
    echo -n "$VALS"
  done
}

# ------------------------------
# 3. Main loop
# ------------------------------

while true; do
  TS=$(date '+%Y-%m-%d %H:%M:%S')
  LINE="$TS"
  LINE="$LINE$(get_netpoll_stats)"
  LINE="$LINE$(get_nic_stats)"
  LINE="$LINE$(get_queue_stats)"
  echo "$LINE" >> "$CSVFILE"
  echo "[$(date '+%H:%M:%S')] Logged metrics → $CSVFILE"
  sleep "$INTERVAL"
done
