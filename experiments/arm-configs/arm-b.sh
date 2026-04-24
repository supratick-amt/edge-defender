#!/bin/bash
# arm-b.sh — Slow two-stage.
# ===========================
# Same pipeline shape as Arm A but dialed way down.
# naabu rate ~50, nmap -T3 with explicit --max-rate.
#
# T3 + --max-rate is used (not T2) because T2 serializes probes with a 400ms
# inter-probe delay that causes nmap to hang against sparse targets. T3 with
# --max-rate gives us controlled pacing without that bottleneck.

set -euo pipefail

HOST="$1"
OUT_DIR="$2"

if command -v naabu >/dev/null 2>&1; then
  echo "[arm-b] naabu discovery rate=50 top-ports=1000..."
  naabu -host "$HOST" \
        -top-ports 1000 \
        -rate 50 \
        -silent \
        -o "$OUT_DIR/naabu-discovery.txt" \
    || true
  PORTS=$(awk -F: '{print $NF}' "$OUT_DIR/naabu-discovery.txt" | sort -un | paste -sd,)
else
  echo "[arm-b] WARN: naabu not installed."
  PORTS=""
fi

echo "[arm-b] nmap -sV -T3 --max-rate 50..."
if [[ -n "$PORTS" ]]; then
  nmap -sV -T3 --max-rate 50 -Pn \
       --defeat-rst-ratelimit \
       --max-rtt-timeout 2s \
       -p "$PORTS" \
       -oA "$OUT_DIR/nmap" \
       "$HOST"
else
  nmap -sV -T3 --max-rate 50 -Pn \
       --defeat-rst-ratelimit \
       --max-rtt-timeout 2s \
       --top-ports 1000 \
       -oA "$OUT_DIR/nmap" \
       "$HOST"
fi
