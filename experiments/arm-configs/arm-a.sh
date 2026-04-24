#!/bin/bash
# arm-a.sh — Production-like baseline.
# =====================================
# naabu discovery at rate ~1000, then nmap -sV -T4 on discovered ports.
# Mirrors current production Global ASM configuration.
#
# Contract: called with $1 = target host, $2 = output directory.
# Writes nmap.{xml,nmap,gnmap} and optionally naabu-discovery.txt into $2.

set -euo pipefail

HOST="$1"
OUT_DIR="$2"

# Stage 1: naabu discovery of top-1000 ports.
if command -v naabu >/dev/null 2>&1; then
  echo "[arm-a] naabu discovery rate=1000 top-ports=1000..."
  naabu -host "$HOST" \
        -top-ports 1000 \
        -rate 1000 \
        -silent \
        -o "$OUT_DIR/naabu-discovery.txt" \
    || true
  # naabu output format: host:port. Extract just the ports.
  PORTS=$(awk -F: '{print $NF}' "$OUT_DIR/naabu-discovery.txt" | sort -un | paste -sd,)
else
  echo "[arm-a] WARN: naabu not installed, using nmap top-ports directly."
  PORTS=""
fi

# Stage 2: nmap -sV on discovered ports at T4.
echo "[arm-a] nmap -sV -T4..."
if [[ -n "$PORTS" ]]; then
  nmap -sV -T4 -Pn \
       -p "$PORTS" \
       -oA "$OUT_DIR/nmap" \
       "$HOST"
else
  # Fallback: top-1000 directly via nmap.
  nmap -sV -T4 -Pn \
       --top-ports 1000 \
       -oA "$OUT_DIR/nmap" \
       "$HOST"
fi
