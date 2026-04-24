#!/bin/bash
# arm-c.sh — Slow nmap-only (no naabu).
# =====================================
# Single-tool pipeline: nmap does discovery itself, at conservative pacing.
# -Pn (per T1154's fix), no -sV during discovery (narrower question per the
# ticket: does the quality delta on blocking targets justify the time cost?).
#
# Port universe matches Arm A/B: nmap's top-1000 ports.
#
# Rationale for -T2 here (vs Arm B's T3): the arm ticket explicitly specifies
# T2 for Arm C. Unlike Arm B where T2's 400ms inter-probe serialization
# becomes a problem for discovery across naabu-surfaced ports, Arm C is
# *expected* to be slow — time cost is part of what we're measuring.
# --max-rate 50 caps the upper bound regardless of T2 internals.
#
# Contract: called with $1 = target host, $2 = output directory.
# Writes nmap.{xml,nmap,gnmap} into $2.

set -euo pipefail

HOST="$1"
OUT_DIR="$2"

echo "[arm-c] nmap discovery: -T2 --max-rate 50 -Pn --top-ports 1000 (no -sV)..."
nmap -sS -T2 --max-rate 50 -Pn \
     --defeat-rst-ratelimit \
     --max-rtt-timeout 2s \
     --top-ports 1000 \
     -oA "$OUT_DIR/nmap" \
     "$HOST"

# Notes for post-hoc analysis:
# - Arm C's artifact will have `service` / `product` fields empty or minimal
#   because -sV was not used. This is intentional — the ticket's question for
#   Arm C is about port *discovery* quality on blocking targets, not service
#   detection. Downstream comparison logic should weight accordingly.
# - Wall-clock duration will typically be the longest of the three arms; this
#   is the "time cost" side of the ticket's tradeoff question.
