#!/bin/bash
# P5 Filtered-baseline iptables rules.
# ====================================
# Static DROP on a fixed subset of honeypot ports. No adaptive behavior —
# same ports are filtered on every probe, from every source, forever.
#
# The subset is split: some TCP ports are filtered, others are left open.
# This gives the scan arms a mix of "open" and "filtered" results on one host,
# which is the realistic shape of a partially-firewalled real-world target.
#
# Usage:
#   iptables-rules.sh install
#   iptables-rules.sh uninstall
#   iptables-rules.sh status

set -euo pipefail

CHAIN="P5_FILTERED"

# Ports that are FILTERED (DROP — nmap sees "filtered")
FILTERED_PORTS="23,25,445,465,541,587"

# Ports that remain OPEN (no filter rule applied — honeypot answers normally):
# 22, 80, 443, 8080, 8443, 9999
# These are for reference; we don't touch them at the iptables level.

install_rules() {
  if iptables -L "$CHAIN" -n >/dev/null 2>&1; then
    uninstall_rules
  fi

  iptables -N "$CHAIN"
  iptables -A "$CHAIN" -j DROP

  iptables -I INPUT 1 -p tcp \
    -m multiport --dports "$FILTERED_PORTS" \
    -j "$CHAIN"

  echo "[p5-rules] installed. filtered_ports=${FILTERED_PORTS}"
}

uninstall_rules() {
  while iptables -C INPUT -p tcp -m multiport --dports "$FILTERED_PORTS" -j "$CHAIN" 2>/dev/null; do
    iptables -D INPUT -p tcp -m multiport --dports "$FILTERED_PORTS" -j "$CHAIN"
  done

  if iptables -L "$CHAIN" -n >/dev/null 2>&1; then
    iptables -F "$CHAIN"
    iptables -X "$CHAIN"
  fi

  echo "[p5-rules] uninstalled."
}

status() {
  if iptables -L "$CHAIN" -n >/dev/null 2>&1; then
    echo "[p5-rules] chain $CHAIN exists:"
    iptables -L "$CHAIN" -n -v
    echo ""
    echo "[p5-rules] INPUT references:"
    iptables -L INPUT -n -v | grep "$CHAIN" || echo "  (none)"
  else
    echo "[p5-rules] not installed."
  fi
}

case "${1:-}" in
  install)   install_rules ;;
  uninstall) uninstall_rules ;;
  status)    status ;;
  *)
    echo "Usage: $0 {install|uninstall|status}" >&2
    exit 1
    ;;
esac
