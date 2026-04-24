#!/bin/bash
# P1 Rate-limit iptables rules.
# =============================
# Caps new TCP connections from any single source IP at ~20/sec, with a small
# burst allowance. Over-limit SYNs are silently dropped (DROP, not REJECT) so
# nmap sees "filtered" rather than "closed".
#
# Only affects NEW connections to the honeypot's published ports. ESTABLISHED
# and RELATED traffic is untouched so already-accepted connections can complete.
#
# Honeypot ports gated by this rule (on the container's host network):
#   TCP: 22, 23, 25, 80, 443, 445, 465, 541, 587, 8080, 8443, 9999
#
# The rule set lives in a dedicated chain P1_RATE_LIMIT so it can be cleanly
# installed and uninstalled without disturbing any other iptables rules on the
# host.
#
# Usage:
#   iptables-rules.sh install
#   iptables-rules.sh uninstall
#   iptables-rules.sh status

set -euo pipefail

CHAIN="P1_RATE_LIMIT"

# Ports the honeypot exposes (from the honeypot's CVE configs).
HONEYPOT_PORTS="22,23,25,80,443,445,465,541,587,8080,8443,9999"

# Rate-limit parameters. Picked to sit ~20/sec sustained with a brief burst.
# --hashlimit-above: the threshold above which traffic is dropped.
# --hashlimit-burst: how many packets can arrive before rate limiting engages.
# --hashlimit-mode srcip: bucket per source IP.
# --hashlimit-htable-expire: how long an idle source-IP bucket lives before GC.
HASHLIMIT_RATE="20/sec"
HASHLIMIT_BURST="5"
HASHLIMIT_EXPIRE_MS="60000"
HASHLIMIT_NAME="p1_ratelimit"

install_rules() {
  # If chain already exists, uninstall first so reinstall is idempotent.
  if iptables -L "$CHAIN" -n >/dev/null 2>&1; then
    uninstall_rules
  fi

  iptables -N "$CHAIN"

  # Rate-limit new TCP connections. Returns ACCEPT if under the limit.
  iptables -A "$CHAIN" \
    -p tcp -m conntrack --ctstate NEW \
    -m hashlimit \
    --hashlimit-above "$HASHLIMIT_RATE" \
    --hashlimit-burst "$HASHLIMIT_BURST" \
    --hashlimit-mode srcip \
    --hashlimit-name "$HASHLIMIT_NAME" \
    --hashlimit-htable-expire "$HASHLIMIT_EXPIRE_MS" \
    -j DROP

  # Anything that wasn't dropped returns to the caller (INPUT) chain.
  iptables -A "$CHAIN" -j RETURN

  # Jump to our chain from INPUT for TCP traffic destined to honeypot ports.
  iptables -I INPUT 1 -p tcp \
    -m multiport --dports "$HONEYPOT_PORTS" \
    -m conntrack --ctstate NEW \
    -j "$CHAIN"

  echo "[p1-rules] installed. rate=${HASHLIMIT_RATE} burst=${HASHLIMIT_BURST} ports=${HONEYPOT_PORTS}"
}

uninstall_rules() {
  # Remove INPUT jump rule (may be present multiple times if reinstalled; loop).
  while iptables -C INPUT -p tcp -m multiport --dports "$HONEYPOT_PORTS" \
        -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null; do
    iptables -D INPUT -p tcp -m multiport --dports "$HONEYPOT_PORTS" \
      -m conntrack --ctstate NEW -j "$CHAIN"
  done

  # Flush and delete chain.
  if iptables -L "$CHAIN" -n >/dev/null 2>&1; then
    iptables -F "$CHAIN"
    iptables -X "$CHAIN"
  fi

  echo "[p1-rules] uninstalled."
}

status() {
  if iptables -L "$CHAIN" -n >/dev/null 2>&1; then
    echo "[p1-rules] chain $CHAIN exists:"
    iptables -L "$CHAIN" -n -v
    echo ""
    echo "[p1-rules] INPUT references:"
    iptables -L INPUT -n -v | grep "$CHAIN" || echo "  (none)"
  else
    echo "[p1-rules] not installed."
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
