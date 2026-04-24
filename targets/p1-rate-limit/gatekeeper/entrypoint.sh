#!/bin/bash
# P1 gatekeeper entrypoint.
# Installs iptables rate-limit rules and then blocks, keeping the container
# alive so the rules persist. On container stop, rules are torn down.
set -euo pipefail

echo "[p1-gatekeeper] installing rate-limit rules..."
/usr/local/bin/iptables-rules.sh install

cleanup() {
  echo "[p1-gatekeeper] tearing down rate-limit rules..."
  /usr/local/bin/iptables-rules.sh uninstall || true
  exit 0
}
trap cleanup SIGTERM SIGINT

echo "[p1-gatekeeper] ready. Rate limit active: ~20 new conn/sec per source IP."
echo "[p1-gatekeeper] iptables chain P1_RATE_LIMIT installed."

# Block indefinitely — tini will forward signals to us and we'll cleanup.
# Also periodically log counter stats so operators can see rate-limit hits.
while :; do
  sleep 60
  echo "[p1-gatekeeper] counter snapshot:"
  iptables -L P1_RATE_LIMIT -n -v 2>&1 | sed 's/^/[p1-gatekeeper]   /' || true
done
