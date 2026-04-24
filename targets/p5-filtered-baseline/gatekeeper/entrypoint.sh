#!/bin/bash
# P5 gatekeeper entrypoint.
# Installs static DROP rules on the filtered subset of ports, then idles.
set -euo pipefail

echo "[p5-gatekeeper] installing filter rules..."
/usr/local/bin/iptables-rules.sh install

cleanup() {
  echo "[p5-gatekeeper] tearing down filter rules..."
  /usr/local/bin/iptables-rules.sh uninstall || true
  exit 0
}
trap cleanup SIGTERM SIGINT

echo "[p5-gatekeeper] ready. Filtered ports are dropping silently."

# Idle. Rules persist until container exits.
while :; do
  sleep 300
  echo "[p5-gatekeeper] still alive."
done
