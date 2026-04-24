#!/bin/bash
# healthcheck.sh — probe a target and report port states.
# =======================================================
# Quick sanity check: is the target reachable, what are the port states from
# our local perspective? Useful both during dev (is my compose stack up?) and
# on AWS (did the instance bootstrap correctly?).
#
# Usage:
#   ./scripts/healthcheck.sh <target> [host]
#
# If host is omitted, probes 127.0.0.1 with the target's local-mode port map.
# If host is provided (e.g., an EC2 DNS name), probes real ports (22, 80, ...).

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target> [host]" >&2
  exit 1
fi

TARGET="$1"
HOST="${2:-127.0.0.1}"
LOCAL_MODE=true
if [[ "$HOST" != "127.0.0.1" && "$HOST" != "localhost" ]]; then
  LOCAL_MODE=false
fi

# Port map per mode.
# Local: honeypot ports are remapped to 81xx/82xx/.../9999.
# Remote: real honeypot ports.
if $LOCAL_MODE; then
  declare -A PORTS=(
    [ssh]=8122 [telnet]=8123 [smtp]=8125 [smtp_tls]=8465 [smtp_sub]=8587
    [smb]=8145 [http]=8180 [http_alt]=8280 [https]=8443 [https_alt]=8444
    [fortinet]=8541 [tcpwrapped]=9999
  )
else
  declare -A PORTS=(
    [ssh]=22 [telnet]=23 [smtp]=25 [smtp_tls]=465 [smtp_sub]=587
    [smb]=445 [http]=80 [http_alt]=8080 [https]=443 [https_alt]=8443
    [fortinet]=541 [tcpwrapped]=9999
  )
fi

echo "[healthcheck] target=$TARGET host=$HOST mode=$($LOCAL_MODE && echo local || echo remote)"
echo ""

probe_tcp() {
  local name="$1" port="$2"
  # 2-second timeout. nc returns 0 if connected, nonzero otherwise.
  if timeout 2 bash -c "echo > /dev/tcp/$HOST/$port" 2>/dev/null; then
    printf "  %-15s %5d  OPEN\n" "$name" "$port"
  else
    printf "  %-15s %5d  filtered/closed\n" "$name" "$port"
  fi
}

for name in ssh telnet smtp smtp_tls smtp_sub smb http http_alt https https_alt fortinet tcpwrapped; do
  probe_tcp "$name" "${PORTS[$name]}"
done
