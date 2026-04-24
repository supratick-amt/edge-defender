#!/bin/bash
# local-down.sh — tear down a locally running target.
# Usage: ./scripts/local-down.sh <target>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <target>" >&2
  exit 1
fi

TARGET="$1"
TARGET_DIR="$REPO_ROOT/targets/$TARGET"

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "ERROR: target not found: $TARGET_DIR" >&2
  exit 1
fi

cd "$TARGET_DIR"
echo "[local-down] stopping $TARGET..."
docker compose down

# Offer volume cleanup, don't force it.
if docker volume ls -q | grep -q "^${TARGET//-/_}_honeypot_logs$"; then
  echo "[local-down] honeypot_logs volume still exists. To remove: docker compose down -v"
fi
