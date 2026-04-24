#!/bin/bash
# local-up.sh — spin one target locally for development/testing.
# ==============================================================
# Builds and starts the target's compose stack. Honeypot binds on remapped
# high ports (see each target's docker-compose.yml for the port map).
#
# Usage:
#   ./scripts/local-up.sh <target>
#
# Example:
#   ./scripts/local-up.sh p1-rate-limit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <target>" >&2
  echo "" >&2
  echo "Available targets:" >&2
  ls -1 "$REPO_ROOT/targets/" | sed 's/^/  /' >&2
  exit 1
fi

TARGET="$1"
TARGET_DIR="$REPO_ROOT/targets/$TARGET"

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "ERROR: target not found: $TARGET_DIR" >&2
  exit 1
fi

# Sanity check: honeypot submodule must be checked out.
if [[ ! -f "$REPO_ROOT/honeypot/Dockerfile" ]]; then
  echo "ERROR: honeypot submodule not initialized." >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

echo "[local-up] bringing up $TARGET..."
cd "$TARGET_DIR"
docker compose up --build -d

echo "[local-up] up. Showing gatekeeper logs (Ctrl-C to detach; stack keeps running)."
echo "[local-up] to tear down: ./scripts/local-down.sh $TARGET"
echo ""
docker compose logs -f gatekeeper 2>/dev/null || docker compose logs -f
