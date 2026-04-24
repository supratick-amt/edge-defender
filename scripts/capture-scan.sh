#!/bin/bash
# capture-scan.sh — run an arm scan and save artifacts with metadata.
# ====================================================================
# Wraps the arm-specific scan command (from experiments/arm-configs/) and
# saves all outputs to experiments/results/<target>/<arm>/<timestamp>/.
#
# Usage:
#   ./scripts/capture-scan.sh <target> <arm> <host>
#
# Example:
#   ./scripts/capture-scan.sh p1-rate-limit arm-a p1.protected-cohort.xxx

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <target> <arm> <host>" >&2
  echo "" >&2
  echo "Arms available:" >&2
  ls -1 "$(dirname "${BASH_SOURCE[0]}")/../experiments/arm-configs/" 2>/dev/null | sed 's/\.sh$//' | sed 's/^/  /' >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGET="$1"
ARM="$2"
HOST="$3"

ARM_SCRIPT="$REPO_ROOT/experiments/arm-configs/${ARM}.sh"
if [[ ! -x "$ARM_SCRIPT" ]]; then
  echo "ERROR: arm config not found or not executable: $ARM_SCRIPT" >&2
  exit 1
fi

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT_DIR="$REPO_ROOT/experiments/results/$TARGET/$ARM/$TIMESTAMP"
mkdir -p "$OUT_DIR"

# Record metadata before the scan so we capture intent even if the scan fails.
cat > "$OUT_DIR/metadata.json" <<EOF
{
  "target": "$TARGET",
  "arm": "$ARM",
  "host": "$HOST",
  "start_time_utc": "$(date -u -Iseconds)",
  "scanner_host": "$(hostname)",
  "scanner_ip_hint": "$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || echo unknown)",
  "git_commit": "$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"
}
EOF

echo "[capture-scan] target=$TARGET arm=$ARM host=$HOST"
echo "[capture-scan] output -> $OUT_DIR"
echo ""

# Arm script writes output into $OUT_DIR. Contract: the arm script receives
# the host as $1 and the output directory as $2.
if "$ARM_SCRIPT" "$HOST" "$OUT_DIR"; then
  STATUS="ok"
else
  STATUS="failed"
fi

# Update metadata with end time and status.
python3 - "$OUT_DIR/metadata.json" "$STATUS" <<'PY' 2>/dev/null || true
import json, sys
path, status = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = json.load(f)
d["end_time_utc"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
d["status"] = status
with open(path, "w") as f:
    json.dump(d, f, indent=2)
PY

echo ""
echo "[capture-scan] done. status=$STATUS"
echo "[capture-scan] artifacts in: $OUT_DIR"
