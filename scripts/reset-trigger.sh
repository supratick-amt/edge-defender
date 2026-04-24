#!/bin/bash
# reset-trigger.sh — on-demand reset.
# ====================================
# For experiment rounds where precise timing matters (e.g., 3 consecutive
# rounds of one arm with resets between each), call this before each round.
#
# Sets RESET_TRIGGER=manual so logs distinguish on-demand from scheduled.
# Everything else is the same as reset.sh.
#
# Usage (on the target instance):
#   ./scripts/reset-trigger.sh
#
# Remote:
#   ssh <instance> /opt/protected-cohort/scripts/reset-trigger.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RESET_TRIGGER="manual"
exec "$SCRIPT_DIR/reset.sh"
