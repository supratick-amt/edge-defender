#!/bin/bash
# reset.sh — hourly reset entry point.
# =====================================
# Runs on each target instance via cron. Tears down and recreates the target's
# compose stack, which flushes all defensive state (iptables counters, fail2ban
# jails, WAF caches) because the gatekeeper container is destroyed.
#
# The target this instance runs is determined by the TARGET_NAME env var or a
# /etc/protected-cohort/target file. One target per instance.
#
# Crontab entry (installed at instance bootstrap):
#   0 * * * * /opt/protected-cohort/scripts/reset.sh >> /var/log/protected-cohort-resets.log 2>&1
#
# Manual invocation is fine too (cron and manual go through the same path).

set -euo pipefail

# Where the repo is checked out on the instance. DevOps-configurable.
REPO_ROOT="${PROTECTED_COHORT_ROOT:-/opt/protected-cohort}"

# Resolve which target this instance runs.
resolve_target() {
  if [[ -n "${TARGET_NAME:-}" ]]; then
    echo "$TARGET_NAME"
    return
  fi
  if [[ -f /etc/protected-cohort/target ]]; then
    cat /etc/protected-cohort/target
    return
  fi
  echo "ERROR: TARGET_NAME env var not set and /etc/protected-cohort/target not found" >&2
  exit 1
}

TARGET=$(resolve_target)
TARGET_DIR="$REPO_ROOT/targets/$TARGET"

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "ERROR: target directory not found: $TARGET_DIR" >&2
  exit 1
fi

TIMESTAMP=$(date -u -Iseconds)
TRIGGER="${RESET_TRIGGER:-cron}"

echo "[$TIMESTAMP] reset start target=$TARGET trigger=$TRIGGER"

cd "$TARGET_DIR"
docker compose down
docker compose up --build -d

# Wait for gatekeeper healthcheck to pass before returning so callers can
# proceed with scans knowing the defensive layer is active.
MAX_WAIT=60
WAITED=0
while [[ $WAITED -lt $MAX_WAIT ]]; do
  if docker compose ps --format json 2>/dev/null | grep -q '"Health":"healthy"'; then
    echo "[$(date -u -Iseconds)] reset complete target=$TARGET (gatekeeper healthy after ${WAITED}s)"
    exit 0
  fi
  sleep 2
  WAITED=$((WAITED + 2))
done

echo "[$(date -u -Iseconds)] reset WARN target=$TARGET gatekeeper not healthy after ${MAX_WAIT}s"
exit 1
