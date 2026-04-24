# Operations

## Deploying a target

### Local (development / testing)

```bash
# One-time: clone with submodules
git clone --recurse-submodules <repo-url>
cd protected-cohort
# Or if already cloned:
git submodule update --init --recursive
```

Spin one target:

```bash
./scripts/local-up.sh p1-rate-limit
```

Tear down:

```bash
./scripts/local-down.sh p1-rate-limit
```

### AWS (production)

AWS provisioning is owned by the DevOps team. Each target should run on its own EC2 instance with its own public IP. Per-instance bootstrap should:

1. Install Docker and docker-compose
2. Clone this repo (with submodules)
3. `cd targets/<target-name> && docker compose up -d --build`
4. Install the reset cron (see below)

## Reset strategy

Reset runs between **every measured scan round**, not just between arms. Accumulated defensive state (rate counters, fail2ban jails, WAF caches) is a confounder otherwise — Arm A's blocks pollute Arm B's measurement.

### Default: hourly cron

Each instance runs `scripts/reset.sh` every hour via cron. The script:

- Runs `docker compose down && docker compose up -d` for that instance's target
- This destroys and recreates the gatekeeper container, flushing all iptables state, fail2ban jails, and WAF caches
- Logs the reset timestamp so it can be correlated with scan runs

Crontab entry installed on each instance:

```
0 * * * * /opt/protected-cohort/scripts/reset.sh >> /var/log/protected-cohort-resets.log 2>&1
```

The target this instance runs is determined by the `TARGET_NAME` environment variable set at bootstrap time (or by a `TARGET_NAME` file in `/etc/protected-cohort/`).

### On-demand: precision reset

For experiment rounds where precise timing matters (e.g., running 3 consecutive rounds of Arm B with resets between), use `scripts/reset-trigger.sh`:

```bash
# On the target instance
./scripts/reset-trigger.sh

# Or remotely via SSH
ssh <target-instance> /opt/protected-cohort/scripts/reset-trigger.sh
```

The trigger script does the same work as the cron but logs the trigger source so we can tell scheduled vs. on-demand resets apart in post-hoc analysis.

### Future: webhook / Slack integration

Not in MVP. Candidates:

- Small HTTP service on each instance exposing `POST /reset`
- Slack slash command that fans out resets to all five targets
- Scan orchestrator that calls reset before each arm invocation

## Health checking

```bash
./scripts/healthcheck.sh p1-rate-limit
```

Outputs one line per honeypot port: `PORT STATE` (e.g., `80 open`, `443 open`, `9999 tcpwrapped`). Quick way to confirm a target is reachable and its gatekeeper isn't accidentally blocking legitimate probes from the local machine.

## Capturing scan artifacts

```bash
./scripts/capture-scan.sh <target> <arm> <target-host>
```

Example:

```bash
./scripts/capture-scan.sh p1-rate-limit arm-a p1.protected-cohort.xxx
```

Wraps the arm-specific scan command (from `experiments/arm-configs/`) and saves output to `experiments/results/<target>/<arm>/<timestamp>/`.

## Retiring a target

Four steps:

1. Stop the target's compose stack: `docker compose -f targets/<target>/docker-compose.yml down -v`
2. Disable the cron on that instance
3. Notify DevOps to tear down the EC2 instance and release the Elastic IP
4. Update `docs/target-catalog.md` marking the target as retired

If the target was serving as a `vuln1.fast-scan-demo-target.click` replacement, also notify the Platform team before teardown.
