# Experiment Runbook

How to run an arm-comparison scan against the protected cohort.

## Prerequisites

- Cohort deployed (either locally via `scripts/local-up.sh` or on AWS)
- `nmap` and `naabu` installed on the scan host
- Arm configs in `experiments/arm-configs/` match the configurations under test
- For AWS scans: SSH access to target instances (for on-demand resets)

## Single-round experiment

One target, one arm, one round:

```bash
./scripts/capture-scan.sh <target> <arm> <target-host>
```

Example:

```bash
./scripts/capture-scan.sh p1-rate-limit arm-a p1.protected-cohort.xxx
```

Output lands in `experiments/results/<target>/<arm>/<UTC-timestamp>/`:

- `nmap.xml` — structured scan output
- `nmap.nmap` — human-readable scan output
- `nmap.gnmap` — grepable scan output
- `metadata.json` — arm config, target host, scan start/end times, reset timestamp immediately prior

## Full experiment: all targets × all arms × N rounds

Every scan round runs against a **freshly reset target**. This is the only way to get clean signal given that defensive state persists across rounds in this threat model.

Recommended order per target:

```
for round in 1..3:
  for arm in [arm-a, arm-b, arm-c]:
    1. reset target
    2. wait ~30s for gatekeeper to be fully up
    3. run arm scan, capture artifact
    4. cool-off pause (~5 min between arms — lets any in-flight state settle)
```

Arm order can be randomized per round to avoid order effects if the cohort is misbehaving.

### Reset between rounds

For local tests:

```bash
cd targets/<target> && docker compose down && docker compose up -d
sleep 30
```

For AWS tests:

```bash
ssh <target-instance> /opt/protected-cohort/scripts/reset-trigger.sh
sleep 30
```

The default hourly cron **does not replace per-round resets**. Use it as a safety net, not as the primary reset mechanism during an active experiment.

## Interpreting results

Per round, for each arm, capture from the port-scan artifact:

- Open ports discovered (count and which specific ports)
- Services identified (`service` and `product` fields — the T2172 enrichment fields)
- Service detection confidence (`conf` and `method` fields)
- Scan wall-clock duration
- Which specific ports were found/missed compared to other arms on the same target

Expected shape of the analysis:

- **P5:** all arms should match — sanity check
- **P1:** Arm A loses ports under burst rates; Arm B/C recover
- **P2:** all arms lose ports after cardinality threshold; slower arms reach further
- **P3:** Arm A trips ban early; later ports filtered; Arm B/C stay under threshold
- **P4:** Arm A's `-sV` probes get WAF-dropped; Arm B recovers some; Arm C rarely runs `-sV` so behavior differs

## Baseline comparison

Run the same arms against the **control cohort** (cooperative honeypot in edge-starter) for each experiment. Control cohort results establish the "no defenses" baseline; protected cohort results show what each defense costs. The delta is the experiment's signal.

## Rounds per arm per cohort

At least **3 rounds per arm per cohort**. One round isn't enough to distinguish signal from scan noise. If variance between rounds is high, add more rounds or investigate (is the reset actually clearing state? is the network path flaky?).

Pause between rounds as needed — overnight is fine for a multi-day experiment. The per-round reset removes all accumulated state, so temporal separation between rounds isn't required for correctness, only for convenience.
