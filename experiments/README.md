# Experiments

How the arm-comparison experiment is organized.

## Layout

```
experiments/
├── README.md             # This file
├── arm-configs/          # One script per arm; each is the full scan command
│   ├── arm-a.sh          # Production baseline: naabu 1000 + nmap -T4
│   ├── arm-b.sh          # Slow two-stage: naabu 50 + nmap -T3 --max-rate 50
│   └── arm-c.sh          # Slow nmap-only: -T2 --max-rate 50 -Pn (no -sV)
└── results/              # Scan artifacts land here (gitignored)
    └── <target>/<arm>/<UTC-timestamp>/
        ├── nmap.xml
        ├── nmap.nmap
        ├── nmap.gnmap
        ├── naabu-discovery.txt   (arms A and B only)
        └── metadata.json
```

## Arm definitions

Taken directly from the upstream arm-experiment ticket. Each arm is a fully
self-contained scan pipeline — `arm-X.sh <host> <out-dir>` runs the scan and
writes artifacts into `<out-dir>`.

### Arm A — Production baseline

Mirrors current Global ASM production:

- naabu discovery at rate 1000, top-ports 1000
- nmap `-sV -T4 -Pn` on discovered ports

Aggressive pacing. Expected to lose ports/services on targets with reactive
defenses. Comparison anchor.

### Arm B — Slow two-stage

Same two-stage shape as Arm A, dialed down:

- naabu rate 50
- nmap `-sV -T3 --max-rate 50 -Pn --defeat-rst-ratelimit --max-rtt-timeout 2s`

Tests whether slowing the existing pipeline is enough, with structure held constant.

T3 (not T2) because T2's 400ms inter-probe delay causes nmap to hang against
sparse targets; T3 with explicit `--max-rate` gives controlled pacing without
the hidden bottleneck.

### Arm C — Slow nmap-only

Skips naabu, narrower question about whether the time cost of nmap-only
discovery is justified on blocking targets:

- nmap `-sS -T2 --max-rate 50 -Pn --defeat-rst-ratelimit --max-rtt-timeout 2s --top-ports 1000`
- **No `-sV` during discovery** (per the ticket's scope for Arm C)

Arm C's artifacts will have sparse `service` / `product` fields. This is
intentional — Arm C answers a port-discovery question, not a service-detection
question.

## Running an experiment

See `docs/experiment-runbook.md` for the full procedure. TL;DR:

```bash
# One target, one arm, one round (via the capture helper)
./scripts/capture-scan.sh p1-rate-limit arm-a <target-host>
```

For a full experiment (all targets × all arms × 3 rounds), script a loop that
resets each target before every round:

```bash
for round in 1 2 3; do
  for target in p1-rate-limit p2-cardinality p3-fail2ban p4-waf p5-filtered-baseline; do
    for arm in arm-a arm-b arm-c; do
      # Reset before each measured round (critical — defensive state persists otherwise)
      ./scripts/reset-trigger.sh "$target"
      sleep 30

      ./scripts/capture-scan.sh "$target" "$arm" "$TARGET_HOSTS_MAP[$target]"

      # Cool-off between arms, lets any in-flight state settle
      sleep 300
    done
  done
done
```

In practice the reset needs to happen on the target *instance*, not the scan
host — so the above loop has to SSH to the target or hit its reset webhook.
See the runbook.

## Capturing from the scan artifact

Per the original arm-experiment ticket, compare these signals per arm per round:

- **Open ports discovered** (count and which specific ports)
- **Services identified** — `service` and `product` fields (T2172 enrichment)
- **Service detection confidence** — `conf` and `method` fields
- **Scan wall-clock duration** (nmap's `Elapsed:` line)
- **Port set delta** — which ports found/missed compared to other arms on the same target

`nmap.xml` is the machine-readable source; `nmap.nmap` is human-readable.

## Baseline comparison

Each experiment should also run the same arms against the **control cohort**
(cooperative honeypot in edge-starter). The control run establishes "what the
arms find when nothing is fighting back." The protected-cohort run shows what
each defense costs. The delta is the experiment's signal.

## Notes on rounds

- **At least 3 rounds per arm per cohort.** One round is not enough to tell
  signal from scan noise.
- **Reset between every round**, not just between arms. With no IP rotation in
  production, defensive state persists across rounds; without reset, Arm A's
  impact pollutes Arm B's measurement.
- **Overnight pauses are fine** between rounds — per-round reset removes
  accumulated state, so temporal separation isn't required for correctness.
- Consider randomizing arm order per round if you suspect order effects.
