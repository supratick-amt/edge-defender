# Protected Cohort

Simulated defended test targets for the nmap arm-comparison experiment.

## What this is

A set of deployable test targets that simulate reactive defensive behaviors (rate limiting, cardinality-based blocking, fail2ban-style adaptive blocks, WAF-fronted HTTP). Each target runs the RootEvidence honeypot behind a defensive layer so scan arms can be compared against realistic blocking behavior — not just against cooperative open targets.

This is the **protected cohort**. It complements the existing **control cohort** (the cooperative honeypot in edge-starter).

See `docs/design.md` for the full design, experimental question, and scope.

## Target inventory

| Target | Defense | Status |
|---|---|---|
| P1 — Rate-limited | iptables hashlimit, ~20 probes/sec/source | **Implemented** |
| P2 — Cardinality-based blocker | iptables recent module, distinct host:port tuples | Scaffolded (stub) |
| P3 — Adaptive connection blocker | fail2ban port-scan jail | Scaffolded (stub) |
| P4 — WAF-fronted HTTP | nginx + ModSecurity/CRS | Scaffolded (stub) |
| P5 — Filtered baseline | iptables DROP, no reactive behavior | **Implemented** |

P1 and P5 are built out end-to-end as the MVP pipeline validation. P2/P3/P4 are scaffolded for the next implementation pass.

## Quick start (local dev)

Clone with submodules:

```bash
git clone --recurse-submodules <repo-url>
cd protected-cohort
```

Or if already cloned:

```bash
git submodule update --init --recursive
```

Spin up one target locally:

```bash
./scripts/local-up.sh p1-rate-limit
```

The target will be reachable on `localhost` at remapped ports (see that target's README for the port map).

## Layout

```
protected-cohort/
├── honeypot/               # git submodule — RootEvidence/honeypot
├── docs/                   # design, threat model, operations, runbooks
├── targets/                # one directory per target
│   ├── p1-rate-limit/
│   ├── p2-cardinality/     (stub)
│   ├── p3-fail2ban/        (stub)
│   ├── p4-waf/             (stub)
│   └── p5-filtered-baseline/
├── scripts/                # reset, healthcheck, local-up, scan capture
└── experiments/            # arm configs and scan results
```

## Reset strategy

Per-run reset is **required** for clean experimental signal. The cohort runs with no IP rotation in production today, so defensive state (rate counters, fail2ban jails, WAF learning) persists across scans. Without resets, Arm A's impact pollutes Arm B's measurement.

Default: hourly cron on each target instance runs `scripts/reset.sh`. For precision runs, `scripts/reset-trigger.sh` can reset an individual target on demand.

See `docs/operations.md` for details.

## Open items

- DevOps team owns AWS infra (EC2 provisioning, DNS, IAM). Terraform is not in this repo.
- Honeypot is currently built from source via submodule. If the honeypot project publishes a pre-built image, compose files will be updated to pull instead of build.
- P2/P3/P4 gatekeeper implementations pending.
- Stretch goal: one real WAF target on Cloudflare Pro — pending pricing approval.
