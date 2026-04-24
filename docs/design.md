# Protected Cohort — Design (v2)

## Experimental question

Does slower single-source scanning (Arm B, Arm C) recover port/service discovery that aggressive pacing (Arm A) loses to target-side reactive defenses?

This cohort provides the "defended target" environment the arm-comparison experiment needs. Testing against the existing honeypot alone (cooperative, no defenses) produces near-identical output across arms, which doesn't answer the question.

## Experimental arms being compared

These are defined in the upstream arm experiment ticket; captured here for context:

- **Arm A** — baseline, production-like: naabu rate ~1000, nmap `-T4`, top-ports 1000
- **Arm B** — slow two-stage: naabu rate ~50, nmap `-T2/-T3`, top-ports 1000
- **Arm C** — slow nmap-only: `-T2 --max-rate 50 -Pn`, no `-sV` during discovery, top-ports 1000

The cohort's job is to produce targets where the arms' behaviors meaningfully diverge.

## Cohort architecture

Two cohorts, used together:

- **Control cohort** (exists today): cooperative honeypot, no defenses
- **Protected cohort** (this project): same honeypot, fronted by a distinct defensive layer per target

```
scanner → [defensive layer per target] → honeypot container (unchanged)
```

The honeypot is identical across both cohorts. Only the defensive layer varies. All defensive state (rate counters, bans, WAF learning) lives in the defensive layer so teardown is cheap.

## Behavior matrix — 5 MVP targets

| Target | Defense | Simulates | What Arm A loses | How Arm B/C recovers |
|---|---|---|---|---|
| **P1 — Packet-rate limited** | iptables `hashlimit` at ~20 probes/sec/source, drop excess | Basic firewall rate limiting (T2007 threshold) | Open ports missed mid-scan when SYN rate exceeds threshold | Sub-threshold pacing, full port list |
| **P2 — Cardinality-based blocker** | iptables `recent` on distinct host:port tuples — block source IP after >8 unique combos in 60s | Behavioral IDS / modern bot detection (matches `auroratk` production observation) | Scan blackholed after small number of distinct probes, regardless of pacing | Paced arms may reach more ports before tripping threshold |
| **P3 — Adaptive connection blocker** | fail2ban port-scan jail, bans source IP after N connections in T seconds | IDS-style reactive blocking on connection count | Later ports filtered; scan partially blackholed | Paced arms stay under hit-count threshold |
| **P4 — WAF-fronted HTTP** | ModSecurity/CRS or nginx rate-limit in front of honeypot HTTP ports | Application-layer WAF detecting scanner patterns | `service`/`product` fields empty, low conf; `-sV` probes dropped | Slower probe cadence returns clean banners |
| **P5 — Filtered baseline** | iptables DROP on a fixed subset of ports | Plain filtered ports, no reactive behavior | Nothing — all arms should agree | Control: if arms disagree, experiment is buggy |

### Dropped from MVP (moved to follow-up)

- **Kitchen-sink target** (P1 + P2 + P3 + P4 stacked). Attribution becomes ambiguous when combined defenses trigger — can't tell which defense caused a difference. Worth building after MVP produces clean per-target signal.

## Target count: 5

- P1 and P2 cover the two distinct reactive defense *philosophies* (volume vs. cardinality)
- P3 covers connection-count IDS behavior
- P4 covers HTTP application-layer defense
- P5 is the filtered-port control

Each MVP target tests exactly one defensive hypothesis.

## Reset strategy — per-run reset

Per Max's feedback, reset runs between **every measured scan round**, not just between arms. This removes accumulated state as a confounder — every scan round is an independent observation.

**Implementation:**

- Reset script per target: flush iptables counters, clear fail2ban jails, restart WAF container
- Runs as a cron **every hour** on each target instance by default
- Also triggerable explicitly between rounds via a Slack command or HTTP webhook for precision runs

See `operations.md` for the reset script details.

## Threat model and scope

**In scope:**

- Single-source scanning (one scanner IP per target), matching current production
- Source-IP-based defenses (rate limits, fail2ban, WAF) are the right threat model
- Reactive behavior that degrades scan quality on aggressive pacing

**Out of scope:**

- Distributed-source scanning / IP rotation evasion. Prod plans to ship IP rotation later; cohort will need re-validation or augmentation (JA3 fingerprinting, behavioral detection) at that point. Noted as future work.
- OS fingerprinting (`-O`) accuracy under defenses — arm ticket is about port/service discovery
- Host discovery reliability — Arm C is `-Pn`; Arm A/B use naabu with its own discovery
- Tarpits / scan-time-efficiency comparisons — experiment measures artifact quality, not wall-clock
- Full host blackhole — covered implicitly by P2/P3 at the extreme

## Integration

Each target is deployed as a **gatekeeper + honeypot** pair on a dedicated host (EC2 in production, `localhost` for local dev).

- `targets/p1-rate-limit/docker-compose.yml` — iptables hashlimit
- `targets/p2-cardinality/docker-compose.yml` — iptables `recent`
- `targets/p3-fail2ban/docker-compose.yml` — fail2ban
- `targets/p4-waf/docker-compose.yml` — nginx + ModSecurity reverse proxy (HTTP/HTTPS only)
- `targets/p5-filtered-baseline/docker-compose.yml` — no gatekeeper; honeypot with reduced port exposure

Same-host deployment: gatekeeper and honeypot co-located. The gatekeeper binds public ports; the honeypot is reachable only from within the instance's Docker network (except for P5, which exposes ports directly).

**Honeypot image:** built from source via git submodule, same pattern as edge-starter. If the honeypot project publishes a pre-built image later, compose files will switch to pulling.

**Reset:** `docker compose down && up -d` per target, via hourly cron on each instance. Fully clears gatekeeper state.

## Infra plan

**Primary: AWS EC2, always-on, one instance per target.**

- Each target gets its own public IP → independent defensive domain, clean per-target state
- Always-on because these targets will replace `vuln1.fast-scan-demo-target.click` as shared Platform test infra

**Terraform / provisioning is owned by the DevOps team** and lives in their infra repo, not here.

## Coordination

- **DevOps (Sebin, Tavis)** — AWS account access, IAM roles, instance provisioning, DNS for `protected-cohort.xxx` subdomain
- **Max** — MVP scope approved; pending approval on Cloudflare Pro follow-up
- **Platform team** — sync on `vuln1.fast-scan-demo-target.click` replacement plan once MVP is running

## Follow-up items (not MVP)

- Combined-defenses "kitchen sink" target, once MVP produces clean per-target signal
- Cloudflare Pro real-WAF target, pending pricing approval
- Documented handoff plan for retiring `vuln1.fast-scan-demo-target.click`
- Re-validation when production ships IP rotation
