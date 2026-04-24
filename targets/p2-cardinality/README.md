# P2 — Cardinality-Based Blocker *(STUB — not implemented)*

**Status:** scaffolded, gatekeeper not implemented yet.
**Pattern to follow:** see `targets/p1-rate-limit/` as the template.

## What it will do

Simulates behavioral IDS / modern bot detection that keys on **distinct host:port cardinality** rather than raw packet rate. This is the defense pattern Max observed against the `auroratk` domain in production — slowing down doesn't help, because any port scan is high-cardinality by definition.

## Planned defensive behavior

- iptables `recent` module tracking distinct destination ports per source IP
- Threshold: source IP touches **more than 8 distinct ports within a 60-second window** → block
- Block duration: ~5 minutes (source IP blackholed — all new SYNs DROP)
- After block expires, counters reset; source IP can try again

## Expected experiment behavior

Unlike P1, **all arms trip this defense** — a port scan of 1000 top-ports is inherently high-cardinality. The difference between arms becomes *how far they get before tripping*:

- Arm A (fast): trips quickly, sees maybe 8–15 ports before blackhole
- Arm B (slower): similar outcome, possibly a few more ports
- Arm C (slowest): similar, maybe reaches further

No arm fully escapes. The experimental signal is **partial recovery**, not full recovery.

## Implementation TODO

1. `gatekeeper/Dockerfile` — same Alpine + iptables base as P1
2. `gatekeeper/entrypoint.sh` — same pattern as P1, just calls a different rules script
3. `gatekeeper/iptables-rules.sh` — the interesting part:
   - Use `iptables -m recent` with a separate list per dest port
   - Or more cleanly: `iptables -m hashlimit` with `--hashlimit-mode srcip,dstport` and a very low rate — this approximates "Nth distinct combination" over a window
   - Cleanest: custom xtables module (`ipt_pknock`, `conntrack` tricks) — probably overkill for MVP
   - **Recommended first cut:** iptables `recent` module. Two steps:
     1. Mark each new dest port for the source: `iptables -A PREROUTING -m recent --name p2 --rdest --set`
     2. If source has hit more than N distinct dests in window: `-m recent --name p2 --rcheck --seconds 60 --hitcount 8 -j DROP`
   - The subtle part is making `recent` count *distinct* destinations, not total packets. The `--rdest` + a per-dest-port list approach is one way; another is layering hashlimit on top.
4. `docker-compose.yml` — copy from P1, rename container to `p2-gatekeeper` / `p2-honeypot`, change healthcheck chain name to `P2_CARDINALITY`
5. This README — replace with per-target operator doc (see P1's README as template)

## References

- `iptables` `recent` module: `man iptables-extensions` → RECENT
- Test approach: write a script that opens N distinct dest ports from one source in T seconds, confirm block kicks in at the right threshold
- Reset path: same as P1 — `docker compose down && up -d` clears all `recent` table state

## Open design questions

- Should the threshold be tuned per-target (8 ports / 60s) or made configurable via env var?
- Should blocked sources get REJECT (closed) or DROP (filtered)? DROP is more realistic for this threat model.
- Should block state persist across container restarts? MVP answer: no, reset wipes it. Real WAFs often persist, but that would defeat our per-round reset strategy.
