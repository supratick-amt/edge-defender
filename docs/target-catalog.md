# Target Catalog

Operator-facing reference for each target in the cohort. Use this to decide which target to point a scan at, and to interpret what behavior to expect.

---

## P1 — Rate-Limited

**Status:** Implemented
**Directory:** `targets/p1-rate-limit/`
**Simulates:** Basic firewall with packet-rate limiting on the source IP.

**Defensive behavior:**
- iptables `hashlimit` module
- Limit: ~20 new TCP connections per second, per source IP
- Burst: small allowance before limiting kicks in
- Over-limit probes: silently dropped (packet never reaches the honeypot)

**Expected arm behavior:**
- **Arm A** (naabu 1000 + nmap T4, ~100s of probes/sec): drops heavily once the rate limit engages; open ports missed in bursts
- **Arm B** (naabu 50 + nmap T2/T3): may hover near the threshold; partial loss possible
- **Arm C** (nmap T2 `--max-rate 50`): stays well under the threshold; full port list

**Reset effect:** `docker compose down && up -d` destroys the gatekeeper container, which re-installs a fresh iptables ruleset with zero counters.

**Known caveats:**
- Linux kernel's inherent RST rate limiting also kicks in under high load; this can confound pure-rate interpretation at very high probe rates
- The `hashlimit` module keys on source IP only, not source:port, so all connections from one scanner are aggregated

---

## P2 — Cardinality-Based Blocker

**Status:** Stub (gatekeeper not implemented)
**Directory:** `targets/p2-cardinality/`
**Simulates:** Behavioral IDS / modern bot detection that keys on distinct host:port cardinality rather than raw packet rate.

**Defensive behavior (planned):**
- iptables `recent` module tracking distinct `host:port` tuples per source
- Threshold: ~8 distinct host:port combinations within a 60-second window
- Over-threshold behavior: source IP blackholed for a cooldown period (~5 minutes)

**Expected arm behavior:**
- **All arms** will trip this — a port scan is high-cardinality by definition
- **Slower arms may reach more ports before tripping** the threshold
- No arm fully escapes; experiment measures *partial recovery* rather than full recovery

**Motivation:** this matches the blocking behavior observed against the `auroratk` domain in production. Raw-rate defenses (P1) can be evaded by slowing down; cardinality-based defenses cannot.

**Implementation TODO:** see `targets/p2-cardinality/README.md`.

---

## P3 — Adaptive Connection Blocker

**Status:** Stub (gatekeeper not implemented)
**Directory:** `targets/p3-fail2ban/`
**Simulates:** IDS / intrusion prevention with fail2ban-style adaptive blocking based on connection count.

**Defensive behavior (planned):**
- fail2ban watching iptables logs for new TCP connections from a single source
- Threshold: N connections (N~20) in T seconds (T~10)
- Action: ban the source IP via iptables DROP for a recovery window (~10 minutes)

**Expected arm behavior:**
- **Arm A:** trips the ban early in the scan; later ports appear filtered
- **Arm B/C:** slower pacing may stay under the ban threshold entirely

**Reset effect:** `docker compose down && up -d` destroys the fail2ban container, clearing all active jails.

**Implementation TODO:** see `targets/p3-fail2ban/README.md`.

---

## P4 — WAF-Fronted HTTP

**Status:** Stub (gatekeeper not implemented)
**Directory:** `targets/p4-waf/`
**Simulates:** HTTP application-layer WAF (e.g., ModSecurity + OWASP CRS, or Cloudflare-style rate limiting).

**Defensive behavior (planned):**
- nginx reverse proxy in front of honeypot's HTTP/HTTPS ports
- ModSecurity with OWASP CRS ruleset
- nginx `limit_req` zone targeting scanner-like request patterns (nmap user-agents, rapid sequential probes)

**Scope:**
- P4 is HTTP-only — TCP ports (22, 25, 445, etc.) are not exposed on P4 to keep the attribution clean
- If you need HTTP-and-TCP on the same target, that's the kitchen-sink follow-up target

**Expected arm behavior:**
- **Arm A (nmap `-sV`):** version-detection probes are HTTP-heavy and rapid; WAF drops them, `service`/`product` fields come back empty or low-confidence
- **Arm B:** slower `-sV` cadence; some probes survive; partial service identification
- **Arm C (no `-sV` during discovery):** minimal HTTP interaction during discovery; later service-detection phase (if any) behaves like Arm B

**Implementation TODO:** see `targets/p4-waf/README.md`.

---

## P5 — Filtered Baseline

**Status:** Implemented
**Directory:** `targets/p5-filtered-baseline/`
**Simulates:** A plain firewalled host with some ports filtered (DROP) and some open. No reactive behavior.

**Defensive behavior:**
- iptables DROP on a fixed subset of honeypot ports
- Remaining ports are exposed normally

**Purpose:**
- **Control / sanity check.** All three arms should produce identical results on P5. If they disagree, something is wrong with the experiment setup — probably scan-host misconfiguration or test harness bugs.

**Expected arm behavior:**
- All arms: filtered ports reported as `filtered`, open ports reported as `open` with correct service detection
- Arms should match modulo noise

**Reset effect:** same as P1 — reset destroys and recreates the gatekeeper, reinstating fresh iptables rules.
