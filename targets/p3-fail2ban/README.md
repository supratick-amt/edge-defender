# P3 — Adaptive Connection Blocker *(STUB — not implemented)*

**Status:** scaffolded, gatekeeper not implemented yet.

## What it will do

Simulates IDS / IPS behavior that detects port-scan-like patterns and reactively bans the source IP. Closest production analog: fail2ban with a port-scan jail, or psad with reactive response.

## Planned defensive behavior

- fail2ban watching iptables logs for new TCP connections from a source IP
- Threshold: **N new connections (~20) in T seconds (~10)** from one source
- Action: add iptables DROP for that source IP, lasting ~10 minutes
- Multiple bans from the same source escalate the duration (optional, nice-to-have)

## Expected experiment behavior

- **Arm A:** trips the ban early (its probe rate is well above threshold). Later ports appear filtered because the whole host is blackholed mid-scan.
- **Arm B:** slower pacing *may* stay under the per-window threshold. Depends on exactly where we set N/T.
- **Arm C:** slowest — most likely to complete without triggering.

This is the cleanest experiment on "paced vs. unpaced" — the ban threshold is a hard gate.

## Implementation TODO

1. Gatekeeper image: Debian or Ubuntu (fail2ban isn't in Alpine's main repo). Install `fail2ban` + `iptables`.
2. `gatekeeper/jail.local` — define a port-scan jail:
   ```
   [portscan]
   enabled = true
   filter = portscan
   action = iptables-allports[name=portscan]
   logpath = /var/log/iptables-audit.log
   maxretry = 20
   findtime = 10
   bantime = 600
   ```
3. `gatekeeper/filter.conf` — the regex matching iptables log entries (fail2ban reads from the kernel's iptables LOG target).
4. An iptables LOG rule in the entrypoint to feed fail2ban: every new SYN from outside gets a log entry.
5. `gatekeeper/entrypoint.sh` — install the LOG rule, start fail2ban, idle.
6. `docker-compose.yml` — needs `NET_ADMIN`, `network_mode: host`, a mount for the logpath (tmpfs is fine).
7. Copy this README into the full per-target operator doc format (see P1).

## Critical detail: fail2ban in a container

fail2ban reads kernel log output. In a container with `network_mode: host`, the container sees the host's kernel log if we mount `/dev/log` or run `rsyslog` in the container. Cleanest approach: fail2ban reads a file that the iptables LOG target writes to via `ulogd` or `rsyslog`. Slightly fiddly — worth a spike to validate the log pipeline before committing to this approach.

Fallback: use the pure-iptables approach from P2 (no fail2ban, just `iptables -m recent` with a bigger window). Simpler; loses the "fail2ban" brand but produces equivalent behavior.

## Open design questions

- fail2ban vs. pure-iptables `recent` module — which feels more like a real IDS in scan results?
- Ban duration: 10 minutes is a common real-world value. For experiments we want it long enough to cover the full scan (so Arm B doesn't trip it mid-scan and recover).
- Should the gatekeeper log bans to stdout so we can correlate with scan timestamps?
