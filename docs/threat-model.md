# Threat Model

## Assumptions matching current production

### Single-source, no IP rotation

The protected cohort is designed around the production scanner's current behavior: **one scanner IP hits a given target IP per scan, and the same scanner IP is reused across scan rounds.**

This matches the fleet's current state: scanners are distributed globally, but the fleet routes each target through one scanner, not across many.

### What this implies for defenses

Source-IP-based reactive defenses are the right threat model:

- Rate limits keyed on source IP (iptables `hashlimit`)
- Cardinality counters keyed on source IP (iptables `recent`)
- fail2ban jails keyed on source IP
- WAF rules keyed on source IP

All of these will observe the full aggression of a single arm from a single source — the same way a real defended target would see production traffic today.

### What this implies for experiments

**Blocks persist across scan rounds.** If Arm A trips a fail2ban jail, that ban is still active when Arm B runs 10 minutes later. Without reset, Arm B inherits Arm A's punishment and produces polluted results.

This is why the reset strategy is **per-run**, not just per-arm. Every measured scan round starts with clean defensive state. See `operations.md`.

## Out of scope

### Distributed-source scanning / IP rotation evasion

The production scanner will eventually rotate source IPs between scans of the same target. When that ships, source-IP-based defenses become partially or fully evadable, and this cohort's defensive behaviors will no longer match the threat model.

At that point the cohort will need one of:

- Re-validation with rotated sources to confirm how much the defenses still detect
- Augmentation with cross-source defensive signals (JA3/TLS fingerprinting, behavioral detection based on scan patterns, NAT-aware counters)
- Documentation that the cohort represents legacy-threat-model behavior only

This is tracked as a follow-up item, not a blocker for MVP.

### Adversarial scan stealth techniques

The cohort does not test:

- TCP/IP stack fingerprint spoofing
- Fragmented probes
- Idle scans (zombie hosts)
- Decoy source IPs (nmap `-D`)

These are techniques used by adversarial scanners to evade detection. The production scanner doesn't use them, so the cohort doesn't need to model defenses against them.

### Host discovery reliability

Arm C uses `-Pn` (treat all hosts as up). Arm A/B use naabu which has its own discovery. None of the arms stress ICMP-based host discovery, so the cohort doesn't model ICMP rate limiting or host-discovery evasion.

### OS fingerprinting accuracy

The arm experiment measures port/service discovery quality, not OS fingerprinting (`-O`) accuracy. Defenses that affect TCP/IP stack fingerprints are out of scope.
