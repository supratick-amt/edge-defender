# P5 — Filtered Baseline

A plain firewalled honeypot: some ports filtered (DROP), others open.

## Purpose

**Control for the experiment.** All three scan arms should produce identical results on P5. If they disagree, something is wrong with the scan harness — not with the arm pacing strategy. P5 validates the experiment setup before trusting results from P1–P4.

## What it does

- Fixed iptables DROP on a subset of honeypot ports
- No rate limiting, no adaptive behavior, no learning
- Same probes get same responses regardless of source IP, timing, or volume

## Port map (local)

| Host port | Container port | Service | Expected state |
|---|---|---|---|
| 8122 | 22 | SSH | **open** |
| 8123 | 23 | Telnet | **filtered** |
| 8125 | 25 | SMTP | **filtered** |
| 8145 | 445 | SMB | **filtered** |
| 8180 | 80 | HTTP | **open** |
| 8280 | 8080 | HTTP alt | **open** |
| 8443 | 443 | HTTPS | **open** |
| 8444 | 8443 | HTTPS alt | **open** |
| 8465 | 465 | SMTP/TLS | **filtered** |
| 8541 | 541 | Fortinet FGFM | **filtered** |
| 8587 | 587 | SMTP submission | **filtered** |
| 9999 | 9999 | tcpwrapped | **open** (tcpwrapped) |

On AWS, bind to real ports on the instance's public IP.

## Spin locally

```bash
./scripts/local-up.sh p5-filtered-baseline
```

## Validate

```bash
# Open ports should respond
curl -v http://localhost:8180/
nc -v localhost 8122

# Filtered ports should time out (not RST, not respond)
nc -v -w 3 localhost 8123     # should hang for 3s then fail
nc -v -w 3 localhost 8125     # should hang for 3s then fail
```

A full nmap scan:

```bash
nmap -p 22,23,25,80,443,445,465,541,587,8080,8443,9999 \
     -Pn 127.0.0.1
```

Expected: open ports on 22, 80, 443, 8080, 8443, 9999; filtered on 23, 25, 445, 465, 541, 587.

## Reset

```bash
docker compose down && docker compose up --build -d
```

## Tuning

To change which ports are filtered, edit `FILTERED_PORTS` in `gatekeeper/iptables-rules.sh` and rebuild.
