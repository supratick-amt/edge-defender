# P1 — Rate-Limited Target

Simulates a basic firewall with per-source-IP packet-rate limiting.

## What it does

- `gatekeeper` container applies iptables `hashlimit` rules at the host network level
- Threshold: ~20 new TCP connections per second per source IP (with small burst)
- Over-threshold SYNs are silently dropped (nmap sees "filtered")
- `honeypot` container runs unchanged behind the gatekeeper

## Port map (local)

| Host port | Container port | Service |
|---|---|---|
| 8122 | 22 | SSH |
| 8123 | 23 | Telnet |
| 8125 | 25 | SMTP |
| 8145 | 445 | SMB |
| 8180 | 80 | HTTP |
| 8280 | 8080 | HTTP alt |
| 8443 | 443 | HTTPS |
| 8444 | 8443 | HTTPS alt |
| 8465 | 465 | SMTP/TLS |
| 8541 | 541 | Fortinet FGFM |
| 8587 | 587 | SMTP submission |
| 9999 | 9999 | tcpwrapped |

On AWS these bind to the real ports (22, 23, 25, 80, ...) on the instance's public IP.

## Spin locally

From the repo root:

```bash
./scripts/local-up.sh p1-rate-limit
```

Or from this directory:

```bash
docker compose up --build -d
docker compose logs -f gatekeeper
```

Wait for the gatekeeper to report `ready. Rate limit active.` before scanning.

## Validate the rate limit is working

**Basic reachability (under the threshold):**

```bash
curl -v http://localhost:8180/
# Should get the Elasticsearch honeypot fingerprint
```

**Trigger the rate limit (above the threshold):**

```bash
# Hammer with ~100 connections as fast as possible
for i in {1..100}; do
  curl -s -o /dev/null -m 2 http://localhost:8180/ &
done
wait
```

You should see:

- The first handful of requests succeed
- Subsequent requests start timing out (the gatekeeper is dropping SYNs)
- In another terminal: `docker compose exec gatekeeper iptables -L P1_RATE_LIMIT -n -v`
  shows non-zero packet counts on the DROP rule

**Scan comparison:**

```bash
# Fast scan — expect port loss
nmap -T4 --max-rate 500 -p 22,23,25,80,443,445,465,541,587,8080,8443,9999 \
     -Pn 127.0.0.1 \
     --script-args unsafe=1 2>&1 | tee /tmp/p1-fast.out

# Slow scan — expect full port discovery
nmap -T2 --max-rate 10 -p 22,23,25,80,443,445,465,541,587,8080,8443,9999 \
     -Pn 127.0.0.1 2>&1 | tee /tmp/p1-slow.out

diff <(grep '/tcp' /tmp/p1-fast.out) <(grep '/tcp' /tmp/p1-slow.out)
```

The slow scan should find strictly more (or equal) open ports than the fast scan.

**Note on local testing:** localhost scanning is not fully representative — loopback has no real RTT or fragmentation. For meaningful arm-comparison signal, run on AWS or a separate LAN host.

## Reset

```bash
docker compose down && docker compose up --build -d
```

This destroys the gatekeeper, which means iptables rules are torn down by the container's SIGTERM handler, then reinstalled cleanly on the new container start. All rate-limit counters reset to zero.

## Tear down

```bash
docker compose down -v
```

`-v` also removes the `honeypot_logs` volume.

## Tuning

To adjust the rate limit, edit `gatekeeper/iptables-rules.sh`:

- `HASHLIMIT_RATE` — sustained rate (default `20/sec`)
- `HASHLIMIT_BURST` — initial burst allowance (default `5`)
- `HASHLIMIT_EXPIRE_MS` — how long an idle source-IP bucket persists (default `60000` = 60s)

After editing, `docker compose up --build -d` to rebuild the gatekeeper image.

## Known caveats

- **Host network mode:** the gatekeeper needs `network_mode: host` to apply iptables rules affecting the honeypot container's traffic. This means it shares the host's network namespace entirely.
- **Linux kernel RST rate limiting** operates independently of our rules and can confound interpretation at very high probe rates. This is real-world-realistic but worth noting when analyzing results.
- **Multiple scanners from the same source:** `hashlimit` keys on source IP only. If you're testing with multiple scanning processes from the same machine, they share the bucket.
