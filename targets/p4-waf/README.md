# P4 — WAF-Fronted HTTP *(STUB — not implemented)*

**Status:** scaffolded, gatekeeper not implemented yet.

## What it will do

Simulates an HTTP application-layer WAF in front of a web server. Closest production analog: ModSecurity + OWASP CRS, or Cloudflare's WAF on a protected domain.

**P4 is HTTP-only.** The other honeypot protocols (SSH, SMB, SMTP, etc.) are **not exposed** on P4 to keep attribution clean — a scan against P4 is explicitly testing what happens when the target is a web-only defended host.

## Planned defensive behavior

Two layers:

1. **nginx reverse proxy** with `limit_req` on rapid request patterns and on nmap-style user agents.
2. **ModSecurity with OWASP CRS** ruleset: detects scanner signatures (headers, request cadence, specific probe paths like `/admin`, `/phpmyadmin`) and returns 403 or resets the connection.

Both layers only affect HTTP/HTTPS. The honeypot's HTTP CVE configs (Elasticsearch, JBoss, PHP-CGI, etc.) sit behind this proxy.

## Expected experiment behavior

- **Arm A with `-sV`:** heavy rapid HTTP probing for version detection. ModSec catches scanner patterns, starts dropping/403ing probes. Result: `service` and `product` fields come back empty or low-confidence. This is the **largest expected quality gap** across all targets.
- **Arm B:** slower `-sV` cadence. Some probes survive WAF filters. Partial service identification.
- **Arm C (no `-sV` during discovery):** discovery probes are much simpler (just SYNs) and largely unaffected by WAF. If a follow-up service-detection phase happens, it behaves like Arm B.

## Implementation TODO

1. `gatekeeper/nginx.conf` — upstream to honeypot container, `limit_req` zones, pass TLS through or terminate at nginx (easier).
2. `gatekeeper/modsec/main.conf` — enable ModSecurity, point at CRS rules.
3. `gatekeeper/modsec/custom-rules.conf` — rules specifically targeting nmap's `-sV` probe signatures. Examples:
   - User-Agent contains "Nmap Scripting Engine"
   - Rapid GET of both `/` and `/favicon.ico` + `/robots.txt` within <1s
   - HEAD requests with no Accept header
4. Base image: `owasp/modsecurity-crs:nginx` already wires nginx + ModSec + CRS. Start there.
5. `docker-compose.yml`:
   - Gatekeeper publishes 80, 443 on the host
   - Honeypot uses `expose:` (not `ports:`) for 80, 443 — reachable only from gatekeeper
   - The other honeypot ports (22, 25, 445, etc.) are **not exposed at all** on P4
6. Internal Docker network between gatekeeper and honeypot.

## Scope decisions to make

- **HTTPS:** terminate TLS at nginx (easier, exposes one cert under our control) or pass TLS through (harder, keeps honeypot's self-signed cert visible). Recommendation: terminate at nginx for MVP — cleaner WAF behavior.
- **Rate-limit threshold:** picks a balance between "trips Arm A consistently" and "doesn't trip Arm B/C." Start with nginx `limit_req zone=scanner rate=5r/s burst=10`. Tune after initial scans.
- **Which CRS paranoia level:** 1 (default) is reasonable for MVP. Higher levels block more but also false-positive on benign requests.

## Open questions for the Cloudflare follow-up

When the Cloudflare Pro stretch goal comes online, compare P4's simulated behavior to Cloudflare's real-WAF behavior side-by-side. Confirm the simulated WAF is "close enough" to real to be useful, or note the gaps.
