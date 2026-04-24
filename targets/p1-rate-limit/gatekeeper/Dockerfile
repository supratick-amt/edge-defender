# P1 Rate-limit gatekeeper
# ========================
# Minimal Alpine image that installs iptables and applies rate-limiting rules
# at container start. Runs in host network mode so the rules affect the host's
# inbound traffic, gating what reaches the honeypot container.

FROM alpine:3.19

RUN apk add --no-cache \
      iptables \
      ip6tables \
      bash \
      tini

COPY iptables-rules.sh /usr/local/bin/iptables-rules.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/iptables-rules.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
