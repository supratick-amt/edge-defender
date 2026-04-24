# P5 Filtered baseline gatekeeper
# ===============================
# Minimal Alpine image that applies a fixed iptables DROP on a subset of
# honeypot ports. No reactive behavior — just a static firewall rule.

FROM alpine:3.19

RUN apk add --no-cache \
      iptables \
      bash \
      tini

COPY iptables-rules.sh /usr/local/bin/iptables-rules.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/iptables-rules.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
