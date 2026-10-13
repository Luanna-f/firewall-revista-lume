FROM ubuntu:24.04

# iptables (firewall), iproute2 (comando ip) e ping para testes
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
