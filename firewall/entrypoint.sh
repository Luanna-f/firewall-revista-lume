#!/bin/bash
# ====================================================================
# FIREWALL - REVISTA LUME (LAN + DMZ)
# Estrutura baseada no script corporativo da apostila (5 etapas)
# ====================================================================

# 1. Roteamento: ip_forward ja e ligado pelo docker-compose (sysctls)
echo "[firewall] ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"

# Descobre os nomes das interfaces pelo IP (no Docker o nome pode variar)
for i in $(seq 1 10); do
  LAN_IF=$(ip -o -4 addr show | awk '/172\.16\.0\.254/ {print $2}')
  DMZ_IF=$(ip -o -4 addr show | awk '/172\.20\.0\.254/ {print $2}')
  [ -n "$LAN_IF" ] && [ -n "$DMZ_IF" ] && break
  sleep 1
done
echo "[firewall] LAN=$LAN_IF DMZ=$DMZ_IF"

# 2. Limpar regras preexistentes (Flush) e zerar contadores
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
iptables -Z

# 3. Politica padrao restritiva (Zero Trust / Default DROP)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 4. Loopback e conexoes ativas (a regra de ouro do stateful)
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# 5. Regras do case
# 5.1 Regra de ouro da DMZ: a DMZ nunca inicia conexao para a LAN
iptables -A FORWARD -s 172.20.0.0/24 -d 172.16.0.0/24 -m state --state NEW -j DROP

# 5.2 LAN -> banco de dados (5432): registra a tentativa e bloqueia
iptables -A FORWARD -s 172.16.0.0/24 -d 172.20.0.20 -p tcp --dport 5432 -m limit --limit 2/min -j LOG --log-prefix "[ALERTA DB 5432]: "
iptables -A FORWARD -s 172.16.0.0/24 -d 172.20.0.20 -p tcp --dport 5432 -j DROP

# 5.3 LAN -> portal web (80/443): liberado
iptables -A FORWARD -s 172.16.0.0/24 -d 172.20.0.10 -p tcp -m multiport --dports 80,443 -j ACCEPT

echo "[firewall] regras carregadas:"
iptables -L -n -v --line-numbers

# Mantem o container em execucao
exec tail -f /dev/null