#!/bin/bash
# Passo 4: apenas inicia o gateway (sem regras ainda: politicas padrao ACCEPT).
# No Passo 5 este script passa a carregar as regras do firewall.

echo "[firewall] gateway iniciado"
echo "[firewall] ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"

# Mantem o container em execucao
exec tail -f /dev/null
