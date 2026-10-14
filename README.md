# Firewall Linux (Netfilter/Iptables) - Revista Lume

Trabalho Parcial de Segurança da Informação - IF Goiano, Campus Ceres.
Cenário simulado em Docker Compose: uma revista de moda (fictícia, "Revista Lume") com rede interna da redação (LAN), zona desmilitarizada (DMZ) e um firewall Linux entre as duas.

O relatório técnico completo está em [`docs/relatorio.md`](docs/relatorio.md).

## Arquitetura

| Container  | Rede           | IP                              | Função                                  |
|------------|----------------|---------------------------------|-----------------------------------------|
| `cliente`  | `lan`          | 172.16.0.10                     | Estação da redação (curl, nmap, ping)   |
| `firewall` | `lan` e `dmz`  | 172.16.0.254 / 172.20.0.254     | Gateway/roteador com iptables           |
| `dmz-web`  | `dmz`          | 172.20.0.10                     | Portal (Nginx, porta 80)                |
| `dmz-db`   | `dmz`          | 172.20.0.20                     | Banco de assinantes (Postgres, 5432)    |

Redes: `lan` = 172.16.0.0/24 e `dmz` = 172.20.0.0/24 (drivers `bridge` isoladas).

## Como executar

Pré-requisitos: Docker e Docker Compose (Docker Desktop no Windows).

```
git clone https://github.com/Luanna-f/firewall-revista-lume.git
cd firewall-revista-lume
docker compose up -d --build
docker ps
```

Devem aparecer 4 containers: `firewall`, `cliente`, `dmz-web` e `dmz-db`.
As regras do firewall são carregadas automaticamente pelo `firewall/entrypoint.sh` na subida do container.

Para ver as regras carregadas:

```
docker logs firewall
```

## Testes rápidos

```
# Positivo: a LAN acessa o portal (deve mostrar o HTML da página LUME)
docker exec cliente curl -s http://172.20.0.10

# Negativo: a LAN não alcança o banco (5432 deve aparecer "filtered")
docker exec cliente nmap -Pn -p 80,5432 172.20.0.10 172.20.0.20

# Negativo: a DMZ não inicia conexão para a LAN (100% packet loss)
docker exec dmz-web ping -c 2 -W 2 172.16.0.10

# Evidência: contadores de pacotes por regra
docker exec firewall iptables -L FORWARD -n -v --line-numbers
```

O passo a passo completo e os resultados esperados estão na seção 4 do relatório.

## Encerrar o ambiente

```
docker compose down
```

## Observações

- No Windows, os scripts `.sh` precisam de quebra de linha do Linux (LF). O arquivo `.gitattributes` garante isso e o `Dockerfile` do firewall ainda converte por segurança.
- Se o Docker acusar `Pool overlaps`, outra rede do Docker já usa a faixa 172.16.0.0/24 ou 172.20.0.0/24: remova-a (`docker network ls` e `docker network rm`) ou altere as faixas no `docker-compose.yml`.
