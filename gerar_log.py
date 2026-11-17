"""Gera um log de SSH FICTÍCIO para testar o analisador.

Todos os IPs usados pertencem às faixas reservadas para documentação
(203.0.113.0/24 e 198.51.100.0/24), então não existem na internet de verdade.
"""

import random
from datetime import datetime, timedelta

random.seed(42)  # mesma saída sempre, facilita testar

eventos = []


def registrar(momento, texto):
    # Formato parecido com o de /var/log/auth.log (syslog)
    data = momento.strftime("%b %d %H:%M:%S")
    pid = random.randint(1000, 9999)
    eventos.append((momento, f"{data} servidor sshd[{pid}]: {texto}"))


inicio = datetime(2026, 11, 17, 8, 0, 0)

# 1) Uso normal: usuários legítimos, com um erro de digitação de vez em quando
for _ in range(60):
    momento = inicio + timedelta(minutes=random.randint(0, 600))
    usuario = random.choice(["ana", "bruno", "carla"])
    ip = f"198.51.100.{random.randint(10, 14)}"
    if random.random() < 0.1:
        registrar(momento, f"Failed password for {usuario} from {ip} port 50022 ssh2")
    registrar(momento + timedelta(seconds=5),
              f"Accepted password for {usuario} from {ip} port 50022 ssh2")

# 2) Força bruta clássica: 40 tentativas em ~3 minutos
atacante = "203.0.113.50"
momento = inicio + timedelta(hours=3)
for _ in range(40):
    momento += timedelta(seconds=random.randint(2, 6))
    usuario = random.choice(["root", "admin", "test", "oracle"])
    registrar(momento, f"Failed password for invalid user {usuario} "
                       f"from {atacante} port 41000 ssh2")

# 3) Ataque lento: poucas tentativas espalhadas (NÃO deve ser marcado)
lento = "203.0.113.99"
for hora in (1, 4, 7):
    registrar(inicio + timedelta(hours=hora),
              f"Failed password for root from {lento} port 42000 ssh2")

# 4) O mais perigoso: muitas falhas e, no fim, um login que deu certo
invasor = "203.0.113.77"
momento = inicio + timedelta(hours=6)
for _ in range(15):
    momento += timedelta(seconds=random.randint(3, 8))
    registrar(momento, f"Failed password for ana from {invasor} port 43000 ssh2")
registrar(momento + timedelta(seconds=10),
          f"Accepted password for ana from {invasor} port 43000 ssh2")

# Ordena por horário e grava o arquivo
eventos.sort(key=lambda par: par[0])
with open("auth_exemplo.log", "w", encoding="utf-8") as arquivo:
    for _, linha in eventos:
        arquivo.write(linha + "\n")

print(f"Log de exemplo criado: auth_exemplo.log ({len(eventos)} linhas)")
