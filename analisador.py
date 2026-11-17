"""Analisador de logs de SSH: detecta tentativas de força bruta.

Uso:
    python analisador.py auth_exemplo.log
    python analisador.py auth_exemplo.log --limite 5 --janela 10 --saida relatorio.txt

Use apenas com logs seus ou fictícios.
"""

import argparse
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Expressão regular que "encaixa" nas linhas que nos interessam.
# (?P<nome>...) dá um nome ao pedaço capturado.
PADRAO = re.compile(
    r"^(?P<data>\w{3}\s+\d+\s+[\d:]{8})"          # ex.: Nov 17 11:02:15
    r".*sshd\[\d+\]: "
    r"(?P<resultado>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<usuario>\S+) "         # usuário (pode ser inválido)
    r"from (?P<ip>[\d.]+)"                         # IP de origem
)


def ler_log(caminho, ano):
    """Lê o arquivo e devolve uma lista de eventos (dicionários)."""
    eventos = []
    with open(caminho, encoding="utf-8", errors="replace") as arquivo:
        for linha in arquivo:
            encontrou = PADRAO.search(linha)
            if not encontrou:
                continue  # ignora linhas que não são de login
            # O syslog não guarda o ano, então informamos nós mesmos
            momento = datetime.strptime(
                f"{ano} {encontrou['data']}", "%Y %b %d %H:%M:%S"
            )
            eventos.append({
                "momento": momento,
                "resultado": encontrou["resultado"],
                "usuario": encontrou["usuario"],
                "ip": encontrou["ip"],
            })
    return eventos


def detectar_forca_bruta(eventos, limite, janela_min):
    """Marca IPs com `limite` falhas ou mais dentro de `janela_min` minutos."""
    falhas = defaultdict(list)       # ip -> horários das falhas
    usuarios = defaultdict(set)      # ip -> usuários que ele tentou
    for e in eventos:
        if e["resultado"] == "Failed":
            falhas[e["ip"]].append(e["momento"])
            usuarios[e["ip"]].add(e["usuario"])

    janela = timedelta(minutes=janela_min)
    suspeitos = {}

    for ip, horarios in falhas.items():
        horarios.sort()
        na_janela = deque()   # falhas que ainda estão dentro da janela
        pico = 0
        for horario in horarios:
            na_janela.append(horario)
            # Descarta as falhas que ficaram velhas demais
            while horario - na_janela[0] > janela:
                na_janela.popleft()
            pico = max(pico, len(na_janela))

        if pico >= limite:
            suspeitos[ip] = {
                "total_falhas": len(horarios),
                "pico_na_janela": pico,
                "primeira": horarios[0],
                "ultima": horarios[-1],
                "usuarios": sorted(usuarios[ip]),
            }
    return suspeitos


def detectar_login_apos_falhas(eventos, suspeitos):
    """Um IP suspeito que depois conseguiu entrar é o caso mais grave."""
    comprometidos = {}
    for e in eventos:
        ip = e["ip"]
        if (e["resultado"] == "Accepted" and ip in suspeitos
                and e["momento"] >= suspeitos[ip]["primeira"]):
            comprometidos[ip] = e
    return comprometidos


def montar_relatorio(eventos, suspeitos, comprometidos, limite, janela_min):
    falhas = sum(1 for e in eventos if e["resultado"] == "Failed")
    linhas = [
        "=" * 56,
        "RELATÓRIO DE ANÁLISE DE LOGS SSH",
        "=" * 56,
        f"Eventos analisados : {len(eventos)}",
        f"Logins com falha   : {falhas}",
        f"Regra aplicada     : {limite}+ falhas em {janela_min} min",
        f"IPs suspeitos      : {len(suspeitos)}",
        "",
    ]

    if not suspeitos:
        linhas.append("Nenhum comportamento suspeito encontrado.")
        return "\n".join(linhas)

    # Mostra os mais agressivos primeiro
    ordenados = sorted(suspeitos.items(),
                       key=lambda par: par[1]["total_falhas"], reverse=True)
    for ip, info in ordenados:
        alerta = "CRÍTICO" if ip in comprometidos else "ALERTA"
        linhas += [
            f"[{alerta}] {ip}",
            f"  Falhas no total  : {info['total_falhas']}",
            f"  Pico na janela   : {info['pico_na_janela']} em {janela_min} min",
            f"  Período          : {info['primeira']:%H:%M:%S} a {info['ultima']:%H:%M:%S}",
            f"  Usuários tentados: {', '.join(info['usuarios'])}",
        ]
        if ip in comprometidos:
            login = comprometidos[ip]
            linhas.append(
                f"  >>> Conseguiu entrar como '{login['usuario']}' "
                f"às {login['momento']:%H:%M:%S}. Investigue e troque a senha!"
            )
        linhas.append("")
    return "\n".join(linhas)


def main():
    parser = argparse.ArgumentParser(description="Detecta força bruta em logs SSH.")
    parser.add_argument("arquivo", help="caminho do arquivo de log")
    parser.add_argument("--limite", type=int, default=5,
                        help="falhas para considerar suspeito (padrão: 5)")
    parser.add_argument("--janela", type=int, default=10,
                        help="janela de tempo em minutos (padrão: 10)")
    parser.add_argument("--ano", type=int, default=datetime.now().year,
                        help="ano dos logs (padrão: ano atual)")
    parser.add_argument("--saida", help="salvar o relatório neste arquivo")
    args = parser.parse_args()

    try:
        eventos = ler_log(args.arquivo, args.ano)
    except FileNotFoundError:
        raise SystemExit(f"Arquivo não encontrado: {args.arquivo}")

    suspeitos = detectar_forca_bruta(eventos, args.limite, args.janela)
    comprometidos = detectar_login_apos_falhas(eventos, suspeitos)
    relatorio = montar_relatorio(eventos, suspeitos, comprometidos,
                                 args.limite, args.janela)

    print(relatorio)
    if args.saida:
        with open(args.saida, "w", encoding="utf-8") as arquivo:
            arquivo.write(relatorio + "\n")
        print(f"Relatório salvo em {args.saida}")


if __name__ == "__main__":
    main()
