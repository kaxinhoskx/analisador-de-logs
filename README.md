# 🔐 Analisador de Logs SSH

Ferramenta em Python que lê logs de autenticação SSH e detecta **tentativas de força bruta**, destacando os IPs suspeitos e alertando quando um deles conseguiu entrar no sistema.

> ⚠️ **Uso ético:** este projeto é educacional. Use apenas com logs seus, de ambientes que você administra ou com os dados fictícios incluídos aqui.

## ✨ Funcionalidades

- Leitura de logs no formato syslog (`/var/log/auth.log`) com expressões regulares
- Detecção de força bruta por **janela de tempo** (ex.: 5+ falhas em 10 minutos)
- Ignora usuários legítimos e ataques lentos espalhados no tempo
- Alerta **CRÍTICO** quando um IP suspeito consegue fazer login depois das falhas
- Lista os usuários que o atacante tentou (`root`, `admin`, etc.)
- Relatório no terminal e opção de salvar em arquivo
- Parâmetros configuráveis pela linha de comando
- Gerador de log fictício para testar (IPs de documentação, que não existem na internet)

## 🛠️ Tecnologias

- Python 3.8+ (somente biblioteca padrão: `re`, `collections`, `datetime`, `argparse`)

## 🚀 Como usar

```bash
git clone https://github.com/kaxinhoskx/analisador-de-logs.git
cd analisador-de-logs

# 1. Gera um log fictício de exemplo
python gerar_log.py

# 2. Analisa o log
python analisador.py auth_exemplo.log --ano 2026
```

### Opções

| Opção | Descrição | Padrão |
|-------|-----------|--------|
| `arquivo` | Caminho do log a analisar | (obrigatório) |
| `--limite` | Falhas para considerar o IP suspeito | `5` |
| `--janela` | Janela de tempo em minutos | `10` |
| `--ano` | Ano dos logs (o syslog não guarda o ano) | ano atual |
| `--saida` | Salva o relatório neste arquivo | não salva |

Exemplo: `python analisador.py auth_exemplo.log --limite 10 --janela 5 --saida relatorio.txt`

## 📋 Exemplo de saída

```
========================================================
RELATÓRIO DE ANÁLISE DE LOGS SSH
========================================================
Eventos analisados : 127
Logins com falha   : 66
Regra aplicada     : 5+ falhas em 10 min
IPs suspeitos      : 2

[ALERTA] 203.0.113.50
  Falhas no total  : 40
  Pico na janela   : 40 em 10 min
  Período          : 11:00:02 a 11:02:36
  Usuários tentados: admin, oracle, root, test

[CRÍTICO] 203.0.113.77
  Falhas no total  : 15
  Pico na janela   : 15 em 10 min
  Período          : 14:00:08 a 14:01:34
  Usuários tentados: ana
  >>> Conseguiu entrar como 'ana' às 14:01:44. Investigue e troque a senha!
```

## 🧠 Como funciona

1. **Extração:** uma expressão regular captura data, resultado (`Failed`/`Accepted`), usuário e IP de cada linha.
2. **Janela deslizante:** para cada IP, uma fila (`deque`) guarda só as falhas dos últimos N minutos. O maior tamanho que a fila atinge é o "pico". Se passar do limite, o IP é suspeito.
3. **Correlação:** se um IP suspeito tem um login `Accepted` depois da primeira falha, o alerta vira **CRÍTICO**.

Contar só o total de falhas geraria falsos positivos (um usuário legítimo acumula erros ao longo do tempo). Por isso a regra considera o **tempo**.

## 📁 Estrutura

```
├── analisador.py      # programa principal
├── gerar_log.py       # gera o log fictício
├── auth_exemplo.log   # log de exemplo (dados fictícios)
└── README.md
```

## 📚 O que aprendi

- Expressões regulares com grupos nomeados
- Janela deslizante com `collections.deque`
- Leitura e análise de logs de segurança
- Interface de linha de comando com `argparse`
- Correlação de eventos para priorizar alertas

## 🔮 Próximos passos

- [ ] Testes automatizados com pytest e GitHub Actions
- [ ] Relatório em HTML e CSV
- [ ] Detectar muitas tentativas com usuários inexistentes
- [ ] Suporte a logs de servidores web (Apache/Nginx)

## 👤 Autor

**Kayo** · [LinkedIn](https://www.linkedin.com/in/kayo-alves-pereira-zamboni-26419b426/) · [GitHub](https://github.com/kaxinhoskx)
