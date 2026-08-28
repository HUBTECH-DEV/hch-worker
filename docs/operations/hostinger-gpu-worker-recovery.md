# Recuperação do worker HCH na Hostinger GPU

Este runbook cobre a instância GPU efêmera usada pelo worker editorial. Ele não
substitui bootstrap, atestação, drain, canário ou rollback do runtime.

## Configuração operacional preservada

- acesso local por `ssh hostinger-gpu`, sem IP ou credencial no repositório;
- SSH público `32092` encaminhado para a porta interna `22`;
- painel HCH interno em `127.0.0.1:4320`;
- painel público `20001` encaminhado para a porta interna `4320`;
- túnel local `hostinger-worker-dashboard` em
  `127.0.0.1:4320 -> 127.0.0.1:4320`;
- Ollama privado em `127.0.0.1:11434`;
- `hch-editorial-worker.service` possui o supervisor e o painel;
- `ollama.service` fornece o motor local.

O painel padrão do repositório é `4319`, mas a implantação Hostinger usa o
drop-in `30-dashboard-port.conf` com `HCH_WORKER_DASHBOARD_PORT=4320`. Um
encaminhamento público para `4319` não alcança essa implantação.

## Falha simultânea de SSH e painel

Quando tanto o SSH encaminhado quanto o painel público recusam conexão, não
trate o incidente como falha isolada do Node.js. Confirme no hPanel:

1. se a instância GPU ainda existe e está em execução;
2. se há créditos suficientes para mantê-la;
3. se o IP público continua igual;
4. se o serviço SSH encaminha a porta pública esperada para a interna `22`;
5. se o serviço do painel encaminha a porta pública esperada para a interna
   `4320`.

Instâncias GPU não fazem parte do domínio VPS da API/MCP pública da Hostinger.
Não use `hostinger-vps-mcp` para concluir que a GPU foi destruída ou está
saudável.

## Preflight somente leitura

Depois de restaurar o encaminhamento SSH, faça primeiro o inventário somente
leitura e reexecute bootstrap/atestação. Em seguida, execute no Mac:

```bash
/bin/bash scripts/check-hostinger-gpu-worker.sh
```

O preflight não inicia, pausa ou reinicia serviços. Ele verifica GPU, units,
listeners exclusivamente em loopback, modelo e digest exatos do runtime
aplicado, estado drenado, prontidão ainda válida e evidências recentes do status
e do heartbeat. Ele também deriva o `HostName` do alias SSH e exige que o painel
público em `20001` responda com a mesma identidade/manifesto do painel interno.
Qualquer falha mantém a retomada bloqueada; isso inclui a falta esperada de
prontidão antes do novo bootstrap.

Se a porta pública for alterada intencionalmente, informe-a sem mudar o
repositório:

```bash
HCH_GPU_PUBLIC_DASHBOARD_PORT=20001 \
  /bin/bash scripts/check-hostinger-gpu-worker.sh
```

O túnel local é uma rota adicional e não substitui o gate público acima. Depois
do preflight, `curl --fail http://127.0.0.1:4320/api/status` pode ser usado para
provar separadamente o túnel `hostinger-worker-dashboard`.

## Ordem de retomada

1. Manter claims fechados e confirmar `activeAssignments=0` e
   `currentBatch=null`.
2. Inventariar identidade, trust root, runtime ativo, disco, GPU, cgroup,
   modelos Ollama e listeners.
3. Reexecutar bootstrap e validar uma nova atestação; não reutilizar uma janela
   de prontidão anterior à indisponibilidade.
4. Confirmar o painel em `4320` e pelo menos dois heartbeats saudáveis.
5. Implantar um runtime novo em diretório imutável, preservando o runtime
   anterior e trocando apenas o symlink sob drain.
6. Iniciar com capacidade `1` e exigir um canário real concluído em
   `pending-review` antes de aumentar o paralelismo.
7. Escolher modelo e concorrência pela quantidade de resultados editoriais
   válidos por minuto, não somente pela utilização da GPU.

## Bloqueios fail-closed

- modelo ou digest diferente do RuntimeProfile assinado;
- worker aceitando claims ou com assignments ativos;
- trust, bootstrap, attestation ou heartbeat inválido;
- painel público apontando para a porta interna errada;
- serviço Ollama acessível fora do loopback;
- benchmark concorrendo com o endpoint operacional do worker;
- ausência de runtime anterior verificável para rollback.
