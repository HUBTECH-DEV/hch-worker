# Recuperação do worker HCH na Hostinger GPU

Este runbook cobre a instância GPU efêmera usada pelo worker editorial. Ele não
substitui bootstrap, atestação, drain, canário ou rollback do runtime.

## Configuração operacional preservada

- acesso local por `ssh hostinger-gpu`, sem IP ou credencial no repositório;
- porta pública de SSH descoberta pelo alias local, sem valor fixo no runbook;
- painel HCH interno em `127.0.0.1:4320`;
- túnel local `hostinger-worker-dashboard` em
  `127.0.0.1:4320 -> 127.0.0.1:4320`;
- Ollama privado em `127.0.0.1:11434`;
- `hch-editorial-worker.service` possui o supervisor e o painel;
- `ollama.service` fornece o motor local.

O painel padrão do repositório é `4319`, mas esta implantação Hostinger usa o
drop-in `30-dashboard-port.conf` com `HCH_WORKER_DASHBOARD_PORT=4320`. Um
painel operacional não deve ser exposto publicamente porque a mesma aplicação
contém a superfície local de controle.

## Falha simultânea de SSH e túnel

Quando tanto o SSH quanto o painel pelo túnel recusam conexão, não
trate o incidente como falha isolada do Node.js. Confirme no hPanel:

1. se a instância GPU ainda existe e está em execução;
2. se há créditos suficientes para mantê-la;
3. se o IP público continua igual;
4. se o serviço SSH encaminha a porta pública atual para a interna `22`;
5. se o alias `hostinger-worker-dashboard` encaminha localmente
   `127.0.0.1:4320` para `127.0.0.1:4320` na instância.

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
aplicado, zero reinícios da unit, estado drenado, prontidão ainda válida e
evidências recentes do status e do heartbeat. Ele exige que o painel acessado
pelo túnel em `127.0.0.1:4320` responda com a mesma identidade/manifesto do
painel interno.
Qualquer falha mantém a retomada bloqueada; isso inclui a falta esperada de
prontidão antes do novo bootstrap.

Se a porta local do túnel for alterada intencionalmente, informe a URL literal
de loopback sem mudar o repositório:

```bash
HCH_GPU_TUNNEL_DASHBOARD_URL=http://127.0.0.1:54321 \
  /bin/bash scripts/check-hostinger-gpu-worker.sh
```

O túnel local é parte do gate. A URL aceita somente o endereço literal
`127.0.0.1`, HTTP e uma porta explícita; variáveis de proxy são ignoradas nessa
requisição. Não crie um serviço exposto da Hostinger para o painel do worker.

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
- túnel ausente, desviado por proxy ou com identidade diferente do painel interno;
- serviço Ollama acessível fora do loopback;
- benchmark concorrendo com o endpoint operacional do worker;
- ausência de runtime anterior verificável para rollback.
