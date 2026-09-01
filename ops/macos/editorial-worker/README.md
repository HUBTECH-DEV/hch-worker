# Kit macOS do worker editorial HCH 3.1.0

O kit macOS usa o mesmo runtime Node assinado do Linux e fornece integração
nativa com `launchd`. Ele cobre bootstrap, atestação, heartbeat, capacidade,
execução paralela, dashboard loopback, atualização/rollback do manifesto e
pause/start/stop. O
instalador deixa o worker em **drain**; a capacidade só é aberta por
`hch-editorial-workerctl start` depois de `validate`.

Requisitos: macOS 13 ou superior, Node.js 22.13+, engine local apenas em
loopback e chave raiz instalada por canal independente. Copie e ajuste
`config.example.json`, preservando segredos fora do arquivo. Em seguida:

```sh
HCH_RUNTIME_ROOT=/usr/local/libexec/hch-editorial-runtime \
HCH_WORKER_CONFIG="$HOME/Library/Application Support/HCH/editorial-worker/config.json" \
HCH_NODE_BIN=/opt/homebrew/bin/node \
./install-launch-agents.sh

./hch-editorial-workerctl validate
./hch-editorial-workerctl set-parallelism 1
./hch-editorial-workerctl start
```

O agente de ciclo é contínuo, renova o bootstrap, mantém o heartbeat e
supervisiona o dashboard no mesmo processo. O instalador remove os agentes
legados de bootstrap isolado, heartbeat, listener, executor e dashboard para
evitar disputa pelo lock, presença duplicada e conflito na porta `4319`; o
agente local do Ollama é preservado. Paralelismo zero e `pause` preservam
trabalhos ativos; `stop` cancela e relata a falha ao orquestrador. O runtime é
fail-closed e não publica nem aprova conteúdo.
O rollout canário obrigatório é VPS, macOS/Linux e somente depois Windows.
