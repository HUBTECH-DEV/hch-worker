# HCH Worker Dashboard

Painel web **local** para observar um worker editorial HCH e solicitar somente
duas transições operacionais fixas: iniciar ou pausar em modo drain. O pacote
usa apenas APIs nativas do Node.js 22, não recebe credenciais e não é iniciado
automaticamente. Os snapshots e toda a telemetria continuam somente leitura.

Ele apresenta:

- estado, uptime e standby do worker;
- conexão com o orquestrador e autenticação do nó;
- validação TLS, certificado e cadeia Ed25519 raiz → release → manifesto;
- CPU acumulada e média;
- GPU acumulada e média, distinguindo `unavailable`, `unsupported` e `error`;
- memória média e pico por item;
- tempo médio de processamento;
- volume de entrada e saída;
- rede RX/TX;
- lotes e trabalhos totais, lote atual e trabalhos em execução;
- política adaptativa v2.2.0: tier atual, teto de tokens, unidade mínima,
  limiar/janela consultiva e motivo do downshift;
- por assignment, somente identificador, tempo decorrido, fase, horário do
  último progresso e liveness (`respondendo lentamente` ou `travado`);
- botões com confirmação para `start` e `stop`, quando o launcher confiável
  fornece os caminhos locais fixos do kit.
- descoberta periódica da última release estável e botão `Atualizar` somente
  quando a versão instalada estiver atrás e o executor administrativo fixo
  estiver habilitado.

## Componentes

| Componente | Responsabilidade |
| --- | --- |
| `collector.mjs` | API/CLI usada pelo worker para atualizar snapshots validados |
| `lib/contracts.mjs` | Contratos, validação, rejeição de segredos e agregação |
| `lib/hch-worker-adapter.mjs` | adaptação validada dos snapshots nativos dos kits HCH |
| `lib/adaptive-work.mjs` | redução da política/progresso v2.2.0 para telemetria pública sem conteúdo |
| `lib/operator-control.mjs` | validação estrita e redução pública de `worker-control.json` |
| `lib/control.mjs` | executor estreito de `Hch-Worker.ps1 start/stop`, sem shell |
| `lib/storage.mjs` | allowlists separadas de leitura/escrita, lock e troca atômica |
| `server.mjs` | servidor HTTP limitado a loopback, telemetria e controles locais protegidos |
| `public/` | interface acessível, responsiva e sem bibliotecas externas |
| `schemas/` | JSON Schemas de estado, métricas, orquestração e trabalho adaptativo |

O servidor e o coletor não compartilham memória. O painel aceita tanto os
snapshots próprios `state.json` + `metrics.json` quanto, diretamente, os
arquivos `status.json` + `metrics.json` emitidos pelos kits HCH. Quando existe,
`worker-control.json` também é lido para determinar a intenção operacional do
worker. Para o worker Windows, aponte o diretório de dados ao `StateRoot`; não é
necessário manter um segundo coletor ou duplicar telemetria.

O adaptador é o mesmo em Windows, Linux e macOS. A política vigente chega por
`orchestration.json.workSizing`. Kits podem publicar uma lista estrita
`status.json.activeWork`; o Windows também pode publicar o registro único
`status.json.progress`. A API do dashboard reduz ambos ao mesmo contrato público
e nunca devolve `contentBytes`, sequência, tentativa, hash do plano, lease,
prompt, resposta ou qualquer conteúdo editorial.

## Requisitos e configuração

- Node.js `>= 22.13.0`;
- nenhuma instalação de pacote é necessária;
- host padrão: `127.0.0.1`;
- porta padrão: `4319`;
- diretório padrão: `ops/worker-dashboard/data`.

Variáveis opcionais:

```text
HCH_WORKER_DASHBOARD_HOST=127.0.0.1
HCH_WORKER_DASHBOARD_PORT=4319
HCH_WORKER_DASHBOARD_DATA_DIR=/caminho/privado/worker-dashboard
HCH_WORKER_RELEASE_REPOSITORY=HUBTECH-DEV/hch-worker
HCH_WORKER_RELEASE_CHECK_INTERVAL_MS=900000
HCH_WORKER_UPDATE_SCRIPT=/caminho-confiavel/hch-worker-update.mjs
HCH_WORKER_UPDATE_SCRIPT_ROOT=/caminho-confiavel
```

O host aceita somente `127.0.0.1`, `::1` ou `localhost`. Isso protege o painel
local e não impõe qualquer bloqueio de IP à API central do orquestrador. Workers
continuam podendo operar em redes e endereços variáveis.

O GitHub é usado somente para descobrir a release. A instalação é entregue a
um executor administrativo local fixo; o navegador nunca fornece versão, URL ou
comando. O contrato completo de drain, verificação, instalação e rollback está
em [`docs/worker-release-updates.md`](../../docs/worker-release-updates.md).

## Preparar os snapshots

Esta etapa só é necessária para integrações que não usam um kit HCH. O kit
Windows já grava atomicamente os dois snapshots nativos em seu `StateRoot`.

```bash
node ops/worker-dashboard/collector.mjs init \
  --data-dir /var/lib/hch-worker/dashboard
```

No Windows PowerShell:

```powershell
node .\ops\worker-dashboard\collector.mjs init `
  --data-dir C:\ProgramData\HCH\worker-dashboard
```

O `init` é idempotente e nunca substitui um arquivo existente inválido. Essa
decisão evita apagar evidências de corrupção ou edição indevida.

## Atualizar o estado

O estado é um patch estrito. Campos desconhecidos são rejeitados. O uso de
`--stdin` evita colocar dados operacionais na linha de comando:

```bash
printf '%s' '{
  "worker": {
    "id": "mac-worker-02",
    "displayName": "Mac editorial 02",
    "state": "ready",
    "version": "2.0.0",
    "platform": "darwin-arm64",
    "startedAt": "2026-08-11T21:00:00.000Z"
  },
  "connection": {
    "status": "connected",
    "lastSuccessAt": "2026-08-11T21:05:00.000Z",
    "lastFailureAt": null,
    "errorCode": null
  },
  "authentication": {
    "status": "authenticated",
    "keyId": "SHA256:worker-public-key-fingerprint",
    "lastVerifiedAt": "2026-08-11T21:05:00.000Z",
    "errorCode": null
  },
  "transport": {
    "tlsStatus": "valid",
    "certificateStatus": "valid",
    "certificateExpiresAt": "2026-11-11T00:00:00.000Z",
    "certificateFingerprint": "SHA256:certificate-fingerprint",
    "errorCode": null
  },
  "trust": {
    "status": "valid",
    "rootKeyId": "SHA256:offline-root",
    "releaseKeyId": "SHA256:release-key",
    "manifestSequence": 42,
    "manifestHash": "sha256:manifest",
    "policyHash": "sha256:canonical-policy",
    "lastVerifiedAt": "2026-08-11T21:05:00.000Z",
    "errorCode": null
  }
}' | node ops/worker-dashboard/collector.mjs state \
  --data-dir /var/lib/hch-worker/dashboard --stdin
```

Estados parciais também são aceitos, por exemplo:

```json
{
  "worker": { "state": "processing" },
  "connection": {
    "status": "connected",
    "lastSuccessAt": "2026-08-11T21:06:00.000Z"
  }
}
```

## Registrar telemetria

O CLI completa `schemaVersion`, `eventId` e `occurredAt` quando omitidos. Para
retries idempotentes, o worker deve fornecer um `eventId` estável. Os últimos
512 IDs são mantidos no agregado para deduplicação.

### Amostra de CPU, GPU e rede

```json
{
  "eventId": "sample-mac-02-000001",
  "type": "resource.sample",
  "data": {
    "cpuPercent": 38.5,
    "cpuSecondsDelta": 1.72,
    "gpu": {
      "status": "available",
      "utilizationPercent": 61.2,
      "activeSecondsDelta": 1.4,
      "errorCode": null
    },
    "networkRxBytesDelta": 18420,
    "networkTxBytesDelta": 7310
  }
}
```

Quando não há GPU:

```json
{
  "status": "unsupported",
  "utilizationPercent": null,
  "activeSecondsDelta": 0,
  "errorCode": null
}
```

Use `unavailable` quando há suporte potencial, mas o dispositivo/coletor não
está disponível; `unsupported` quando a plataforma não oferece a métrica; e
`error` com um `errorCode` estável quando a coleta falhou. Mensagens livres não
devem ser enviadas.

### Ciclo de lote e trabalho

```json
{ "type": "batch.started", "data": { "batchId": "batch-42", "totalJobs": 2 } }
```

```json
{
  "type": "job.started",
  "data": { "jobId": "job-101", "batchId": "batch-42", "inputBytes": 48120 }
}
```

```json
{
  "type": "job.completed",
  "data": {
    "jobId": "job-101",
    "batchId": "batch-42",
    "outcome": "succeeded",
    "durationMilliseconds": 28540,
    "memoryAverageBytes": 734003200,
    "memoryPeakBytes": 912261120,
    "outputBytes": 16480
  }
}
```

```json
{ "type": "batch.completed", "data": { "batchId": "batch-42" } }
```

```json
{ "type": "standby.changed", "data": { "active": true } }
```

Envie qualquer evento pelo stdin:

```bash
node ops/worker-dashboard/collector.mjs event \
  --data-dir /var/lib/hch-worker/dashboard --stdin < event.json
```

## API JavaScript do coletor

Workers Node podem evitar o subprocesso:

```js
import {
  initializeCollector,
  recordMetricsEvent,
  updateWorkerState,
} from "./ops/worker-dashboard/collector.mjs";

await initializeCollector({ dataDirectory });
await updateWorkerState(
  { worker: { state: "processing" } },
  { dataDirectory },
);
await recordMetricsEvent(
  {
    eventId: assignmentEventId,
    type: "job.started",
    data: { jobId, batchId, inputBytes },
  },
  { dataDirectory },
);
```

Cada atualização obtém um lock exclusivo, lê e valida o snapshot anterior,
grava um arquivo temporário com permissão `0600`, sincroniza e o substitui por
rename atômico. Em falha, o snapshot anterior permanece disponível.

## Semântica da agregação

| Métrica exibida | Fonte e cálculo |
| --- | --- |
| CPU total | soma de `cpuSecondsDelta` |
| CPU média | média aritmética de `cpuPercent` |
| GPU total | soma de `activeSecondsDelta` apenas quando `available` |
| GPU média | média de `utilizationPercent` apenas quando `available` |
| memória média/item | média de `memoryAverageBytes` dos trabalhos concluídos |
| pico por item | maior `memoryPeakBytes` observado |
| tempo médio | média de `durationMilliseconds` |
| volume | `inputBytes` de inícios + `outputBytes` de conclusões |
| rede | somas de `networkRxBytesDelta` e `networkTxBytesDelta` |
| lotes/trabalhos | contadores dos eventos de início e conclusão |
| executando | IDs de `job.started` ainda não concluídos |
| standby | janela iniciada/finalizada por `standby.changed` ou novo trabalho |

### Trabalho adaptativo v2.2.0

A janela de processamento é **consultiva**: ultrapassá-la pode reduzir o tier
dos próximos assignments, mas não prova travamento e não interrompe o trabalho
atual. Quando `minimumUnit=true`, a janela total é explicitamente ignorada. O
dashboard usa as tolerâncias assinadas para separar dois estados:

- **Respondendo lentamente**: há progresso válido, porém o trabalho entrou na
  faixa próxima da janela ou o último progresso consumiu ao menos metade da
  tolerância aplicável;
- **Travado**: o primeiro progresso, a resposta ou a finalização não avançou
  dentro da tolerância aplicável, ou o orquestrador já classificou o assignment
  como `stalled`.

O estado `travado` é uma observação de liveness. O dashboard não mata o processo,
não encerra lease e não altera o fluxo de revisão/publicação.

Os schemas normativos estão em:

- `schemas/worker-state.schema.json`;
- `schemas/metrics-event.schema.json`;
- `schemas/metrics-snapshot.schema.json`;
- `schemas/orchestration-snapshot.schema.json`;
- `schemas/adaptive-work-status.schema.json`.

## Iniciar manualmente o painel

Somente depois que o worker estiver integrado:

```bash
node ops/worker-dashboard/server.mjs \
  --host 127.0.0.1 \
  --port 4319 \
  --data-dir /var/lib/hch-worker/dashboard
```

Acesse `http://127.0.0.1:4319`. Este pacote não instala nem inicia serviço do
sistema. Iniciado dessa forma, sem os três caminhos confiáveis de controle, o
painel funciona normalmente para observação e exibe os botões desabilitados.

No Windows, use o `Start-WorkerDashboard.ps1` instalado com o kit. O launcher
aceita somente o layout versionado
`%ProgramFiles%\HCH\EditorialWorker\versions\<semver>\ops\windows\editorial-worker`,
a configuração canônica
`%ProgramData%\HCH\EditorialWorker\config\WorkerConfig.psd1` e o Windows
PowerShell de `%SystemRoot%\System32`. CLI, configuração e PowerShell possuem
allowlists de raiz independentes, portanto a configuração não precisa ficar no
diretório do kit. Esses caminhos pertencem à configuração de startup e nunca
são aceitos no request do navegador.

No macOS/Linux, o mesmo painel pode habilitar os controles por um único script
Node.js local, fixado no startup:

```bash
node ops/worker-dashboard/server.mjs \
  --host 127.0.0.1 --port 4319 --data-dir <estado> \
  --control-driver fixed-node-script \
  --control-script <raiz>/hch-worker-control.mjs \
  --control-script-root <raiz> \
  --control-timeout-ms 75000
```

O script deve ser arquivo regular canônico, filho direto da raiz informada e
ter exatamente esse nome. O dashboard o executa pelo mesmo Node.js canônico que
serve o painel, com ambiente mínimo, `shell: false` e apenas `start` ou `stop`.
O timeout deve cobrir integralmente a validação local do runtime e do modelo;
o valor operacional recomendado é 75 segundos.

### Endpoints

`GET /api/status` devolve apenas campos permitidos pelos contratos. A resposta
inclui também o estado não sensível da operação de controle, sem token CSRF, e
`operatorControl`. Este último expõe somente status de validação,
`acceptingClaims`, `drainRequested`, paralelismos e horário — nunca `updatedBy`,
paths ou conteúdo livre. `worker-control.json` válido é a fonte autoritativa;
capacidade continua como fallback para kits antigos quando o arquivo não foi
publicado. Um arquivo presente porém inválido desabilita as ações na interface.
O bloco `adaptiveWork` expõe somente a política reduzida e a liveness dos
assignments. Ele não contém texto gerado, prompt ou amostras do progresso.

`GET /api/control` devolve disponibilidade, operação em andamento, resultado
anterior e um token CSRF aleatório de 32 bytes mantido somente na memória do
processo. O token não é persistido.

`POST /api/control` aceita exclusivamente um destes corpos:

```json
{ "action": "start" }
```

```json
{ "action": "stop" }
```

No driver Windows, o primeiro invoca somente
`Hch-Worker.ps1 start -ConfigPath <fixo>` e o segundo somente
`Hch-Worker.ps1 stop -ConfigPath <fixo>`. No driver Node.js fixo, o painel
invoca somente `hch-worker-control.mjs start|stop`; o próprio script pertence ao
kit local e não recebe caminhos. Não há rota para `configure`, bootstrap,
paralelismo arbitrário, comandos ou paths.
Todas as respostas desses endpoints sempre incluem:

```http
Cache-Control: no-store, max-age=0
Pragma: no-cache
Expires: 0
```

Arquivos ausentes, excessivamente grandes, inválidos ou inseguros produzem
valores neutros e alertas; detalhes de caminho e conteúdo não são retornados.

### Semântica de pausa

Pausar primeiro grava capacidade solicitada zero no controle local e impede
novos ciclos do Windows Service persistente. O worker publica esse estado local antes de
tentar o aviso central de drain com timeout limitado. A execução já iniciada
não é encerrada: assignments ativos mantêm heartbeat, lote e conclusão até um
estado terminal seguro. Uma falha ao avisar a API nunca reabre novos claims.
Mesmo que `status.json` ainda contenha uma concessão positiva antiga, a
interface mostra `Finalizando` ou `Pausado` quando `worker-control.json` declara
`acceptingClaims=false` e `drainRequested=true`.

## Controles de segurança

- bind exclusivamente em loopback;
- validação de cliente e `Host` loopback em todas as rotas, inclusive assets e
  leitura do token, bloqueando DNS rebinding;
- nenhuma restrição de IP é acrescentada à API central: a limitação loopback
  vale somente para este painel na máquina do worker;
- controles desabilitados por padrão e habilitados somente com os três arquivos
  canônicos fixados no startup;
- POST com `Origin` exatamente same-origin, `Sec-Fetch-Site: same-origin`, token
  CSRF comparado em tempo constante, `application/json` estrito, tamanho máximo
  de 128 bytes e uma única operação em voo;
- sem CORS e sem resposta permissiva a `OPTIONS`;
- `execFile` com `shell: false`; ação, script, configuração e executável não
  podem vir de body, query ou cabeçalhos;
- stdout, stderr, paths e mensagens de exceção nunca são devolvidos ao browser;
- arquivos fixos são revalidados contra symlink/substituição imediatamente
  antes de cada ação;
- CLI, configuração e PowerShell devem ser filhos diretos de suas raízes
  canônicas independentes; a execução usa `RemoteSigned`, nunca `Bypass`;
- `worker-control.json` pertence somente à allowlist de leitura; o coletor Node
  não pode gravá-lo nem contornar as invariantes do módulo PowerShell;
- nomes de arquivo fixos, limite de 1 MiB e rejeição de symlinks;
- snapshots com campos estritamente permitidos;
- rejeição recursiva de campos com nomes associados a segredos, senhas,
  tokens, cookies, credenciais, autorização, API keys e chaves privadas;
- somente IDs/fingerprints públicos da cadeia Ed25519;
- CSP, proteção contra framing, `nosniff` e política same-origin;
- interface usa `textContent`, não injeta telemetria como HTML;
- erros públicos não incluem caminhos nem conteúdo dos arquivos.

O diretório de dados deve ser legível somente pela conta do worker e pela conta
local que executa o painel. Não armazene chave privada, token, cabeçalho HTTP ou
corpo editorial nesses snapshots.

## Testes

```bash
node --test ops/worker-dashboard/test/*.test.mjs
```

Os testes usam diretórios temporários e portas efêmeras em loopback; não deixam
um painel em execução. As ações de controle usam um executor injetado que só
registra argumentos: nenhum PowerShell, worker, tarefa ou API real é chamado.
