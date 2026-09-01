# HCH Editorial Worker Kit para Windows

## Instalação simplificada

O instalador gráfico recomendado é gerado por:

```powershell
.\ops\windows\installer\Build-HchWorkerSetup.ps1
```

Ele produz `HCH-Worker-Setup-<versão>-x64.exe`, assinado quando a chave de
publicação está disponível, e os manifests para futura distribuição via
`winget install Hubtech.HCHWorker`. O usuário confirma a publicadora, informa o
token e escolhe o paralelismo inicial; `0` instala o serviço em pausa, mantendo
heartbeat e renovação da atestação. Consulte
[`../installer/README.md`](../installer/README.md) para build e segurança.

Versão do kit: **3.1.0**. Este diretório implementa o bootstrap, o gate de
confiança e o ciclo editorial local do HCH Editorial Orchestration Trust
Protocol v2. O processamento é hospedado por um Windows Service nativo,
persistente, iniciado pelo SCM sem terminal e sem depender de logon. A
instalação e a inicialização do serviço preservam `drain`; nada solicita fila
ou gera conteúdo até o operador executar explicitamente `start`.

## Garantias

- Cada worker cria localmente uma identidade Ed25519 exclusiva. A chave privada
  PKCS#8 permanece no worker e recebe ACL para o usuário do serviço e `SYSTEM`.
- O orquestrador conhece somente a chave pública SPKI e seu fingerprint.
- A identidade não depende do IP. Mudança de rede, NAT, DHCP ou ausência de IP
  fixo não altera a identidade nem a autorização do nó.
- Requisições mutáveis usam Ed25519 bruto e HTTP Message Signatures (RFC 9421),
  `Content-Digest` SHA-256 (RFC 9530), nonce descartável, expiração e ID de
  requisição.
- O manifesto v2 é assinado por uma chave de release, cuja delegação é
  validada com a chave raiz fixada fora da API.
- Sequência monotônica, expiração e `previousManifestHash` bloqueiam rollback,
  freeze e equivocação do manifesto.
- O `contentContractHash` assinado é recalculado e persistido no manifesto
  aplicado, prontidão, status, trust state e atestação. Hash igual renova
  somente metadados atômicos, sem baixar artefatos nem interromper assignments;
  hash diferente fecha novos claims e aguarda o lote ativo terminar antes do
  apply. O heartbeat de presença continua durante esse drain e anuncia
  capacidade de novos claims igual a zero.
- O fallback para JWS, payload ou delegação expirados exige o mesmo
  `manifestHash` já aplicado. Uma delegação expirada não pode autorizar um
  manifesto novo, mesmo quando o payload novo ainda está válido.
- A delegação raiz → release também tem sequência monotônica. O worker mantém
  em `trust-state.json` a maior `delegationSequence` e o hash SHA-256 JCS do
  envelope aceito: sequência menor é downgrade e a mesma sequência com outro
  hash é equivocação. As âncoras só são gravadas após a verificação integral.
- Apenas ações declarativas conhecidas são aceitas. Não existe execução de
  shell, script ou comando recebido no manifesto.
- Artefatos são baixados para staging e validados por tamanho e SHA-256 antes
  da aplicação. Arquivos substituídos são copiados para backup e registrados
  em journal incremental para rollback.
- `claim` só é chamado quando `ready.json` e `applied-manifest.json` concordam e
  o atestado ainda está válido.
- O manifesto assinado precisa conter `capacityPolicy` com algoritmo, teto
  estrutural, tetos por classe/nó, orçamento global, TTL e limites de pressão.
  O hash JCS dessa política é persistido em `engine.json`,
  `applied-manifest.json` e `ready.json`; ausência ou divergência bloqueia novos
  claims.
- O mesmo gate vale para `adaptiveWorkPolicy`: o hash SHA-256 JCS é persistido
  em `engine.json`, `applied-manifest.json` e `ready.json`, ecoado no atestado
  v2.2 e conferido novamente antes de validar qualquer plano de geração.
- Todo claim envia `requestedCapacity` (0–64) e a pressão instantânea
  disponível de CPU, memória e GPU. O worker só aceita a decisão central em
  `capacity`, valida algoritmo, classe, teto, contadores, TTL, telemetria
  refletida e `availableSlots`, e nunca interpreta capacidade solicitada como
  capacidade concedida.
- Cada resposta de claim é verificada antes de ser entregue ao gerador: o
  worker recalcula o SHA-256 JCS de `entry` e de `runtimeProfile` (removendo
  somente `runtimeProfileHash`) e recusa qualquer divergência. O mesmo gate é
  repetido imediatamente antes de heartbeat, falha e conclusão.
- Cada assignment inclui um `generationPlan` imutável e seu SHA-256 JCS. O
  plano deve corresponder exatamente à `adaptiveWorkPolicy` instalada a partir
  do manifesto assinado: tier, perfil editorial, teto de tokens, janela
  consultiva e três períodos de tolerância de liveness. O gerador passa
  exatamente `generationPlan.maxOutputTokens` ao Ollama e nunca recalcula esse
  teto localmente.
- A resposta do Ollama é consumida como NDJSON streaming. O gerador mantém um
  sidecar atômico `progress.json`, contendo somente `phase`, `attempt`,
  `sequence`, `contentBytes` e `updatedAt`; nenhum prompt, trecho produzido,
  lease ou segredo é gravado nesse arquivo. O heartbeat do assignment envia
  apenas os quatro contadores não sensíveis.
- A janela de processamento não é um deadline de execução. O watchdog nunca
  encerra um processo pelo tempo total ou por ele ter alcançado a janela. Ele
  só intervém quando falta o primeiro progresso, o stream deixa de avançar ou
  a finalização trava além das tolerâncias assinadas. No tier mínimo, a janela
  é explicitamente ignorada enquanto houver progresso, mesmo lento.
- `provider`, `engineAdapter` e `engineAdapterVersion` são obrigatórios no
  `runtimeProfile`, participam desse hash imutável e devem coincidir exatamente
  com `engine.provider`, `engine.adapter` e `engine.adapterVersion` do
  `runtime/config/engine.json` derivado do manifesto assinado.
- A conclusão repete `manifestSequence`, `manifestHash`, `policyHash`,
  `runtimeProfileHash` e `generationPlanHash` do assignment, além de
  `inputSnapshotHash`. Falha e heartbeat também repetem o hash do plano. Resultado
  antigo ou adulterado é descartado, nunca reenviado automaticamente, e o
  bootstrap de atualização é iniciado.
- O atestado leva um `updateReceipt` com manifesto anterior/alvo, mapa exato de
  hashes dos artefatos, resultado, flag de rollback, horário e hash canônico do
  registro técnico local sem segredos.
- O atestado v2 declara `provider`, `engineAdapter` e
  `engineAdapterVersion` como campos canônicos de topo; o campo legado
  `engineVersion` não é enviado.
- Falha de uma renovação com hash de conteúdo igual mantém a prontidão anterior
  somente até `readyUntil` e é registrada como refresh adiado; não muda o
  Worker para `update-failed` nem cancela trabalho ativo.

O fluxo editorial continua terminando em `pending-review`; este kit não aprova
nem publica conteúdo.

## Pré-requisitos

- Windows PowerShell 5.1;
- Node.js 22 ou superior disponível pelo caminho configurado;
- TLS válido para o control plane;
- chave pública raiz Ed25519, SPKI PEM, entregue por canal autenticado fora da
  API;
- token de enrollment fornecido como `HCH_EDITORIAL_ENROLLMENT_TOKEN` somente
  para a primeira associação da chave pública;
- Ollama local acessível pelo endereço definido em `OllamaBaseUri`.

O helper [`crypto/hch-ed25519.mjs`](crypto/hch-ed25519.mjs) usa apenas o módulo
`node:crypto`. Ele gera PKCS#8/SPKI, calcula o fingerprint, aplica JCS, assina e
verifica Ed25519 sem dependências NPM.

O probe TLS usa `SslStream` sem callback de validação e
`SslProtocols.None` (seleção segura do protocolo pelo Windows; neste notebook
negocia TLS 1.3). Cadeia e hostname seguem a validação padrão do .NET. O modo
de revogação online do Windows PowerShell 5.1 falhou para a cadeia pública
atual mesmo quando `HttpClient`/WinHTTP a validam; por compatibilidade, o probe
mantém o padrão do framework (`checkCertificateRevocation = false`). Não há
fallback que aceite certificado, hostname ou cadeia inválidos.

## Estado local

O exemplo usa `C:\ProgramData\HCH\EditorialWorker`:

```text
state/
  identity/
    worker-private.pk8.pem
    worker-public.spki.pem
    identity.json
  staging/<transaction-id>/
  backups/<utc-sequence-transaction>/transaction.json
  enrolled.json
  trust-state.json
  applied-manifest.json
  ready.json
  worker-control.json
  capacity.json
  status.json
  metrics.json
  cycles/
    active-batch.json
    last-cycle.json
    work-<id>/progress.json
runtime/
  config/engine.json
  editorial/policy.json
  editorial/prompt.md
  editorial/editorial-content-schema.json
  editorial/editorial-source-schema.json
trust/
  orchestrator-root.pem
```

`state/` e chaves nunca devem ser copiados entre workers. Rotacionar uma chave
cria uma nova identidade e exige novo enrollment; a chave pública anterior deve
ser revogada no orquestrador.

## Configuração e bootstrap

1. Copie `WorkerConfig.psd1.example` para `WorkerConfig.psd1` e ajuste somente
   caminhos, nome do nó, capacidade e origens locais permitidas.
2. Instale a raiz real no `RootPublicKeyPath` por canal fora da API.
3. Disponibilize o token de enrollment como variável protegida do processo ou
   da máquina; não o grave no PSD1.
4. Execute `Initialize-Worker.ps1`. O comando mostra apenas `nodeId`, `keyId` e
   o caminho da chave pública.
5. Execute `Invoke-WorkerBootstrap.ps1`. O comando termina depois do atestado;
   não solicita trabalho.
6. Consulte `Get-WorkerState.ps1`. Somente `ready.json` válido permite a etapa
   de claim.

Exemplo de chamada inicial, a ser executado pelo operador somente após as
chaves e configurações terem sido provisionadas:

```powershell
$env:HCH_EDITORIAL_ENROLLMENT_TOKEN = '<obtido-do-cofre-local>'
.\Initialize-Worker.ps1 -ConfigPath .\WorkerConfig.psd1
.\Invoke-WorkerBootstrap.ps1 -ConfigPath .\WorkerConfig.psd1
.\Get-WorkerState.ps1 -ConfigPath .\WorkerConfig.psd1
Remove-Item Env:\HCH_EDITORIAL_ENROLLMENT_TOKEN
```

Nenhum desses três scripts gera conteúdo.

### Controle operacional do ciclo

`Hch-Worker.ps1` é a interface operacional única para o serviço persistente de
processamento:

```powershell
# Em PowerShell elevado: cria identidade, grava drain e instala/inicia o
# serviço SCM com Automatic (Delayed Start), sem habilitar claims.
.\Hch-Worker.ps1 configure -ConfigPath .\WorkerConfig.psd1

# Validação estritamente local: não chama claim e não reserva item.
.\Hch-Worker.ps1 validate -ConfigPath .\WorkerConfig.psd1

# Primeira ativação usa paralelismo 1, salvo valor local definido antes.
.\Hch-Worker.ps1 start -ConfigPath .\WorkerConfig.psd1

# Solicita um N local; a API ainda pode conceder menos.
.\Hch-Worker.ps1 set-parallelism -ConfigPath .\WorkerConfig.psd1 -Parallelism 6

# Pausa: bloqueia novos claims e deixa assignments já adquiridos terminarem.
.\Hch-Worker.ps1 pause -ConfigPath .\WorkerConfig.psd1

# Stop: cancela assignments ativos e relata operator-stop-requested.
.\Hch-Worker.ps1 stop -ConfigPath .\WorkerConfig.psd1

.\Hch-Worker.ps1 status -ConfigPath .\WorkerConfig.psd1
```

`set-parallelism -Parallelism 0` tem a mesma semântica de `pause`.
Valores positivos podem variar de 1 até `LocalParallelismLimit`, limitado
também pelo máximo estrutural da `capacityPolicy` assinada. Não há hipótese
estrutural de apenas um ou dois processos. A resposta de status mantém campos
separados para desejo local, capacidade pedida ao servidor, capacidade
concedida, assignments ativos, motivo e validade da concessão.

O aviso central de drain é best effort: a flag local é gravada primeiro. Assim,
uma indisponibilidade da API não reabre claims. `pause` preserva o ciclo em
andamento. `stop` encerra geradores ativos e relata cada assignment como
`operator-stop-requested`; falhas de relato ficam no journal de reconciliação.
`start`, `pause` e `stop` não exigem direito de
iniciar ou parar o serviço no SCM.

O host é compilado por `Build-HchWorkerService.ps1` como `winexe` sobre .NET
Framework 4.8. `Install-HchWorkerService.ps1` copia o kit para uma versão
protegida em `Program Files`, compara hashes antes de remover Zone.Identifier,
registra conta virtual exclusiva, SID de serviço, inicialização automática
atrasada e recovery, e aposenta a tarefa editorial legada. Ele nunca usa
`ExecutionPolicy Bypass`; os filhos executam com `RemoteSigned`, `-NoLogo`,
`-NoProfile` e `-NonInteractive`. Consulte
[`docs/operations/windows-worker-service.md`](../../../docs/operations/windows-worker-service.md).

## Contrato de rede

Enrollment é uma operação administrativa autenticada pelo token dedicado e
registra somente `nodeId`, `keyId` e a chave pública. A prova de posse da chave
privada acontece em seguida: o worker obtém um nonce com finalidade específica
em `POST /api/editorial/orchestrator/challenge` e assina bootstrap, atestado,
claim e conclusão. O próprio pedido de challenge também é assinado, usando
um nonce local imprevisível `client-<uuid><uuid>`; o servidor verifica a prova
de posse e impede replay antes de emitir o nonce da operação. O token de
enrollment não substitui a identidade Ed25519.

A assinatura `hch` cobre exatamente:

```text
@method
@authority
@path
content-digest
content-type
x-hch-node-id
x-hch-key-id
x-hch-request-id
x-hch-created
x-hch-expires
x-hch-nonce
```

O control plane autentica `nodeId + keyId + assinatura + nonce`; o IP de origem
não faz parte da identidade, do cadastro ou da decisão de autorização.

Cada mutação editorial mantém em `StateRoot\pending-operations` somente
metadados (`operationKey`, `requestId`, alvo, digest JCS do corpo, janela
temporal e, no claim, a telemetria de pressão não sensível) — nunca corpo,
lease token ou credencial. A pressão original é reutilizada no retry para que
o corpo e seu digest permaneçam idênticos. Se uma resposta se perder,
a próxima invocação da mesma
operação, com corpo idêntico, preserva `X-HCH-Request-Id` e o digest, mas obtém
challenge e nonce novos. Corpo ou alvo diferentes com o mesmo registro são
recusados localmente. O registro só é removido depois de uma resposta final
coerente.

A garantia contratual é de 24 horas desde a primeira tentativa persistida.
Depois disso, o kit não cria outro ID automaticamente: primeiro é necessário
confirmar no control plane que o lease expirou e o item foi reclaimed (ou que
a operação nunca adquiriu lease). Em seguida, arquive a evidência expirada:

```powershell
.\Resolve-ExpiredWorkerOperation.ps1 `
  -ConfigPath .\WorkerConfig.psd1 `
  -OperationKey claim-request `
  -ConfirmLeaseExpiredOrReclaimed `
  -Confirm
```

O próximo ciclo usará novo request ID. O endpoint `/execute` pertence somente
à VPS; um retry dele relê o estado vinculado ao request original e nunca repete
o gerador/LLM. Este kit Windows não chama `/execute` e não faz retry automático
de geração.

Envelope esperado para o manifesto:

```json
{
  "manifest": {
    "protected": "<base64url de JCS(protected)>",
    "payload": "<base64url de JCS(manifesto v2)>",
    "signature": "<assinatura Ed25519 base64url>"
  },
  "delegation": {
    "protected": "<base64url de JCS(protected)>",
    "payload": "<base64url da delegação root->release>",
    "signature": "<assinatura Ed25519 base64url>"
  },
  "rootKeyId": "hch-root-v1",
  "rootPublicKeyFingerprint": "SHA256:<base64url>"
}
```

Esse é exatamente o envelope JCS/JWS-like implementado pelo módulo canônico
`lib/editorial-worker-signatures.mjs`; o kit importa esse módulo e não define
um segundo perfil de assinatura.

## Plano declarativo

O worker reconhece somente:

| Ação | Efeito permitido |
|---|---|
| `verify-artifact` | staging e validação de tamanho/hash |
| `apply-editorial-policy` | instala os quatro artefatos editoriais conhecidos |
| `configure-engine` | grava configuração JSON canônica no runtime |
| `pull-model-by-digest` | usa apenas a API local fixa do Ollama e verifica digest |
| `self-test` | verifica artefatos, configuração, motor e modelo |

`actions` aceita exclusivamente os cinco tipos da tabela e
`authorizationClass: release`. `install-runtime-artifact` e
`install-engine-adapter` só podem aparecer em `rootActionCapabilities`, com
`status: requires-separate-root-envelope`; essa lista nunca é iterada como
plano nem executada. Se qualquer um desses tipos vier em `actions`, o worker
grava `root-action-refused-no-canonical-authorization` e interrompe a
atualização antes de staging.
A delegação de release, sozinha, não autoriza código executável. Um envelope
canônico específico de autorização raiz será definido numa versão futura do
protocolo; até lá não há caminho alternativo. Campos `command`, `script`,
`shell` e `arguments` provocam rejeição do manifesto.

Downloads só podem usar `AllowedArtifactOrigins`. Autotestes e a API do motor
só podem usar `AllowedSelfTestOrigins`. Essas allowlists evitam SSRF; não
restringem de qual IP um worker pode acessar o orquestrador.

## Integração com o loop editorial

`Run-WorkerCycle.ps1` é o consumidor da fila. Cada execução adquire um lock
exclusivo, reconcilia o journal anterior, relê o controle local, renova o
bootstrap quando necessário e executa o preflight do Ollama **antes** de fazer
claim. O pedido contém o N desejado e a pressão local; somente os
`availableSlots` da decisão central podem virar novos processos.

Para cada assignment o ciclo:

1. valida novamente os hashes JCS imutáveis de `entry` e `runtimeProfile`, a
   política, o prompt, o manifesto, o motor, o modelo e o digest;
2. grava o assignment em diretório privado e inicia um processo Node separado;
3. usa exclusivamente o Ollama em loopback. A evidência editorial é o snapshot
   canônico já recebido (`title` e `summary`); a URL da fonte não é buscada pelo
   worker, evitando SSRF e alteração da evidência durante o lease;
4. envia heartbeat inicial, periódico e final, persiste o novo
   `leaseExpiresAt` e interrompe os geradores se houver desconexão ou mudança de
   política;
5. produz o draft canônico com proveniência exata e
   `review.status = pending-editorial-review`; e
6. conclui somente se a API confirmar `commitAccepted=true`,
   `status=pending-review`, `automaticApproval=false` e
   `automaticPublication=false`.

O modelo pode fazer no máximo uma tentativa inicial e uma reparação guiada
pelos erros do validador editorial. Falha terminal é devolvida ao endpoint de
falha para retry/reclaim central. Ambiguidade de rede nunca dispara nova
geração: o journal mantém `draft-ready`, `completing`, `commit-unknown` ou
`fail-unknown` e reutiliza o mesmo corpo e request ID. Um `commit-unknown`
expirado bloqueia o ciclo para reconciliação explícita, evitando duplicidade.

Se o servidor retornar `428 update-required` ou rejeitar política/manifesto
com `409`, `ready.json` é invalidado, o resultado antigo é descartado e o
bootstrap aplica o novo contrato antes de qualquer claim posterior. Não há
rota de aprovação ou publicação neste ciclo.

## Rollback e recuperação

Uma falha durante apply ou self-test restaura arquivos a partir do journal e
mantém o worker em `update-failed`, sem claim. Pull de modelo é aditivo e não
remove modelos preexistentes no rollback, evitando afetar outros consumidores
locais.

Antes da atestação, `backups/<transação>/update-receipt.json` recebe o recibo
e o log técnico local. `receiptHash` é o SHA-256 hexadecimal do JSON JCS
exatamente sobre
`previousManifestHash`, `targetManifestHash`, `artifactHashes`, `result`,
`rollbackPerformed` e `appliedAt`; a API o recalcula. `localAuditHash` é o
SHA-256 JCS do `localLog` completo, incluindo `transactionId` e mudanças
aplicadas. Ele é opaco para a validação operacional atual, mas fica persistido
para auditoria futura. A API recebe somente o contrato definido em
`schemas/worker-update-receipt-v1.schema.json`; o mapa `artifactHashes` precisa
conter exatamente cada `artifact.name` e o SHA-256 declarado pelo manifesto.

Para um processo interrompido, identifique o journal correto em `backups` e,
após revisão humana, use:

```powershell
.\Restore-WorkerUpdate.ps1 `
  -ConfigPath .\WorkerConfig.psd1 `
  -TransactionJournalPath '<StateRoot>\backups\...\transaction.json' `
  -Confirm
```

O rollback invalida `ready`. Um novo bootstrap é obrigatório.

## Status e métricas para o dashboard

O kit grava atomicamente, dentro de `StateRoot`:

- `status.json`, schema `hch.worker-status/v1`: conexão com a API, validação
  TLS e certificado (inclusive validade em sete dias e fingerprint SHA-256),
  autenticação Ed25519, cadeia pública raiz → release → manifesto, estado,
  `running`, `standby`, prontidão, uptime, lote atual e o snapshot de capacidade
  (`requestedCapacity`, `grantedCapacity`, `activeAssignments`,
  `capacityReason`, `validUntil`);
- `metrics.json`, schema `hch.worker-metrics/v1`: CPU e GPU atuais, acumuladas
  e médias; GPU NVIDIA via `nvidia-smi` ou GPU AMD/integrada pelos contadores
  `GPUEngine`, sem nomes de dispositivo; memória por item no fechamento;
  RX/TX acumulados; bytes de requisição/resposta; lotes, jobs, atualizações,
  durações e tempo total em standby.
- `worker-control.json`, schema `hch.worker-control/v1`: intenção local do
  operador. O dashboard o valida estritamente e usa `acceptingClaims` e
  `drainRequested` antes de qualquer snapshot de capacidade potencialmente
  atrasado. O painel não possui permissão lógica para gravar esse arquivo.

Os schemas estão em `schemas/worker-status-v1.schema.json`,
`schemas/worker-capacity-v1.schema.json` e
`schemas/worker-metrics-v1.schema.json`. Esses arquivos nunca recebem token,
lease token, chave privada, payload editorial ou segredo. O dashboard somente
lê esses snapshots. As duas ações operacionais descritas abaixo passam pelo
CLI confiável do worker e não gravam os snapshots diretamente.

Os contratos endurecidos do bootstrap e das âncoras locais estão em
`schemas/worker-bootstrap-attestation-v2.schema.json` e
`schemas/worker-trust-state-v1.schema.json`.

### Dashboard persistente e somente local

O Windows Service inicia e supervisiona `ops/worker-dashboard` como filho
direto, sem PowerShell persistente e sem Scheduled Task. Se o painel falhar, o
serviço aplica reinício limitado com backoff; a execução editorial continua
independente. A instalação 3.1.0 remove a tarefa legada somente depois de
confirmar HTTP 200 no novo painel.

Para diagnóstico, o painel ainda pode ser executado manualmente em primeiro
plano, sempre limitado ao loopback:

```powershell
.\Start-WorkerDashboard.ps1 `
  -ConfigPath .\WorkerConfig.psd1 `
  -DashboardRoot C:\HCH\ops\worker-dashboard `
  -Port 4319
```

Depois de iniciado, o painel fica disponível somente em
`http://127.0.0.1:4319`. A limitação de loopback é exclusiva do painel local e
não cria bloqueio por IP na API central.

O painel oferece `Iniciar`, `Pausar`, `Parar e cancelar` e paralelismo de 0 a
64. Zero equivale a pausa e não cancela assignments ativos. `Stop` encerra os
geradores, registra a falha e a comunica ao orquestrador. Não existe controle
web para `configure`, bootstrap, shell, scripts ou paths.

## Limite desta versão

Os journals mantêm evidência técnica mínima de aplicação e rollback. Ledger
central, relatórios, retenção e processo de compliance ficam explicitamente
fora deste kit e devem ser implementados na etapa posterior de auditoria.

Testes estáticos, criptográficos, do gerador/ciclo e do adaptador do dashboard:

```powershell
node --test .\tests\worker-kit.test.mjs .\tests\worker-cycle.test.mjs .\tests\windows-service.test.mjs
node --test ..\..\worker-dashboard\test\*.test.mjs
```

Esses testes usam fixtures locais e servidores Ollama simulados. Eles não
fazem bootstrap, claim, heartbeat ou conclusão contra a API real e não
instalam, iniciam ou alteram o Windows Service real.
