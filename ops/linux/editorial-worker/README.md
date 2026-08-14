# Kit portátil Linux/macOS do worker editorial HCH 3.1.0

Este diretório contém o runtime portátil 3.1.0 para Linux/macOS sobre o
protocolo editorial HCH 2.0. Ele oferece os fluxos abaixo:

- `bootstrap`: cria ou carrega a identidade Ed25519 local, opcionalmente
  cadastra sua chave pública, valida e aplica o manifesto canônico e atesta o
  ambiente;
- `execute`: depois do gate de prontidão, solicita à rota central `/execute`
  um único ciclo idempotente do executor legado `vps-primary`;
- `run-one`: reivindica e executa localmente exatamente um assignment com o
  plano de geração adaptativo imutável;
- `supervise`: mantém heartbeat de presença assinado, executa o pool paralelo
  autorizado e supervisiona o dashboard loopback no mesmo processo de serviço.

`bootstrap` nunca reserva itens e nunca chama `/execute` ou `/claim`. A CLI operacional
`hch-editorial-workerctl` controla a intenção operacional do serviço contínuo.
`pause` e paralelismo zero preservam trabalhos ativos; `stop` cancela geradores
ativos e relata `operator-stop-requested` ao orquestrador.

## Requisitos

- Linux ou macOS e Node.js `22.13.0` ou mais recente;
- acesso HTTPS ao orquestrador;
- engine local acessível exclusivamente por loopback e compatível com
  `GET /api/tags`;
- modelo e digest definidos no manifesto já presentes nessa engine;
- chave pública raiz e seu fingerprint obtidos por um canal administrativo
  independente do próprio manifesto.

O kit não possui dependências npm externas. A implementação criptográfica
compartilhada fica em `../../../lib/editorial-worker-signatures.mjs`.

## Configuração

Copie `config.example.json` para um caminho administrativo, por exemplo
`/etc/hch-editorial-worker/config.json`, e substitua o fingerprint fictício
pela impressão digital real da chave raiz:

```bash
sudo install -d -m 0750 /etc/hch-editorial-worker/trust
sudo install -d -m 0700 /var/lib/hch-editorial-worker
sudo install -m 0644 hch-root-v1.pub.pem \
  /etc/hch-editorial-worker/trust/hch-root-v1.pub.pem
sudo install -o root -g hch-editorial-worker -m 0640 config.example.json \
  /etc/hch-editorial-worker/config.json
```

Campos relevantes:

- `nodeId` e `keyId` identificam este worker e sua chave pública no
  orquestrador;
- `orchestratorBaseUrl` aceita somente uma origem HTTPS, sem credenciais,
  caminho, query ou fragmento;
- `stateDirectory` e `rootPublicKeyPath` precisam ser caminhos absolutos;
- `rootPublicKeyFingerprint` é o pin local `SHA256:<base64url>` da chave raiz;
- `localEngineBaseUrl` aceita somente `localhost`, `127.0.0.1` ou `::1`;
- `requestedCapacity` aceita inteiros de `0` a `64`; é o fallback inicial até
  existir `worker-control.json`, e `0` significa drain;
- `requestTimeoutMilliseconds` limita as chamadas curtas de controle;
- `executeRequestTimeoutMilliseconds` limita somente a chamada final de
  `/execute` do adaptador VPS legado. Ele não é aplicado ao gerador portátil,
  que não possui timeout total;
- `enrollmentTokenEnvironment` contém somente o nome da variável que será
  consultada durante o cadastro; o token não pertence ao JSON. O nome
  correspondente com sufixo `_FILE` aponta para um credential file.

Não há allowlist ou bloqueio por IP. Workers podem mudar de rede e endereço. A
identidade é a chave Ed25519 exclusiva de cada worker: a chave privada nunca
sai da máquina e o orquestrador conserva apenas a chave pública associada a
`nodeId` e `keyId`.

## Primeiro bootstrap e enrollment

O enrollment é a única etapa que usa um token administrativo. Ele não deve ser
colocado na linha de comando, em variável exportada ou em arquivo persistente.
Na VPS com systemd 239, o enrollment one-shot usa
`scripts/run-editorial-enrollment.sh`. O script lê o token sem eco, cria um
arquivo `0600` efêmero em `/run/hch-editorial-worker`, muda sua posse para o
usuário do worker, executa o bootstrap por `runuser` e apaga o arquivo por
`trap`. O valor não entra na linha de comando, na unit ou no ambiente do
processo chamador:

```bash
sudo /usr/local/libexec/hch-editorial-enrollment
```

O arquivo precisa ser regular, não pode ser symlink, deve ser privado e ter no
máximo 16 KiB. O kit lê esse valor somente no bootstrap com `--enroll`, remove
as duas variáveis do ambiente do próprio processo logo após capturá-las e não
grava nem registra o token. Definir simultaneamente a variável direta e
`..._FILE` é recusado. A unit usa o usuário estático
`hch-editorial-worker` e `StateDirectoryMode=0700`.

Na primeira execução, o kit gera uma chave Ed25519 PKCS#8 e sua chave pública
SPKI dentro de `stateDirectory/identity`. Em Linux, a leitura da chave privada
é recusada se o arquivo conceder acesso a grupo ou terceiros. Se apenas um dos
dois arquivos existir, o kit não regenera silenciosamente a identidade.

Depois de o cadastro existir, o token não é necessário:

```bash
node worker.mjs bootstrap \
  --config /etc/hch-editorial-worker/config.json
```

O resultado bem-sucedido informa `state: "ready"` ou, para capacidade zero,
`state: "draining"`, sempre com `workStarted: false`. Isso significa que o
ambiente foi atestado; não significa que a fila começou a ser processada.

## Contrato de bootstrap

O fluxo é deliberadamente fail-closed:

1. lê a chave raiz local e confirma seu fingerprint;
2. obtém o envelope publicado e verifica a cadeia assinada
   `raiz -> delegação de release -> manifesto`;
3. recalcula `manifest.hash` como SHA-256 do JSON RFC 8785 do manifesto,
   removendo somente o campo de primeiro nível `hash`;
4. aplica anti-rollback por sequência e hash do manifesto e também pela maior
   sequência local da delegação `root -> release`; uma delegação inferior é
   recusada mesmo ainda válida, e a mesma sequência com outro hash JCS é
   tratada como equivocation; imediatamente após a verificação criptográfica,
   fixa atomicamente a nova âncora monotônica antes de qualquer apply,
   self-test ou atestação;
5. valida estritamente a `adaptiveWorkPolicy`, incluindo tiers crescentes,
   menor unidade, janelas de inatividade e hash JCS SHA-256; recusa ações
   desconhecidas, ações ou artefatos `root-required`, comandos
   arbitrários e qualquer manifesto que habilite autorização por IP; valida a
   estrutura, versão, tetos e garantia `telemetryMayOnlyReduce` da
   `capacityPolicy` assinada;
6. solicita um challenge autenticado, chama `/bootstrap` com assinatura
   Ed25519 e verifica novamente o manifesto devolvido pela sessão;
7. baixa artefatos somente da origem e namespace do orquestrador, validando
   tamanho, tipo MIME e SHA-256 antes do apply;
8. constrói e verifica o `RuntimeProfile` v2, incluindo a identidade completa
   `provider`, `engineAdapter` e `engineAdapterVersion` no hash imutável;
9. grava política, prompt, schemas e configuração da engine de maneira
   atômica; em falha tratada, restaura as versões anteriores;
10. consulta `GET /api/tags` no loopback e exige correspondência exata de nome
   e digest do modelo;
11. exige que `/bootstrap` preserve `requestedCapacity` e devolva exatamente a
    `capacityPolicy` e a `adaptiveWorkPolicy` assinadas; a atestação inclui
    `adaptiveWorkPolicyHash` e valida a concessão, incluindo
    solicitado, concedido, classe, motivo e TTL;
12. persiste `capacity.json` e só então grava `ready.json`; o recibo técnico
    produzido durante o apply segue na atestação, e a âncora de delegação já foi
    fixada antes da aplicação.

A ação declarativa `pull-model-by-digest` não autoriza shell remoto nem inicia
a engine. Nesta versão ela representa o estado desejado; o bootstrap confirma
que o modelo exato já está presente e falha com `model-digest-unavailable` caso
contrário.

As únicas ações de release aceitas são:

- `verify-artifact`;
- `configure-engine`;
- `pull-model-by-digest`;
- `apply-editorial-policy`;
- `self-test`.

Uma atualização de binário que requeira root não pode ser instanciada por uma
release. Ela exige um procedimento administrativo separado e não é executada
por este kit.

## Capacidade adaptativa assinada

`capacityPolicy` pertence ao manifesto assinado e é armazenada, junto com seu
hash JCS SHA-256, em `applied-manifest.json`, `ready.json` e na configuração da
engine. O worker aceita o algoritmo `hch-adaptive-capacity-v1`, solicitação
estrutural máxima `64`, classes conhecidas, mapas de plataforma/nó, TTL finito e
limiares de pressão coerentes. Campo desconhecido, classe ausente para o worker
ou uma política que permita à telemetria elevar a concessão é recusado.

Cada ciclo envia o desejo local efetivo e pressão instantânea:

```json
{
  "requestedCapacity": 8,
  "pressure": { "cpuPercent": 42.5, "memoryPercent": 61.25 }
}
```

CPU é derivada da carga de um minuto por processador lógico e memória da fração
ocupada. GPU só é enviada quando houver uma medição válida. A resposta precisa
conter `capacity` coerente com a política assinada: a concessão não pode superar
a solicitação, o teto do nó/classe ou os slots declarados; a pressão deve ser o
eco exato do pedido, e `grantedUntil` precisa respeitar o TTL. Somente depois de
todas essas verificações o snapshot é gravado em `capacity.json`.

Capacidade `0` é drain: o ciclo ainda pode negociar o estado central, mas exige
concessão zero, zero itens e zero resultados. Uma concessão expirada permanece
registrada para auditoria, porém `effectiveGrantedCapacity` passa a zero.

## RuntimeProfile v2 imutável

O perfil consumido pelo worker possui exatamente os campos `provider`,
`engineAdapter`, `engineAdapterVersion`, `model`, `modelDigest`, `protocol`,
`temperature`, `contextWindow`, `maxOutputTokens`, `policyId`, `policyVersion`,
`policyHash`, `promptConfigHash`, `pipelineVersion`, `manifestSequence`,
`manifestHash` e `runtimeProfileHash`. Campos ausentes ou desconhecidos são
recusados.

`runtimeProfileHash` é o SHA-256 hexadecimal minúsculo do JSON RFC 8785 do
perfil, removendo **somente** `runtimeProfileHash`. Assim, trocar o provider,
usar outro adaptador ou executar outra versão do adaptador exige um novo hash,
mesmo quando modelo, digest e parâmetros de geração permanecem iguais. O
schema publicável está em `schemas/worker-runtime-profile-v2.schema.json`.
O payload de atestação correspondente está descrito em
`schemas/worker-attestation-v2.schema.json`; ele usa os três campos de engine
no nível superior e não aceita o alias legado `engineVersion`.

No adaptador VPS, `/execute` não devolve assignments ao processo local: o
lifecycle é executado no ponto central. Ainda assim, antes da chamada o kit
recalcula o perfil a partir do manifesto assinado e exige concordância com
`applied-manifest.json`, `ready.json` e `runtime/config/engine.json`. Logo, o
gate local não aceita uma configuração instalada com provider ou adapter
divergente. O supervisor portátil usa o mesmo verificador antes de aceitar
cada claim.

## Trabalho adaptativo e progresso real

Cada assignment recebido por `POST /claim` contém `generationPlan` e
`generationPlanHash`. O worker recalcula o hash SHA-256 do JSON RFC 8785,
confirma que o plano deriva exatamente da `adaptiveWorkPolicy` assinada e que
`maxOutputTokens` não supera o `RuntimeProfile`. O request Ollama usa
`stream: true` e `num_predict` exatamente igual ao plano: o worker nunca eleva,
renegocia ou infere localmente esse orçamento.

O fluxo NDJSON aceita conclusão somente quando o último registro declara
`done=true` e `done_reason="stop"`. Outro motivo ou ausência desses campos é
tratado como saída incompleta, sem registrar conteúdo ou motivo bruto. Somente
bytes não vazios de `message.content` incrementam `sequence` e
`contentBytes`. Uma nova tentativa incrementa `attempt` e zera ambos os
contadores; dentro da mesma tentativa eles só crescem.

Não há timeout total de processamento. A janela é apenas um sinal para que o
servidor reduza o tier dos próximos trabalhos. O assignment atual continua
enquanto demonstra progresso, mesmo lentamente; no tier mínimo, a janela total
é explicitamente ignorada. Os únicos watchdogs são:

- primeira resposta dentro de `firstProgressGraceSeconds`;
- novo conteúdo dentro de `stallAfterSeconds`;
- conclusão após entrar em `finalizing` dentro de
  `finalizationGraceSeconds`.

O heartbeat do assignment é serial, não sobreposto e ocorre a cada 30 s. Ele
envia o snapshot de progresso sem prompt, conteúdo ou resposta bruta. Uma
resposta HTTP 409 `generator-stalled` aborta a inferência local e registra
`fail` de forma fail-closed. `complete` e `fail` precisam ecoar o mesmo
`generationPlanHash`; conclusão válida permanece `pending-review` e exige
`automaticApproval=false` e `automaticPublication=false`.

## Supervisor portátil

Depois de enrollment e bootstrap válidos:

```bash
node worker.mjs supervise \
  --config /etc/hch-editorial-worker/config.json
```

O supervisor mantém um único lock de runtime e no máximo um `workPromise`.
Heartbeat de nó é imediato e depois a cada 60 s, independentemente de job
longo ou capacidade zero. `orchestration.json` registra de forma estrita
`workSizing` e `workload.claimableByTier`, além de capacidade e carga.

Pausar/`control-stop` grava `acceptingClaims=false` e capacidade efetiva zero:
os heartbeats continuam, nenhum claim novo começa e o assignment já ativo não
é interrompido. Bootstrap/attestation não devem disputar o lock com um job em
andamento.

## Anti-rollback da delegação de release

`trust-state.json` preserva `delegationSequence` e `delegationHash`. O segundo
valor é o SHA-256 do envelope completo de delegação em JSON RFC 8785. O worker
aceita a mesma sequência somente com o mesmo hash e aceita sequência maior,
substituindo as duas âncoras. Uma sequência menor ou equivocation falha antes
de bootstrap, download ou `/execute`.

Uma âncora nova é persistida atomicamente assim que a cadeia e o manifesto
assinados foram verificados, antes de `/bootstrap`, download, apply, self-test
ou atestação. Falha posterior deixa o worker não pronto, mas não rebaixa a
âncora: um replay da delegação anterior continuará recusado. Falha ao gravar o
pin interrompe o fluxo antes de qualquer aplicação.
O formato persistido está publicado em
`schemas/worker-trust-state-v1.schema.json`.

## Assinatura das chamadas e idempotência

Até a solicitação de `/challenge` é assinada. Ela usa um nonce aleatório local
com prefixo `client-`, prova posse da chave do worker e recebe o nonce da
operação. A chamada seguinte usa esse challenge no perfil
`hch-editorial-worker-request/v1`.

Para uma mesma tentativa lógica, o corpo canônico e `requestId` permanecem
iguais. Cada retry obtém um challenge e nonce novos. O estado pendente fica em
`operations.json`, portanto uma queda entre envio e resposta reutiliza o mesmo
ID. Uma operação já concluída recebe novo ID quando for iniciada novamente.

O endpoint deve manter a mesma regra no servidor: replay do mesmo
`nodeId/keyId/requestId` devolve o resultado anterior, sem repetir claims ou
geração.

## Recibo da atualização

A atestação leva `updateReceipt`, validado por
`schemas/worker-update-receipt-v1.schema.json`, com dois hashes distintos:

- `receiptHash`: SHA-256 hexadecimal do JSON RFC 8785 formado exatamente por
  `previousManifestHash`, `targetManifestHash`, `artifactHashes`, `result`,
  `rollbackPerformed` e `appliedAt`;
- `localAuditHash`: SHA-256 hexadecimal do journal técnico local completo,
  incluindo os resultados das ações, artefatos e verificações. Ele é a âncora
  para o processo de auditoria/compliance que será implementado depois.

O hash da política canônica segue no manifesto aplicado e na atestação. Antes
de qualquer execução, `ready.json`, `status.json`, `applied-manifest.json` e o
manifesto publicado precisam concordar. Se a política ou o manifesto mudou, a
execução é recusada com `update-required` e um novo bootstrap é obrigatório.

## Executar um ciclo na VPS

Somente a configuração com `nodeId: "vps-primary"` pode usar este adaptador
central legado:

```bash
node worker.mjs execute \
  --config /etc/hch-editorial-worker/config.json
```

O comando valida a prontidão, o manifesto atual, a âncora monotônica da
delegação e o `RuntimeProfile` v2 instalado antes de chamar
`POST /api/editorial/orchestrator/execute` com `requestedCapacity` e `pressure`.
A seleção e a deduplicação dos itens são responsabilidade do ponto central. O
adaptador `/execute` não acessa diretamente a tabela da fila e não publica
conteúdo. Workers portáteis usam `run-one`/`supervise` e as rotas assinadas de
claim, heartbeat, complete e fail.

Como o endpoint central conclui claim, heartbeat, geração e commit dentro da
mesma chamada, somente o POST de `/execute` usa
`executeRequestTimeoutMilliseconds` (45 minutos por padrão). A unit publicada
usa `TimeoutStartSec=60min`, deixando margem para o timeout padrão; se o valor
for aumentado, a margem da unit também deve ser revista. Os wrappers usam por
padrão a cópia operacional imutável em
`/usr/local/libexec/hch-editorial-runtime/ops/linux/editorial-worker/worker.mjs`.
Esse layout preserva o import relativo do módulo criptográfico canônico em
`/usr/local/libexec/hch-editorial-runtime/lib/`; o checkout de deploy não
precisa ser legível pelo usuário do serviço.

Este comando é deliberadamente de um ciclo. A repetição é feita pela unit
`hch-editorial-republication.timer`, nunca por um loop interno.

## CLI operacional uniforme

### Layout de instalação na VPS

Copie os artefatos com proprietário `root:root`, salvo onde indicado:

| Origem no repositório | Destino | Modo |
| --- | --- | --- |
| `ops/linux/editorial-worker/` | `/usr/local/libexec/hch-editorial-runtime/ops/linux/editorial-worker/` | `root:root`; diretórios `0755`, arquivos `0644`, `worker.mjs` `0755` |
| `lib/editorial-worker-signatures.mjs` | `/usr/local/libexec/hch-editorial-runtime/lib/editorial-worker-signatures.mjs` | `0644 root:root` |
| `lib/editorial-work-sizing.mjs` | `/usr/local/libexec/hch-editorial-runtime/lib/editorial-work-sizing.mjs` | `0644 root:root` |
| `lib/editorial-policy.mjs` | `/usr/local/libexec/hch-editorial-runtime/lib/editorial-policy.mjs` | `0644 root:root` |
| `lib/editorial-normalization.mjs` | `/usr/local/libexec/hch-editorial-runtime/lib/editorial-normalization.mjs` | `0644 root:root` |
| `scripts/run-editorial-bootstrap.sh` | `/usr/local/libexec/hch-editorial-bootstrap` | `0755` |
| `scripts/run-editorial-node-heartbeat.sh` | `/usr/local/libexec/hch-editorial-node-heartbeat` | `0755` |
| `scripts/run-editorial-republication.sh` | `/usr/local/libexec/hch-editorial-republication` | `0755` |
| `scripts/run-editorial-enrollment.sh` | `/usr/local/libexec/hch-editorial-enrollment` | `0700` |
| `scripts/hch-editorial-workerctl` | `/usr/local/sbin/hch-editorial-workerctl` | `0755` |
| `ops/systemd/hch-editorial-bootstrap.service` | `/etc/systemd/system/hch-editorial-bootstrap.service` | `0644` |
| `ops/systemd/hch-editorial-bootstrap.timer` | `/etc/systemd/system/hch-editorial-bootstrap.timer` | `0644` |
| `ops/systemd/hch-editorial-node-heartbeat.service` | `/etc/systemd/system/hch-editorial-node-heartbeat.service` | `0644` |
| `ops/systemd/hch-editorial-node-heartbeat.timer` | `/etc/systemd/system/hch-editorial-node-heartbeat.timer` | `0644` |
| `ops/systemd/hch-editorial-republication.service` | `/etc/systemd/system/hch-editorial-republication.service` | `0644` |
| `ops/systemd/hch-editorial-republication.timer` | `/etc/systemd/system/hch-editorial-republication.timer` | `0644` |
| `ops/systemd/hch-editorial-worker.sysusers.conf` | `/usr/lib/sysusers.d/hch-editorial-worker.conf` | `0644` |
| `ops/systemd/hch-editorial-worker.tmpfiles.conf` | `/usr/lib/tmpfiles.d/hch-editorial-worker.conf` | `0644` |
| configuração adaptada de `config.example.json` | `/etc/hch-editorial-worker/config.json` | `0640 root:hch-editorial-worker` |
| chave raiz pública pinada | `/etc/hch-editorial-worker/trust/hch-root-v1.pub.pem` | `0644 root:root` |

`/usr/local/libexec/hch-node` deve ser um runtime Node.js compatível com
`package.json` e executável pelo usuário estático. Depois da cópia, crie o
usuário/diretórios e releia as units com `systemd-sysusers`,
`systemd-tmpfiles --create` e `systemctl daemon-reload`. Esses comandos apenas
preparam o host; não habilite timers antes de cumprir o gate do servidor
descrito abaixo.

Instale `scripts/hch-editorial-workerctl` como
`/usr/local/sbin/hch-editorial-workerctl`, modo `0755`. A CLI executa as
operações de estado como o usuário `hch-editorial-worker` e reserva `systemctl`
para o controle do serviço:

```bash
sudo hch-editorial-workerctl configure
sudo hch-editorial-workerctl validate
sudo hch-editorial-workerctl set-parallelism 8
sudo hch-editorial-workerctl start
sudo hch-editorial-workerctl status
sudo hch-editorial-workerctl pause
sudo hch-editorial-workerctl stop
```

- `configure`: cria/verifica a identidade e grava controle local em drain; não
  inicia processamento;
- `validate`: confere somente identidade, pin raiz, ready/applied/trust,
  artefatos, modelo local, RuntimeProfile e política de capacidade; não chama
  `/claim` nem `/execute`;
- `start`: valida, restaura a última capacidade não zero e habilita
  `hch-editorial-worker.service`;
- `pause`: grava drain zero e preserva assignments ativos;
- `stop`: grava cancelamento; o supervisor encerra geradores ativos e relata a
  falha ao orquestrador;
- `set-parallelism 0..64`: persiste o desejo; zero equivale a `pause`;
- `status`: combina controle, concessão/TTL, prontidão e estado do serviço sem
  acessar a API.

### Gate de ativação do servidor

Não habilite o timer enquanto a rota VPS `/execute` aceitar somente `{}`. O
contrato necessário para este cliente é um corpo assinado com exatamente
`requestedCapacity` e `pressure`, e uma resposta com `capacity` no formato
`CapacityDecision`: `algorithmVersion`, solicitado, concedido, slots, ativos
local/global, disponibilidade global, classe, teto do nó, motivo,
`grantedUntil` e eco da pressão. Até essa mudança ser publicada no servidor,
mantenha `hch-editorial-republication.timer` desabilitado; instalar/copiar os
artefatos e executar testes locais não autoriza `start`.

`configure` não substitui enrollment/bootstrap. Depois do primeiro enrollment,
execute ou acione `hch-editorial-bootstrap.service`, confirme `validate` e só
então habilite explicitamente `hch-editorial-node-heartbeat.timer`; a CLI
`start` controla apenas o timer de processamento. Confirme pelo menos dois
heartbeats de presença com intervalo de 60 segundos, inclusive em capacidade
zero, antes de usar `start`. O `hch-editorial-bootstrap.timer` também é
habilitado separadamente para renovar a attestation. Os arquivos
`hch-editorial-worker.sysusers.conf` e
`hch-editorial-worker.tmpfiles.conf` criam usuário e diretórios privados; as
units não contêm credenciais.

## Estado local e dashboard

As gravações são feitas por arquivo temporário e rename atômico. Bootstrap,
execute, `run-one` e `supervise` usam um lock exclusivo; `stop` pode trocar somente
`worker-control.json` fora desse lock para sinalizar drain mesmo enquanto um
ciclo já autorizado termina. Os principais arquivos são:

- `identity/worker-private.pk8.pem`: segredo local, modo `0600`;
- `identity/worker-public.spki.pem` e `identity/identity.json`: identidade
  pública e metadados;
- `applied-manifest.json`, `ready.json` e `trust-state.json`: gate local;
- `worker-control.json`: desejo local, último valor não zero e sinal de drain;
- `capacity.json`: última concessão central validada, motivo, pressão e TTL;
- `orchestration.json`: heartbeat 60 s, `workSizing`, capacidade e workload por tier;
- `runtime/`: artefatos verificados e configuração aplicada;
- `receipts/<manifest-hash>.json`: journal e recibo da atualização;
- `operations.json`: IDs e hashes de corpos pendentes/concluídos;
- `status.json`: contrato `hch.worker-status/v1`;
- `metrics.json`: contrato `hch.worker-metrics/v1`.

`status.json` e `metrics.json` são destinados ao monitor multinó e nunca
recebem token, Authorization, chave privada, payload editorial ou credencial.
Os schemas estão em `schemas/`. A pasta de estado inteira não deve ser exposta
ao dashboard porque contém a identidade privada.

O status usa os mesmos campos do kit Windows, incluindo `connection`,
`transport` (TLS e certificado), `trust` (raiz, release, manifesto e política)
e `capacity` (solicitado, concedido, efetivo, motivo, pressão e validade).
O fetch HTTPS do Node valida cadeia e hostname; como ele não expõe o
certificado ao adaptador, fingerprint e expiração podem permanecer `null`.

As métricas também seguem exatamente o contrato Windows: lotes
`total/completed/failed`, jobs `claimed/running/completed/failed/discarded`,
atualizações, duração, CPU, GPU (marcada como `unsupported` e utilização
`null`), memória total/processo/estimativa por item, RX/TX, contadores de fonte
`null` quando não há coletor Linux e tempo em standby.

## Falhas seguras

Qualquer falha de assinatura, pin, validade, hash, tamanho, MIME, modelo,
anti-rollback ou atestação deixa `status.json` fora de `ready`. O comando
`execute` também exige que a validade de `readyUntil` ainda esteja ativa. Um
processo interrompido durante apply não fica autorizado a executar, mesmo que
alguns arquivos atômicos já tenham sido trocados; execute novamente o
bootstrap após corrigir a causa.

Uma terminação não capturável pode deixar `.worker.lock`. Antes de removê-lo,
confirme administrativamente que o PID registrado no arquivo não existe e que
nenhuma instância do kit está ativa. O kit não apaga automaticamente um lock
preexistente, evitando duas operações concorrentes por uma inferência insegura.

Não apague ou regenere as chaves para contornar uma falha. Revogação, rotação
de raiz, alteração de `nodeId/keyId` e recuperação da identidade são operações
administrativas explícitas.

## Testes

A suíte usa somente servidores simulados em memória. Ela não acessa a fila,
não chama o gerador real e não inicia serviço:

```bash
cd ops/linux/editorial-worker
npm test
```

Os casos cobrem assinatura do challenge, enrollment, cadeia raiz/release,
anti-rollback e equivocation de manifesto e delegação, `RuntimeProfile` v2,
recusa de root actions, integridade de artefatos, digest do modelo, recibos,
gate de prontidão, capacidade assinada `0..64`, pressão, TTL, drain, CLI segura
e retry idempotente de `/execute`. A suíte adaptativa também prova hash JCS do
plano, orçamento Ollama exato, progresso cumulativo/reset por tentativa,
conclusão `done_reason=stop`, ausência de timeout total, stall fail-closed,
heartbeat em capacidade zero e ausência de `workPromise` sobreposto.
