# Promoção do HCH Worker Windows v4

Este procedimento impede que a criação do instalável, o canário e a publicação
oficial sejam tratados como uma única ação. O artefato oficial deve ser
exatamente o MSI assinado que passou por todos os gates; ele nunca é recompilado
depois do canário.

## Estados e fronteiras

1. **Candidato assinado** — o workflow `Windows package` só aceita a `main`
   protegida, exige o teste MSI descartável e gera um artefato não oficial com
   retenção de 90 dias. O `signing-status.json` permanece com
   `releaseIntent=candidate` e `releasable=false`.
2. **Canário** — uma VM ou máquina Windows descartável baixa esse artefato pelo
   `run id` e nome exatos. O SHA-256 do MSI deve ser registrado antes de qualquer
   instalação.
3. **Rollback** — o mesmo canário precisa provar a volta operacional ao 3.1.1,
   já promovido em toda a frota pelo gate de ponte.
   Desinstalar o v4 não substitui essa prova.
4. **Evidência atestada** — o atestador revisa as amostras reais sanitizadas,
   assina os bytes UTF-8 exatos de
   `release-evidence/windows/<versão>/canary-evidence.json` e adiciona também a
   assinatura CMS detached `canary-evidence.p7s` na `main` protegida. JSON sem
   essa assinatura nunca é evidência de promoção.
5. **Tag protegida** — depois do canário e da revisão da evidência, criar uma tag
   anotada `windows-v<versão>` apontando para o commit que produziu o candidato,
   não para o commit posterior que adicionou a evidência.
6. **Promoção** — o workflow `Promote Windows candidate` baixa o artefato do run
   original, verifica assinaturas, checksums, attestation, a assinatura CMS do
   canário, as amostras e o rollback, e publica os mesmos bytes. Compatibilidade
   e impacto são derivados do `release-compatibility.json` já checksummed e
   ligado ao provenance do candidato; não são inputs do operador. A release usa
   `--latest=false` para preservar a ponte 3.1.1 descrita em
   `docs/worker-release-updates.md`.

O arquivo versionado declara o efeito da troca do runtime. O gate real de cada
conteúdo continua sendo o `contentContractHash` do manifesto assinado: uma
alteração que mude esse hash coloca o Worker em drain antes de aplicar a nova
política, independentemente de o número do executável ter mudado.

## Gate de exclusividade 3.1/v4

A migração preserva os arquivos, a identidade e a definição do serviço 3.1.1.
O serviço v4 inicia em `Paused/Drain` e recusa `Start` ou paralelismo positivo
enquanto o serviço legado não estiver simultaneamente **Stopped** e
**Disabled**. `Pause`, `Stop` e paralelismo zero continuam disponíveis.

Antes do canário:

1. Drenar o 3.1.1 e confirmar que não há claim, complete ou fail pendente.
2. Parar o serviço legado e aguardar o estado `Stopped`.
3. Registrar a definição atual do serviço e o caminho do backup/receipt criado
   pela migração.
4. Alterar o serviço legado para `Disabled`.
5. Confirmar que o v4 continua em `Paused/Drain` após instalação e após reboot.
6. Executar `Start` somente com capacidade solicitada e concedida igual a 1.

Não remover o serviço, os arquivos nem o backup do 3.1.1 durante o canário.

## Gate de descoberta da frota 3.1

Antes de publicar qualquer `windows-v4.0.0`, toda a frota 3.1 suportada precisa
receber a ponte 3.1.1 descrita em `docs/worker-release-updates.md`. O inventário
observado em 2026-09-01 ainda era três nós Linux 3.1.0, um macOS 3.1.0 e um
Windows 3.1.0; esse é apenas o inventário histórico anterior à ponte. O canário
4.0 só pode começar depois que a revalidação comprovar todos esses nós em 3.1.1.

A ponte deve atualizar o dashboard compartilhado sem cancelar trabalho. Quando
o pacote do host exigir troca de processo, aplicar `Pause`, deixar os trabalhos
ativos concluírem e só então instalar; nunca usar `Stop` para essa migração. O
macOS observado em `processing` permanece intocado até finalizar o assignment e
entrar em drain. Cada nó precisa voltar com heartbeat saudável, mesma identidade
e parser que percorre a descoberta paginada
`/releases?per_page=100&page=N`, por no máximo dez páginas, antes do próximo nó.
Se a décima página ainda estiver cheia, o monitor falha fechado em vez de tratar
uma lista truncada como completa. A promoção 4.0 fica bloqueada enquanto qualquer
nó suportado continuar dependente apenas de `/releases/latest`.

Essa condição não é comprovada por checkbox, variável de workflow ou pelo
próprio operador do canário. A autoridade de telemetria exporta o snapshot
completo do inventário autoritativo do orquestrador e produz:

```text
release-evidence/fleet/3.1.1/fleet-transition-evidence.json
release-evidence/fleet/3.1.1/fleet-transition-evidence.p7s
```

O schema `hch.worker-fleet-transition/v1` não publica identificadores reais. O
`inventorySnapshotSha256` é um compromisso SHA-256 do inventário canônico com
salt aleatório de 256 bits mantido apenas no cofre de auditoria da autoridade;
nem o inventário nem o salt entram na evidência pública. Esse compromisso deriva
deterministicamente um UUIDv8
`inventorySnapshotId`; cada posição única e contígua da projeção deriva o seu
`nodeIdHash` a partir do snapshot e de `inventoryMemberIndex`. O mapeamento entre
posição e ID real permanece somente no inventário confidencial revisado pela
autoridade de telemetria. Cada nó possui um
`inventoryMembershipReceiptSha256` canônico que vincula índice, pseudônimo e
plataforma ao ID e ao hash do snapshot. A raiz inclui ainda
`inventoryProjectionSha256`, derivado da lista ordenada desses memberships. Isso
permite confrontar duas exportações do mesmo snapshot e impede trocar, remover
ou acrescentar um nó no JSON assinado sem invalidar a projeção, sem publicar os
IDs reais do inventário.

Cada elemento liga o nó à versão 3.1.1, ao protocolo
`platform-release-list/v1` e a um array ordenado `heartbeatSamples`. Cada amostra
contém `requestId`, `serverTime` aceito pelo orquestrador e receipt canônico. O
validador recalcula todos os receipts, recusa request IDs, receipts ou timestamps
duplicados e exige intervalo máximo de 120 segundos entre amostras. O primeiro e
o último heartbeat de **cada nó** precisam cobrir pelo menos sete dias; somente
registrar dois endpoints não passa, pois o intervalo entre eles seria stale.

`windowStartedAtUtc` e `windowCompletedAtUtc` não são agregados declarativos: o
validador os deriva como a interseção de todas as janelas individuais — o mais
recente dos primeiros heartbeats até o mais antigo dos últimos —, exige igualdade
exata com a raiz e requer que essa janela comum também dure ao menos sete dias.
Assim, um nó observado tardiamente não herda o histórico dos demais. A evidência
permanece utilizável por no máximo sete dias depois da conclusão derivada.

Para conter consumo hostil de memória/CPU no runner sem impedir sete dias de
heartbeats de 60 segundos, o validador limita a evidência a 128 MiB, a assinatura
detached a 1 MiB, o inventário a 64 nós, cada nó a 20.000 amostras e o documento
a 500.000 amostras. O limite individual comporta 10.081 heartbeats em sete dias
incluindo os dois extremos; os limites de frota devem ser elevados por mudança
versionada de contrato quando a operação autoritativa ultrapassá-los.

Todos os timestamps da raiz e de `heartbeatSamples` são validados no token JSON
original como string exatamente `yyyy-MM-ddTHH:mm:ss.fffZ`, antes que o
PowerShell possa convertê-los para `DateTime`; offsets equivalentes, frações com
outra precisão e valores não string são recusados. Evidência e CMS precisam ser
arquivos regulares, não reparse points, e tamanho e bytes são lidos pelo mesmo
handle bloqueado contra escrita/remoção. O signer aplica a mesma leitura e cria
o arquivo temporário com `CreateNew` antes do rename atômico.

As contagens também são derivadas do array; `observedWorkerCount` precisa
coincidir com `eligibleWorkerCount`, `legacyLatestOnlyWorkerCount` deve ser zero
e as três plataformas precisam estar representadas.

O JSON é assinado em CMS detached por um certificado pinado específico da
autoridade de telemetria. Esse certificado deve ser diferente tanto do
certificado que assina os artefatos quanto do atestador do canário Windows. A
assinatura cobre os bytes exatos; o validador recalcula os receipts de
membership, a projeção do inventário e os receipts de heartbeat, exige o
inventário completo e recusa propriedades desconhecidas, material sensível,
timestamps futuros ou evidência vencida. O workflow ainda confronta release id,
tag e commit com o estado atual do GitHub. Assim, nem o documento de frota nem a
consulta ao GitHub, isoladamente, conseguem liberar a promoção.

Os gates executáveis são:

```powershell
./scripts/windows/Test-HchWorkerBridgeRelease.ps1 `
  -BridgeSourceCommit '<COMMIT_PROTEGIDO_DA_PONTE>' `
  -CmsSignerSha1 '<SHA1_DO_SIGNER_DOS_ARTEFATOS>' `
  -CmsSignerSha256 '<SHA256_DO_SIGNER_DOS_ARTEFATOS>'

./scripts/windows/Test-HchWorkerFleetTransitionEvidence.ps1 `
  -EvidencePath release-evidence/fleet/3.1.1/fleet-transition-evidence.json `
  -EvidenceSignaturePath release-evidence/fleet/3.1.1/fleet-transition-evidence.p7s `
  -ExpectedTelemetryAuthorityThumbprint '<SHA1_DA_AUTORIDADE_DE_TELEMETRIA>' `
  -ExpectedTelemetryAuthorityCertificateSha256 '<SHA256_DA_AUTORIDADE_DE_TELEMETRIA>' `
  -ExpectedBridgeReleaseId '<ID_NUMERICO_DA_RELEASE>' `
  -ExpectedBridgeSourceCommit '<COMMIT_PROTEGIDO_DA_PONTE>'
```

Depois que a autoridade independente revisar o inventário completo, a assinatura
é criada a partir do Certificate Store, sem exportar a chave privada:

```powershell
./scripts/windows/Sign-HchWorkerFleetTransitionEvidence.ps1 `
  -EvidencePath release-evidence/fleet/3.1.1/fleet-transition-evidence.json `
  -EvidenceSignaturePath release-evidence/fleet/3.1.1/fleet-transition-evidence.p7s `
  -TelemetryAuthorityThumbprint '<SHA1_DA_AUTORIDADE_DE_TELEMETRIA>' `
  -ExpectedTelemetryAuthorityCertificateSha256 '<SHA256_DA_AUTORIDADE_DE_TELEMETRIA>' `
  -CertificateStoreLocation CurrentUser
```

O modo offline existente no validador da release-ponte é exclusivo dos testes
locais e é recusado quando `GITHUB_ACTIONS=true`. O workflow oficial não expõe
switch, input, variável ou `continue-on-error` capaz de ignorar a ponte ou a
evidência da frota.

## Gate funcional e atestação do canário

A evidência `hch.worker-windows-canary/v2` deve estar vinculada a `version`,
`sourceCommit` e `msiSha256`. O workflow não confia em contagens, gaps ou
booleanos agregados: deriva essas propriedades dos arrays assinados. A raiz e
o objeto `gates` têm shape exato e recusam propriedades desconhecidas. O gate
exige:

- instalação e reinicialização em `Paused/Drain`;
- serviço legado parado e desabilitado antes do primeiro `Start`;
- enrollment e bootstrap válidos;
- sessão sustentada de pelo menos 15 minutos, com dez ou mais objetos distintos
  em `heartbeatSamples`; cada recibo contém exatamente `requestId`, `nodeId`,
  `heartbeatAt`, `nextHeartbeatSeconds`, `capacity`, `serverTime` e
  `receiptSha256`; `capacity` contém exatamente `configuredCapacity`,
  `requestedCapacity`, `grantedCapacity`, `activeAssignments`,
  `availableSlots`, `capacityClass`, `reason` e `grantedUntil`;
- esse node heartbeat é uma projeção pública sanitizada da resposta real. Os
  objetos `workload`, `workSizing`, `claim` e `update` continuam sendo validados
  internamente pelo contrato do Worker, mas não são exportados para a evidência,
  evitando incluir assignment, lease ou conteúdo operacional;
- gap máximo derivado de 120 segundos, incluindo as bordas entre início/primeiro
  heartbeat e último heartbeat/conclusão;
- capacidade solicitada/concedida 1, nunca mais de um trabalho ativo e pelo
  menos uma observação do slot em uso;
- claim e dois ou mais recibos `progressSamples` do mesmo assignment. Cada um
  contém exatamente `assignmentId`, `observedPercent`, `observedAtUtc`,
  `requestBodySha256`, `requestProgress`, `response` e `receiptSha256`;
  `requestProgress` contém `phase`, `attempt`, `sequence` e `contentBytes`, e a
  resposta de assignment heartbeat contém exatamente `assignmentId`,
  `generationPlanHash`, `leaseExpiresAt`, `liveness`, `workSizing` e
  `serverTime`; sequência, bytes, percentual e horário devem crescer, e o mesmo
  `generationPlanHash` deve persistir até a conclusão;
- como as amostras do canário já representam progresso material, o gate exige
  `liveness.lastProgressAt` não nulo; isso é deliberadamente mais estrito que o
  DTO geral, que ainda permite `null` no estado inicial `starting`;
- uma ou mais `completions` com os campos exatos da resposta de complete:
  `assignmentId`, `generationPlanHash`, `commitAccepted=true`,
  `status=pending-review`, `automaticApproval=false`,
  `automaticPublication=false`, `replayed` e `serverTime`, além do `journal`
  local separado e de `receiptSha256`;
- uma ou mais `failures` com os campos exatos da resposta de fail:
  `assignmentId`, `generationPlanHash`, `status=failed-attempt`, `replayed` e
  `serverTime`, mais `requestErrorCode`, o `journal` local separado e
  `receiptSha256`; nenhum assignment de falha pode ser também completion;
- cada `journal` contém exatamente `schemaVersion`, `assignmentId`,
  `generationPlanHash`, `phase`, `requestId`, `requestBodySha256`,
  `draftSha256`, `lastErrorCode` e `updatedAtUtc`; completion exige fase
  `completed` e erro nulo, enquanto fail exige fase `failed` e o mesmo código
  sanitizado da requisição;
- todos os `assignmentId`, `requestId` e `receiptId` usam UUID não vazio no
  formato canônico `D`, como os contratos reais do runtime;
- ausência de conteúdo secreto e de agregados legados autodeclarados na evidência;
- `rollbackReceipt` com SHA-256 do backup e das definições anterior/restaurada,
  igualdade das definições e recibo de heartbeat 3.1.1 para o mesmo `nodeId`.

Todo `receiptSha256` é recalculado pelo validador. A forma canônica começa com
`schema=hch.worker-canary-receipt/v1`, seguida por `kind=<tipo>` e pelos campos
sanitizados em ordem fixa, uma linha `nome=valor` por campo, codificada em UTF-8
sem BOM, com LF inclusive no final. Datas são convertidas para Unix time em
milissegundos, booleanos usam `true`/`false` e valores nulos usam `~`. Qualquer
alteração nos campos ou reutilização de digest invalida a promoção.

O CMS detached é validado sobre os bytes exatos, deve ter um único signatário e
`signingTime` assinado posterior a `completedAtUtc`, no máximo 24 horas depois.
No momento da promoção, tanto `completedAtUtc` quanto `signingTime` devem estar
dentro da janela de frescor de sete dias e não podem estar mais de cinco minutos
no futuro, tolerância reservada ao skew UTC. Em cada node heartbeat, a diferença
entre `heartbeatAt` e `serverTime` é limitada separadamente a cinco segundos.
Comparações entre `serverTime` e relógios locais, como `observedAtUtc` e
`journal.updatedAtUtc`, usam a mesma tolerância geral de cinco minutos, sem
relaxar a ordem dos timestamps produzidos pelo próprio orquestrador.
O certificado do atestador é aceito somente se coincidir simultaneamente com o
thumbprint SHA-1 e o SHA-256 do certificado configurados no environment
protegido, estiver válido no `signingTime` e contiver o EKU Code Signing
`1.3.6.1.5.5.7.3.3`.

O recibo canônico, junto com o CMS, prova quais dados sanitizados o Worker
validou e quais bytes o atestador revisou e assinou. Ele **não** é uma assinatura
independente emitida pelo orquestrador; essa garantia adicional exigiria um
contrato de recibo assinado pelo próprio orquestrador.

Os `receiptSha256` atuais são compromissos de integridade, não uma raiz de
autenticidade: alguém capaz de montar capturas locais também consegue recalcular
esses hashes. A release oficial permanece bloqueada até que o orquestrador
assine os receipts, publique prova append-only equivalente, ou uma autoridade
independente exporte diretamente do datastore autoritativo e assine a projeção.
O CMS final autentica essa autoridade e os bytes revisados, mas não transforma
uma captura sintética em evento ocorrido. O script de assinatura faz apenas
preflight estrutural; a revisão da origem autoritativa não pode ser delegada a
ele.

O JSON não deve ser montado manualmente. O exportador
`scripts/windows/Export-HchWorkerCanaryEvidence.ps1` aceita somente um bundle
congelado de capturas já validadas, probes SCM, estado durável, journals reais e
receipt real de rollback. Ele abre o arquivo pelo Windows Installer, rejeitando
bytes arbitrários apenas renomeados para `.msi`, e exige ProductCode, PackageCode
e versão do produto. O bundle também deve conter a saída
`probes/msi-disposable-e2e.json` do lifecycle descartável para os mesmos bytes.
Os probes v2 correlacionam essa saída com observações independentes de SCM e
processo, `ImagePath`, hashes de Service/Tray, boot, PID e horário de início. O
exportador recalcula os receipts, rejeita arquivo desconhecido ou alterado durante
a leitura e produz bytes determinísticos sem assinatura:

```powershell
./scripts/windows/Export-HchWorkerCanaryEvidence.ps1 `
  -CaptureDirectory '<DIRETORIO_CONGELADO_DE_CAPTURAS>' `
  -EvidencePath release-evidence/windows/4.0.0/canary-evidence.json `
  -Version 4.0.0 `
  -SourceCommit '<SHA40_DO_CANDIDATO>' `
  -MsiPath '<HCH-Worker-4.0.0-win-x64.msi>'
```

O runtime C# atual ainda não persiste todo esse bundle: faltam snapshots
duráveis das respostas aceitas de node heartbeat, assignment heartbeat,
complete/fail e dos probes operacionais de restart/rollback. O lifecycle MSI já
produz ProductCode, PackageCode, `ImagePath`, hashes dos payloads e snapshot
SCM/processo; o coletor operacional deve materializar os probes v2 a partir das
APIs do Windows, sem edição manual. Enquanto um harness de canário ou sink do
runtime não produzir essas fontes reais e receipts do orquestrador com origem
autenticada, a promoção permanece bloqueada; nenhuma amostra é sintetizada.

O validador executável é `scripts/windows/Test-HchWorkerCanaryEvidence.ps1`.
Depois da exportação, revisão humana e validação, o operador assina sem exportar
a chave privada:

```powershell
./scripts/windows/Sign-HchWorkerCanaryEvidence.ps1 `
  -EvidencePath release-evidence/windows/4.0.0/canary-evidence.json `
  -EvidenceSignaturePath release-evidence/windows/4.0.0/canary-evidence.p7s `
  -AttesterThumbprint '<SHA1_DO_CERTIFICADO>' `
  -ExpectedAttesterCertificateSha256 '<SHA256_DO_CERTIFICADO>' `
  -CertificateStoreLocation CurrentUser
```

O script procura a chave no Certificate Store local, exige chave privada não
exportada pelo fluxo, EKU Code Signing e grava a assinatura de forma atômica.
Não use PFX, senha, PEM ou chave privada na evidência, no repositório ou no
workflow de promoção.

## Rollback recuperável para 3.1.1

1. Aplicar `Pause` no v4 e aguardar trabalhos ativos/reservados chegarem a zero.
2. Se o canário exigir interrupção, usar `Stop` e aguardar a reconciliação do
   `operator-stop-requested`; a parada do SCM não substitui esse passo.
3. Parar e desabilitar o serviço SCM `HchWorker` (v4).
4. Restaurar o modo `Automatic (Delayed Start)` do serviço legado a partir da
   definição/receipt preservada e iniciá-lo.
5. Confirmar identidade/nodeId, readiness, capacidade e um heartbeat aceito pelo
   orquestrador no 3.1.1, com `serverTime` posterior ao registro do
   rollback; tolerância de relógio local não pode inverter essa ordem emitida
   pelo servidor.
6. Só depois registrar o `rollbackReceipt`, seus hashes, o serviço v4
   desabilitado e o heartbeat legado aceito na evidência.

A ordem comprovada deve ser estrita: último heartbeat/outcome v4, novo boot e
novo PID SCM do v4 em Paused/Drain, resposta/validação do rollback e, por fim,
heartbeat 3.1.1 aceito.
O exportador rejeita restart posterior ao rollback, validação anterior à
resposta de rollback ou heartbeat legado que não seja posterior à validação.

Uma falha em qualquer etapa mantém a versão como candidata. A tag e o release
oficial não podem existir antes desse resultado.

## Controles administrativos obrigatórios no GitHub

- `main` como branch padrão protegida, sem push direto; antes da promoção
  oficial, a proteção deve exigir os checks estáveis `portable`, `windows` e
  `native-windows-v4`. O último sempre testa a solução C# completa, inclusive o
  bootstrapper do instalador; a ausência da aceitação organizacional do WiX só
  adia o packaging. A existência do job não prova que ele está configurado como
  required check: isso deve ser conferido na regra ativa do GitHub;
- o job unsigned acionado por push deve terminar neutro com resumo quando
  `WIX_EULA_ACCEPTED` estiver ausente, enquanto todo dispatch assinado continua
  falhando fechado sem essa variável;
- ruleset ativo para `refs/tags/windows-v*`, sem exclusões nem atores de bypass,
  com bloqueio de atualização e exclusão. A criação permanece possível, mas a
  publicação exige commit exato da `main`, candidato atestado e environment
  revisado; a variável
  `WINDOWS_RELEASE_TAG_RULESET_ENFORCED` deve ser exatamente `true` somente após
  essa configuração;
- ruleset equivalente, também sem exclusões nem bypass, para a tag de ponte
  exata `refs/tags/v3.1.1` antes de sua publicação;
- imutabilidade de releases habilitada antes de criar a ponte; o gate exige
  `isImmutable=true` tanto na consulta `latest` quanto na consulta por tag,
  pois o ruleset da tag não protege os assets anexados à release;
- environment `windows-release-signing` separado do environment
  `windows-release-promotion`, ambos com revisores exigidos;
- pins públicos `HCH_CANARY_ATTESTER_THUMBPRINT` e
  `HCH_CANARY_ATTESTER_CERTIFICATE_SHA256` no environment de promoção; alterar
  qualquer pin exige a mesma revisão administrativa da promoção;
- pins públicos independentes `HCH_FLEET_ATTESTER_THUMBPRINT` e
  `HCH_FLEET_ATTESTER_CERTIFICATE_SHA256` no mesmo environment; eles não podem
  coincidir com os pins do canário ou do signer dos artefatos;
- secrets de assinatura disponíveis apenas no primeiro environment;
- permissões do workflow de promoção limitadas a leitura de Actions/attestation
  e escrita de Contents apenas no job protegido.

Antes de habilitar a promoção, o inventário publicado também deve ser alinhado
ao `SHA256SUMS.txt`: todo arquivo referenciado pelo checksum precisa ser
publicado ou o pipeline deve produzir um manifesto público separado, assinado e
verificado, que cubra exatamente os assets expostos. Um checksum que referencia
provenance, SBOM ou evidência não publicada não constitui um inventário público
reproduzível.

## Forma abreviada da evidência sanitizada

O trecho abaixo documenta a forma, mas é propositalmente abreviado e **não passa
no gate**: a evidência real precisa de no mínimo dez heartbeats únicos, hashes
SHA-256 reais e todas as amostras obtidas da sessão observada.

```json
{
  "schema": "hch.worker-windows-canary/v2",
  "status": "passed",
  "sanitized": true,
  "version": "4.0.0",
  "sourceCommit": "0000000000000000000000000000000000000000",
  "msiSha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "installationReceipt": {
    "msiLifecycleEvidenceSha256": "<sha256-real-do-lifecycle-msi>",
    "productCode": "{00000000-0000-0000-0000-000000000000}",
    "packageCode": "{00000000-0000-0000-0000-000000000000}",
    "serviceName": "HchWorker",
    "serviceImagePath": "C:\\Program Files\\HubTech\\HCH Worker\\4\\Service\\Hch.Worker.Service.exe",
    "serviceExecutableSha256": "<sha256-real-do-service>",
    "trayExecutablePath": "C:\\Program Files\\HubTech\\HCH Worker\\4\\Tray\\Hch.Worker.Tray.exe",
    "trayExecutableSha256": "<sha256-real-do-tray>",
    "installed": {
      "bootStartedAtUtc": "2026-09-01T10:00:00.000Z",
      "processStartedAtUtc": "2026-09-01T11:59:40.000Z",
      "observedAtUtc": "2026-09-01T11:59:50.000Z",
      "processId": 4100
    },
    "restart": {
      "bootStartedAtUtc": "2026-09-01T12:50:00.000Z",
      "processStartedAtUtc": "2026-09-01T12:50:10.000Z",
      "observedAtUtc": "2026-09-01T12:50:20.000Z",
      "processId": 4200
    },
    "receiptSha256": "<sha256-real-do-recibo-canonico>"
  },
  "startedAtUtc": "2026-09-01T12:00:00.0000000+00:00",
  "completedAtUtc": "2026-09-01T13:00:00.0000000+00:00",
  "gates": {
    "installedPausedDrain": true,
    "legacyServiceStoppedDisabled": true,
    "enrollment": true,
    "bootstrap": true,
    "claim": true,
    "restartPausedDrain": true
  },
  "heartbeatSamples": [
    {
      "requestId": "10000000-0000-4000-8000-000000000001",
      "nodeId": "windows-canary-node-0001",
      "heartbeatAt": "2026-09-01T12:01:00.0000000+00:00",
      "nextHeartbeatSeconds": 60,
      "capacity": {
        "configuredCapacity": 1,
        "requestedCapacity": 1,
        "grantedCapacity": 1,
        "activeAssignments": 1,
        "availableSlots": 0,
        "capacityClass": "canary",
        "reason": "canary",
        "grantedUntil": "2026-09-01T12:31:00.0000000+00:00"
      },
      "serverTime": "2026-09-01T12:01:00.0000000+00:00",
      "receiptSha256": "<sha256-real-do-recibo-canonico>"
    }
  ],
  "progressSamples": [
    {
      "assignmentId": "11111111-1111-4111-8111-111111111111",
      "observedPercent": 10,
      "observedAtUtc": "2026-09-01T12:02:00.0000000+00:00",
      "requestBodySha256": "<sha256-real-do-corpo-da-requisicao>",
      "requestProgress": {
        "phase": "responding",
        "attempt": 1,
        "sequence": 1,
        "contentBytes": 1024
      },
      "response": {
        "assignmentId": "11111111-1111-4111-8111-111111111111",
        "generationPlanHash": "<sha256-real-do-plano>",
        "leaseExpiresAt": "2026-09-01T12:32:00.0000000+00:00",
        "liveness": {
          "state": "responding",
          "lastProgressAt": "2026-09-01T12:02:00.0000000+00:00",
          "staleAfterSeconds": 300
        },
        "workSizing": {
          "currentTier": "small",
          "currentRank": 1,
          "reason": "within-window"
        },
        "serverTime": "2026-09-01T12:02:00.0000000+00:00"
      },
      "receiptSha256": "<sha256-real-do-recibo-canonico>"
    }
  ],
  "completions": [
    {
      "assignmentId": "11111111-1111-4111-8111-111111111111",
      "generationPlanHash": "<sha256-real-do-plano>",
      "commitAccepted": true,
      "status": "pending-review",
      "automaticApproval": false,
      "automaticPublication": false,
      "replayed": false,
      "serverTime": "2026-09-01T12:08:00.0000000+00:00",
      "journal": {
        "schemaVersion": 1,
        "assignmentId": "11111111-1111-4111-8111-111111111111",
        "generationPlanHash": "<sha256-real-do-plano>",
        "phase": "completed",
        "requestId": "30000000-0000-4000-8000-000000000001",
        "requestBodySha256": "<sha256-real-do-corpo-da-requisicao>",
        "draftSha256": "<sha256-real-do-draft>",
        "lastErrorCode": null,
        "updatedAtUtc": "2026-09-01T12:08:01.0000000+00:00"
      },
      "receiptSha256": "<sha256-real-do-recibo-canonico>"
    }
  ],
  "failures": [
    {
      "assignmentId": "22222222-2222-4222-8222-222222222222",
      "generationPlanHash": "<sha256-real-do-plano>",
      "status": "failed-attempt",
      "replayed": false,
      "serverTime": "2026-09-01T12:10:00.0000000+00:00",
      "requestErrorCode": "canary-controlled-generation-failure",
      "journal": {
        "schemaVersion": 1,
        "assignmentId": "22222222-2222-4222-8222-222222222222",
        "generationPlanHash": "<sha256-real-do-plano>",
        "phase": "failed",
        "requestId": "40000000-0000-4000-8000-000000000001",
        "requestBodySha256": "<sha256-real-do-corpo-da-requisicao>",
        "draftSha256": null,
        "lastErrorCode": "canary-controlled-generation-failure",
        "updatedAtUtc": "2026-09-01T12:10:01.0000000+00:00"
      },
      "receiptSha256": "<sha256-real-do-recibo-canonico>"
    }
  ],
  "rollbackReceipt": {
    "receiptId": "60000000-0000-4000-8000-000000000001",
    "serverTime": "2026-09-01T12:55:00.0000000+00:00",
    "targetVersion": "3.1.1",
    "v4ServiceDisabled": true,
    "legacyServiceStartMode": "AutomaticDelayed",
    "backupSha256": "<sha256-real-do-backup>",
    "previousServiceDefinitionSha256": "<sha256-real-da-definicao>",
    "restoredServiceDefinitionSha256": "<mesmo-sha256-real-da-definicao>",
    "legacyHeartbeat": {
      "workerVersion": "3.1.1",
      "requestId": "50000000-0000-4000-8000-000000000001",
      "nodeId": "windows-canary-node-0001",
      "heartbeatAt": "2026-09-01T12:56:00.0000000+00:00",
      "nextHeartbeatSeconds": 60,
      "capacity": {
        "configuredCapacity": 1,
        "requestedCapacity": 0,
        "grantedCapacity": 0,
        "activeAssignments": 0,
        "availableSlots": 0,
        "capacityClass": "legacy",
        "reason": "rollback",
        "grantedUntil": null
      },
      "serverTime": "2026-09-01T12:56:00.0000000+00:00",
      "receiptSha256": "<sha256-real-do-recibo-canonico>"
    },
    "receiptSha256": "<sha256-real-do-recibo-canonico>"
  }
}
```
