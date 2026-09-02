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
3. **Rollback** — o mesmo canário precisa provar a volta operacional ao 3.1.0.
   Desinstalar o v4 não substitui essa prova.
4. **Evidência revisada** — somente dados sanitizados são adicionados em
   `release-evidence/windows/<versão>/canary-evidence.json` na `main` protegida.
5. **Tag protegida** — depois do canário e da revisão da evidência, criar uma tag
   anotada `windows-v<versão>` apontando para o commit que produziu o candidato,
   não para o commit posterior que adicionou a evidência.
6. **Promoção** — o workflow `Promote Windows candidate` baixa o artefato do run
   original, verifica assinaturas, checksums, attestation, evidência de canário e
   rollback, e publica os mesmos bytes.

## Gate de exclusividade 3.1/v4

A migração preserva os arquivos, a identidade e a definição do serviço 3.1.0.
O serviço v4 inicia em `Paused/Drain` e recusa `Start` ou paralelismo positivo
enquanto o serviço legado não estiver simultaneamente **Stopped** e
**Disabled**. `Pause`, `Stop` e paralelismo zero continuam disponíveis.

Antes do canário:

1. Drenar o 3.1.0 e confirmar que não há claim, complete ou fail pendente.
2. Parar o serviço legado e aguardar o estado `Stopped`.
3. Registrar a definição atual do serviço e o caminho do backup/receipt criado
   pela migração.
4. Alterar o serviço legado para `Disabled`.
5. Confirmar que o v4 continua em `Paused/Drain` após instalação e após reboot.
6. Executar `Start` somente com capacidade solicitada e concedida igual a 1.

Não remover o serviço, os arquivos nem o backup do 3.1.0 durante o canário.

## Gate funcional do canário

A evidência `hch.worker-windows-canary/v1` deve estar vinculada a `version`,
`sourceCommit` e `msiSha256` e provar:

- instalação e reinicialização em `Paused/Drain`;
- serviço legado parado e desabilitado antes do primeiro `Start`;
- enrollment e bootstrap válidos;
- pelo menos dois heartbeats do v4;
- capacidade solicitada/concedida 1 e no máximo um trabalho ativo;
- claim, dois ou mais sinais de progresso crescente e conclusão em
  `pending-editorial-review`;
- ausência de stall e de conteúdo secreto na evidência;
- rollback recuperável para o 3.1.0 e novo heartbeat do legado.

O validador executável é `scripts/windows/Test-HchWorkerCanaryEvidence.ps1`.

## Rollback recuperável para 3.1.0

1. Aplicar `Pause` no v4 e aguardar trabalhos ativos/reservados chegarem a zero.
2. Se o canário exigir interrupção, usar `Stop` e aguardar a reconciliação do
   `operator-stop-requested`; a parada do SCM não substitui esse passo.
3. Parar e desabilitar o serviço SCM `HchWorker` (v4).
4. Restaurar o modo `Automatic (Delayed Start)` do serviço legado a partir da
   definição/receipt preservada e iniciá-lo.
5. Confirmar identidade/nodeId, readiness, capacidade e um heartbeat aceito pelo
   orquestrador no 3.1.0.
6. Só depois registrar `rollbackTo310=true`, `rollbackHeartbeat=true` e
   `v4ServiceDisabled=true` na evidência.

Uma falha em qualquer etapa mantém a versão como candidata. A tag e o release
oficial não podem existir antes desse resultado.

## Controles administrativos obrigatórios no GitHub

- `main` como branch padrão protegida, com CI obrigatório e sem push direto;
- ruleset ativo para `refs/tags/windows-v*`, com as regras de restrição de
  criação, atualização e exclusão fora do grupo de release; a variável
  `WINDOWS_RELEASE_TAG_RULESET_ENFORCED` deve ser exatamente `true` somente após
  essa configuração;
- environment `windows-release-signing` separado do environment
  `windows-release-promotion`, ambos com revisores exigidos;
- secrets de assinatura disponíveis apenas no primeiro environment;
- permissões do workflow de promoção limitadas a leitura de Actions/attestation
  e escrita de Contents apenas no job protegido.

## Exemplo mínimo de evidência sanitizada

```json
{
  "schema": "hch.worker-windows-canary/v1",
  "status": "passed",
  "sanitized": true,
  "version": "4.0.0",
  "sourceCommit": "0000000000000000000000000000000000000000",
  "msiSha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "startedAtUtc": "2026-09-01T12:00:00.0000000+00:00",
  "completedAtUtc": "2026-09-01T13:00:00.0000000+00:00",
  "gates": {
    "installedPausedDrain": true,
    "legacyServiceStoppedDisabled": true,
    "enrollment": true,
    "bootstrap": true,
    "heartbeat": true,
    "claim": true,
    "progress": true,
    "completedPendingEditorialReview": true,
    "restartPausedDrain": true,
    "rollbackTo310": true,
    "rollbackHeartbeat": true
  },
  "heartbeats": { "count": 2 },
  "capacity": { "requested": 1, "granted": 1, "maxActiveObserved": 1 },
  "progress": { "samples": 2, "firstPercent": 5, "lastPercent": 100, "stalled": false },
  "rollback": {
    "targetVersion": "3.1.0",
    "v4ServiceDisabled": true,
    "legacyServiceStartMode": "AutomaticDelayed"
  }
}
```
