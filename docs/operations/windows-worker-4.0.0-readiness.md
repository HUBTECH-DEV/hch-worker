# Readiness de disponibilização do HCH Worker Windows 4.0.0

## Objetivo e classificação

Este runbook separa o que pode ser concluído no desenvolvimento do que exige
uma autoridade, infraestrutura ou evidência operacional externa. Enquanto a
última etapa não for concluída, `4.0.0` significa **candidato Windows**. Não
significa versão estável, release oficial ou autorização para tornar o Worker
3.1.0 histórico.

O produto Windows contém um único serviço SCM, o tray, a Central de Controle,
o onboarding e o bootstrap. O runtime instalado é C#/.NET 10 autocontido e não
depende de PowerShell, Node.js nem terminal aberto. Instalação, upgrade,
recuperação e conclusão do onboarding mantêm o Worker em `Paused/Drain` e com
capacidade zero até um `Start` explícito.

## Estado preparado pelo desenvolvimento

- solução nativa versionada em `4.0.0`, com Service, Core, Protocol, Security,
  Persistence, Ollama, IPC, Tray, Installer e testes separados;
- IPC local `Hch.Worker.Control.v2`, protegido por ACL e autorização por SID;
- concorrência real por slots, com `MaxConcurrentJobs`, `ClaimBatchSize` e
  `GrantedCapacity` independentes;
- `Pause` drena sem cancelar, `Stop` cancela e reconcilia
  `operator-stop-requested`, e a parada SCM permanece distinta;
- heartbeat, claim, progresso, complete/fail, journals e recuperação
  idempotente preservam os contratos públicos;
- dashboard nativo com estados de serviço/operação separados, capacidade,
  jobs, progresso, métricas, GPU quando comprovável, histórico agregado, logs
  sanitizados, tema e acessibilidade;
- onboarding por HIH/PKCE ou contrato nativo homologado, chave SSH Ed25519 do
  usuário separada da identidade operacional do Worker e enrollment efêmero;
- MSI WiX por máquina, migração 3.1 transacional, rollback seletivo e dados
  persistentes fora dos binários versionados;
- declaração humana revisada `src/windows/release-compatibility.json`,
  versionada e incorporada a hashes, provenance e notas da release, sem campo
  manual de compatibilidade no `workflow_dispatch`; ela não substitui o
  `contentContractHash`, o relatório de compatibilidade nem o canário real;
- workflows separados para CI, candidato Windows, ponte 3.1.1 e promoção,
  sempre fail-closed para assinatura e publicação.

## Gate local de fonte

Executar em PowerShell 7, na raiz do repositório:

```powershell
dotnet tool restore
dotnet restore src/windows/Hch.Worker.sln `
  --locked-mode --runtime win-x64 -p:PublishReadyToRun=true
dotnet format src/windows/Hch.Worker.sln --verify-no-changes --no-restore
dotnet build src/windows/Hch.Worker.sln `
  --configuration Release --no-restore
dotnet test src/windows/Hch.Worker.sln `
  --configuration Release --no-restore
./scripts/windows/Test-HchWorkerDependencies.ps1 `
  -SolutionPath src/windows/Hch.Worker.sln `
  -EvidencePath artifacts/windows-v4/ci/dependency-vulnerability-scan.json
./scripts/windows/Test-HchWorkerInstallerSource.ps1
./scripts/windows/Test-HchWorkerReleaseWorkflow.ps1
npm run test:windows
```

O gate deve terminar sem warning de compilação, teste falho, lock file alterado
ou diff de formatação. Um timeout causado por saturação do host deve ser
reproduzido isoladamente antes de ser classificado; nunca deve ser ignorado no
CI oficial.

O contrato externo do onboarding é um gate separado, executado contra produção:

```powershell
./scripts/windows/Test-HchWorkerOnboardingEndpoints.ps1
```

Ele exige discovery HIH/HAH compatível e as rotas protegidas de challenge e
enrollment do HCH. Respostas `404`, redirects, schema inesperado ou origem fora
do HAH bloqueiam a promoção. Em 2 de setembro de 2026, essas rotas de produção
ainda respondiam `404`; portanto, o código pode ficar pronto para candidato,
mas a disponibilização utilizável permanece condicionada ao deploy e à
configuração dessas contrapartes.

## Build não publicável para engenharia

Aceitar a licença WiX não é uma decisão de código. Depois de a organização
revisar os termos e registrar `WIX_EULA_ACCEPTED=wix7`, pode-se produzir um MSI
local sem assinatura, claramente não publicável:

```powershell
./scripts/windows/Build-HchWorkerPackage.ps1 `
  -Version 4.0.0 `
  -ReleaseIntent Candidate `
  -AcceptWixEula `
  -AllowUnsigned `
  -AllowUnpinnedCandidate
```

Esse artefato serve para UI, instalação descartável e diagnóstico. Ele não é
confiável para distribuição e não pode ser renomeado como release.

## Configuração administrativa necessária no GitHub

Antes de gerar um candidato assinável:

1. Proteger a `main` e exigir os checks `portable`, `windows` e
   `native-windows-v4`.
2. Registrar a aceitação revisada como variável
   `WIX_EULA_ACCEPTED=wix7`.
3. Criar os environments `windows-release-signing` e
   `windows-release-promotion`, com revisores distintos e sem bypass.
4. Criar `bridge-release-signing` e `bridge-release-promotion` com a mesma
   separação de funções.
5. Configurar somente como variáveis públicas os pins da raiz, do signer, do
   atestador de canário e da autoridade de telemetria.
6. Manter PFX/senha apenas como secrets do environment de assinatura, ou usar
   HSM/Certificate Store; nunca armazenar chave privada no repositório.
7. Configurar URL de timestamp RFC 3161 e certificado Authenticode de
   organização com EKU Code Signing.
8. Proteger `refs/tags/v3.1.1` e `refs/tags/windows-v*`, bloquear alteração e
   exclusão e habilitar imutabilidade de releases.

Os nomes e o comportamento exatos dessas variáveis estão nos workflows e em
`windows-worker-v4-installer.md`. Definir uma variável como `true` não substitui
a regra administrativa correspondente: a regra precisa ser conferida no
GitHub.

## Sequência do candidato assinável

1. Integrar o código revisado na `main` protegida.
2. Publicar primeiro a ponte genérica 3.1.1 pelo workflow
   `Build and publish compatibility bridge 3.1.1`.
3. Revalidar a frota 3.1 e coletar evidência autoritativa de que todos os nós
   suportados passaram a descobrir releases por sistema operacional.
4. Executar `Windows package` com `signed=true` e
   `run_disposable_msi_e2e=true`.
5. O pipeline restaura em locked mode, testa, faz SCA, assina apenas o
   allowlist, gera MSI, executa o lifecycle descartável, escaneia com Defender,
   produz SBOM/provenance/checksums e atesta os bytes exatos.
6. Preservar o `run id`, o nome do artefato e o SHA-256 do MSI; não recompilar
   nem reempacotar depois do canário.

## Canário operacional obrigatório

O canário é executado em host descartável ou dedicado, nunca neste notebook de
desenvolvimento, com os seguintes controles:

- registrar SHA-256, ProductCode/PackageCode, `ImagePath` e hashes dos binários
  instalados antes de aceitar a prova de instalação;
- instalar em `Paused/Drain`, reiniciar o host e provar nova sessão/boot e novo
  processo SCM ainda pausado;
- concluir HIH, chave pública, enrollment, bootstrap, trust e readiness;
- desabilitar o serviço legado somente depois de drenado, preservando arquivos
  e definição para rollback;
- usar paralelismo 1 por no mínimo 15 minutos e registrar ao menos dez
  heartbeats, claim, progresso material, complete aceito e fail controlado;
- obter receipts assinados pelo orquestrador, prova append-only equivalente ou
  exportação direta do datastore autoritativo por autoridade independente;
- voltar operacionalmente ao 3.1.1 e comprovar o mesmo `nodeId`, definição do
  serviço restaurada e heartbeat aceito depois do rollback;
- assinar a evidência sanitizada com o certificado pinado do atestador, separado
  do signer dos artefatos e da autoridade da frota.

O exportador agora rejeita arquivo-texto renomeado para `.msi` e exige a
correlação do lifecycle descartável, ProductCode/PackageCode, `ImagePath`, hashes,
boot, PID e SCM. Capturas locais continuam sem provar que o orquestrador aceitou
os eventos; enquanto receipts assinados, prova append-only ou exportação direta
do datastore autoritativo não existirem, a promoção deve permanecer bloqueada.

## Promoção e rollback

Somente depois de todos os gates:

1. criar a tag anotada e protegida `windows-v4.0.0` no commit exato que gerou o
   candidato;
2. executar `Promote Windows candidate` informando somente os identificadores
   imutáveis do candidato; compatibilidade e impacto são lidos do conjunto
   assinado;
3. publicar os mesmos bytes, com todo o inventário checksummed, usando
   `--latest=false` durante a janela da ponte;
4. manter o 3.1.1 recuperável até a validação sustentada da frota;
5. só então alterar a classificação do 3.1.1 para histórica. O 3.1.0 é apenas a
   versão histórica anterior à ponte.

Falha de bootstrap, trust, heartbeat, conteúdo, assinatura, EDR ou rollback
interrompe a promoção. `Pause` é usado para drenagem normal; `Stop` é reservado
para cancelamento explícito, reportado e reconciliado.

## Resultado esperado desta fase

Ao concluir os gates locais e enviar a branch do dispositivo, o estado correto
é **fonte 4.0.0 pronta para revisão e geração de candidato**. Os itens restantes
— licença WiX, configuração dos environments, certificado, assinatura,
instalação descartável, canário, receipts autoritativos, tag e release — são
ações externas deliberadamente separadas e não podem ser simuladas pelo
desenvolvimento.
