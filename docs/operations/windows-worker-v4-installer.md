# Instalador do HCH Worker 4 para Windows

## Escopo e estado da versão

O instalador Windows 4 é um MSI x64 por máquina, produzido com WiX Toolset
7. Ele contém o Windows Service, o tray, o bootstrap de primeiro uso e o
runtime .NET 10 autocontido. O produto registra exatamente um serviço SCM,
`HchWorker`; o tray é iniciado no logon e não cria outro serviço nem abre um
terminal.

Esta entrega não torna a versão 3.1.0 histórica. Essa promoção depende do
canário operacional completo da versão 4 e é uma decisão posterior.

## Layout instalado

- Binários versionados: `%ProgramFiles%\HubTech\HCH Worker\4`.
- Dados persistentes: `%ProgramData%\HubTech\HCH Worker`.
- Serviço: `HchWorker`, LocalSystem, início automático atrasado, SID de serviço
  `unrestricted` e três tentativas de recuperação com reinício após falha.
- Tray: `Hch.Worker.Tray.exe`, iniciado por `HKLM\...\Run` no logon.

O MSI nunca remove `%ProgramData%\HubTech\HCH Worker` durante desinstalação ou
major upgrade. Identidade, configuração, journals, trust e evidências ficam
fora dos componentes binários versionados.

## Primeiro boot seguro

Antes de iniciar o serviço, uma ação do próprio produto Installer:

1. recebe o SID do proprietário local;
2. rejeita `SYSTEM`, `LocalService` e `NetworkService` como proprietário;
3. gera uma identidade operacional Ed25519 exclusiva do Worker;
4. grava a chave privada somente como PKCS#8 protegido por DPAPI LocalMachine;
5. usa o fingerprint da chave pública exatamente como `keyId`;
6. cria `config.json` com capacidade inicial 1 e estado operacional
   `Paused/Drain` — nenhum claim é iniciado automaticamente;
7. restringe `state` ao SID do serviço, SYSTEM e Administradores e concede ao
   proprietário somente leitura do `config.json`.

O modo `fresh` é uma propriedade privada do MSI. Antes do marcador ou de
qualquer chave, o bootstrap remove herança do diretório do produto, aplica ACL
protegida e exige que ele esteja vazio. Arquivo, diretório ou `config.json`
pré-criado causa `installer-target-preinitialized-refused`. O modo `upgrade` só
é selecionado por `WIX_UPGRADE_DETECTED` e valida duas vezes configuração,
ACLs, DPAPI, fingerprint, paths e trust já existentes antes de preservá-los.

Os pins de trust são sempre all-or-none no `config.json`:
`rootKeyId`, `rootPublicKeyFingerprint` (`SHA256:` + base64url) e
`rootPublicKeyPath`. Em uma máquina com o Worker 3.1, a presença de
`%ProgramData%\HCH\EditorialWorker` muda o bootstrap para o modo de migração:
ele não pode criar novo `nodeId` ou nova identidade.

O preflight deriva o nome do serviço legado a partir do `nodeId`, exige SCM
`Stopped`, PID zero, locks de escrita disponíveis, ausência de assignment ativo
e ausência de `complete`/`fail`/lease sem reconciliação. O PSD1 é lido como
dados, sem carregar ou executar PowerShell. `identity.json`, a pública SPKI e a
privada PKCS#8 PEM precisam coincidir exatamente em `nodeId`, `keyId`,
fingerprint e prova do par Ed25519. A privada é então normalizada e protegida
por DPAPI `LocalMachine`; nenhum PEM privado aparece em configuração, journal,
stdout ou log.

Antes de publicar o destino, o migrador cria um backup write-once de
`config/state/trust`, com hashes, ACLs e receipt da definição SCM, e repete o
inventário/preflight para detectar qualquer escritor concorrente. O PEM público
raiz é recalculado e conferido contra o pin legado. `ready.json`,
`applied-manifest.json`, `trust-state.json`, enrollment, receipts e journals do
3.1 ficam somente no backup: o v4 não afirma que esse estado foi importado e
refaz bootstrap/atestação em `Paused/Drain`.

Em instalação nova, a release oficial leva o mesmo PEM público como payload do
MSI assinado, junto dos pins validados no build. Não há TOFU, download de chave
ou descoberta de confiança pela rede. Um candidato de engenharia pode omitir
os três pins apenas por opção explícita; nesse caso o serviço inicia
`NotReady + Paused/Drain` e não faz bootstrap, claim ou processamento.

O bootstrap usa um marcador e um journal transacionais. `config.json` é o
último artefato publicado. Em rollback, remove somente configuração, identidade
protegida e cópia pública de trust que o journal prova terem sido criadas pela
migração e que ainda mantêm o hash registrado. Backup, origem legada e arquivos
não relacionados nunca são removidos. Em upgrade ou reparo, uma migração já
`Committed` é validada e retorna idempotentemente sem reescrever identidade ou
configuração.

O SID padrão vem da propriedade Windows Installer `UserSID`, que continua
disponível durante a parte elevada da instalação. A validação com UAC usando
credenciais administrativas de outra pessoa (over-the-shoulder) permanece um
caso obrigatório do teste de instalador. Em GPO, RMM, execução como SYSTEM ou
instalação silenciosa, sempre informe explicitamente o SID do usuário que será
o proprietário.

## Build local

O WiX 7 exige aceitação explícita de sua EULA/OSMF. A organização deve revisar
e cumprir esses termos antes de usar `-AcceptWixEula`.

Build de candidato não publicável, sem certificado:

```powershell
.\scripts\windows\Build-HchWorkerPackage.ps1 `
  -Version 4.0.0 `
  -ReleaseIntent Candidate `
  -AcceptWixEula `
  -AllowUnsigned `
  -AllowUnpinnedCandidate
```

O build nunca recebe material de assinatura. Um candidato assinável começa na
`main` limpa e protegida, antes de qualquer tag. Ele produz uma preparação
testada e presa ao commit:

```powershell
$rootPem = 'C:\trusted-offline\orchestrator-root.pem'
.\scripts\windows\Build-HchWorkerPackage.ps1 `
  -Version 4.0.0 `
  -ReleaseIntent Candidate `
  -SourceRef refs/heads/main `
  -AcceptWixEula `
  -AllowUnsigned `
  -RequireDefender `
  -RootPublicKeyPath $rootPem `
  -RootPublicKeyFingerprint 'SHA256:<43-caracteres-base64url>' `
  -RootKeyId '<id-publicado-da-raiz>'
```

As etapas seguintes são deliberadamente separadas. O thumbprint SHA-1 e o hash
SHA-256 do certificado são política pública revisada. A variável com chave/PFX
existe somente durante cada chamada de `Sign-HchWorkerArtifacts.ps1`; nenhum
restore, teste, publish, WiX, bootstrap ou produto é executado nesse limite:

```powershell
$signerThumbprint = '<SHA-1 de 40 hex revisado>'
$signerCertificateSha256 = '<SHA-256 de 64 hex revisado>'
$timestamp = 'http://timestamp.digicert.com'

# HSM/Certificate Store: defina apenas nesta etapa. O script limpa a variável.
$env:HCH_SIGN_CERT_THUMBPRINT = $signerThumbprint
.\scripts\windows\Sign-HchWorkerArtifacts.ps1 `
  -Stage Payloads -Version 4.0.0 `
  -ExpectedSignerThumbprint $signerThumbprint `
  -ExpectedSignerCertificateSha256 $signerCertificateSha256 `
  -TimestampUrl $timestamp

.\scripts\windows\Repack-HchWorkerPackage.ps1 `
  -Version 4.0.0 `
  -ExpectedSignerThumbprint $signerThumbprint `
  -ExpectedSignerCertificateSha256 $signerCertificateSha256 `
  -AcceptWixEula -RequireDefender

$env:HCH_SIGN_CERT_THUMBPRINT = $signerThumbprint
.\scripts\windows\Sign-HchWorkerArtifacts.ps1 `
  -Stage Msi -Version 4.0.0 `
  -ExpectedSignerThumbprint $signerThumbprint `
  -ExpectedSignerCertificateSha256 $signerCertificateSha256 `
  -TimestampUrl $timestamp
```

O teste `Invoke-HchWorkerMsiDisposableTest.ps1` instala e remove o produto. Ele
somente aceita um GitHub-hosted runner ou uma VM marcada com autorização
expirável de no máximo 24 horas, exige elevação e a frase de confirmação exata.
Não o execute em notebook, servidor, estação de desenvolvimento ou máquina com
qualquer Worker/estado legado. Todo candidato assinado exige a evidência desse
harness antes de `Complete-HchWorkerReleaseEvidence.ps1`; em seguida assina
`SHA256SUMS.txt` com `-Stage Evidence` e valida o conjunto por
`Test-HchWorkerReleaseEvidence.ps1 -RequireCandidate`.

Esse conjunto ainda não é oficial. O canário instala exatamente o MSI pelo
hash, prova reboot em `Paused/Drain` e rollback ao 3.1.0, e registra a evidência
sanitizada na `main`. Somente depois é criada a tag anotada e protegida apontando
para o commit do candidato. O workflow `Promote Windows candidate` baixa o
artefato do run original e publica os mesmos bytes, sem build, repack ou nova
assinatura. O procedimento completo está em
`docs/operations/windows-worker-v4-promotion.md`.

Quando não houver chave em HSM/Certificate Store, `HCH_SIGN_PFX_BASE64` e
`HCH_SIGN_PFX_PASSWORD` são aceitos somente no processo isolado de assinatura.
O PFX é importado como não exportável, o buffer é zerado, o arquivo temporário e
os certificados temporários são removidos no `finally`, e a senha nunca vira
argumento de processo. O fallback sem `signtool.exe` usa
`Set-AuthenticodeSignature`, ainda exigindo SHA-256, timestamp e o signer exato.

O pipeline:

- restaura pacotes em locked mode;
- executa os testes .NET, incluindo fixtures sintéticas da migração 3.1.0,
  bloqueios de reconciliação, idempotência e rollback seletivo;
- publica Service e Tray como `win-x64`, self-contained, sem trimming ou
  single-file e com ReadyToRun;
- publica o bootstrap self-contained single-file;
- executa o autoteste do bootstrap via assembly (sem pedir UAC para esse gate
  não mutante), incluindo DPAPI, igualdade fingerprint/`keyId`, trust Ed25519
  out-of-band, upgrade sem sobrescrita e rollback seletivo;
- bloqueia release assinada sem PEM/pins oficiais ou quando o fingerprint
  recalculado não coincide;
- rejeita qualquer segredo de assinatura durante restore, teste e publish;
- assina somente EXEs/DLLs first-party presentes no allowlist hashado;
- compila e valida as tabelas do MSI;
- prova as três linhas de comando do bootstrap com `CommandLineToArgvW`;
- assina e valida o MSI contra thumbprint e hash do certificado;
- executa SCA, Defender e o lifecycle MSI em runner descartável;
- gera provenance com signer, SBOM SPDX 2.2, hashes, assinatura CMS destacada e
  attestation do GitHub para o candidato imutável.

O check `native-windows-v4` restaura e testa a solução C# em todo pull request e
em cada push na `main`, mesmo
quando a organização ainda não registrou `WIX_EULA_ACCEPTED=wix7`. Nessa
situação, somente os passos que restauram o binário WiX ou produzem MSI são
adiados; o job unsigned de `Windows package` publica um resumo neutro em vez de
deixar a `main` vermelha. Um dispatch assinado continua fail-closed: sem a
aceitação revisada do WiX, root trust, assinatura e lifecycle descartável não
há candidato assinável nem promoção.

Saída: `artifacts\windows-v4\release`.

## Instalação

Interativa, mantendo log completo:

```powershell
msiexec.exe /i .\HCH-Worker-4.0.0-win-x64.msi /l*v .\hch-worker-install.log
```

Silenciosa com proprietário explícito:

```powershell
$ownerSid = 'S-1-5-21-...'
msiexec.exe /i .\HCH-Worker-4.0.0-win-x64.msi `
  /qn HCH_OWNER_SID="$ownerSid" `
  /l*v .\hch-worker-install.log
```

O SID pode ser obtido na sessão do usuário alvo com:

```powershell
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

Não derive o proprietário a partir da conta administrativa usada somente para
aceitar o UAC.

## Upgrade e rollback

Versões MSI 4.x compartilham a família `HubTech.HchWorker.Windows.V4`. O major
upgrade é executado dentro da transação MSI com
`RemoveExistingProducts=afterInstallInitialize`; se a instalação falhar, o
Windows Installer restaura a versão 4 anterior. O `ServiceControl` espera a
parada e a inicialização do serviço.

Antes de `InstallInitialize` e do `RemoveExistingProducts`, o binário de
preflight embutido pede ao serviço uma trava de manutenção. Ela força
`Paused/Drain`, bloqueia novos `Start`/paralelismo positivo até o próximo start
do SCM e exige zero trabalhos ativos/reservados. O MSI também recusa pending
claim, recovery protegida ou journal que não esteja terminal e reconciliado.
Se o serviço não responder autenticamente, o upgrade/desinstalação falha
fechado em vez de interromper trabalho por baixo do runtime.

Após um upgrade já concluído, o rollback controlado é:

1. colocar o Worker em Drain/Pause e comprovar ausência de trabalho ativo ou
   complete/fail não reconciliado;
2. guardar o log MSI e o hash do estado persistente;
3. desinstalar o MSI atual;
4. instalar o MSI anterior, assinado e com hash previamente aprovado;
5. confirmar que `config.json`, identidade, journals e trust permaneceram;
6. iniciar canário com paralelismo 1.

Na primeira troca 3.1.0 → 4.x, o receipt em
`%ProgramData%\HubTech\HCH Worker\state\migration-backups` e o journal em
`state\migration\legacy-windows-v3.json` são a fonte do rollback seletivo. Uma
divergência de hash exige intervenção; o instalador nunca apaga um arquivo
alterado para forçar o retorno.

O MSI não desativa nem remove automaticamente o Worker 3.1.0 legado. O v4
recusa `Start` e paralelismo positivo enquanto o serviço derivado do mesmo
`nodeId` não estiver `Stopped + Disabled`, inclusive se o diretório legado tiver
sido removido mas o serviço ainda estiver registrado. A troca do serviço antigo
e a classificação 3.1.0 como histórica pertencem ao rollout canário, não ao
build do pacote.

## Gates externos

Uma release pública exige, além do código:

- certificado Authenticode de organização válido e com cadeia confiável;
- timestamp RFC 3161 disponível;
- cumprimento da EULA/OSMF do WiX 7;
- teste de instalação limpa, upgrade, rollback, desinstalação, reboot e UAC;
- varredura Defender/EDR do payload e do MSI assinado;
- validação operacional de bootstrap, pipe, heartbeat, claim, progresso,
  complete/fail e recuperação;
- canário sustentado com paralelismo 1.
