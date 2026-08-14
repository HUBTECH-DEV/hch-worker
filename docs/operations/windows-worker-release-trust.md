# Confiança da release Windows do HCH Worker

O publicador interno desta release é `HUBTECH CONSULTORIA E DESENVOLVIMENTO
LTDA`. O instalador 3.1.0 não compila código durante a instalação e, por padrão,
recusa o host nativo quando assinatura Authenticode, timestamp, identidade do
publicador ou hash da evidência não forem válidos. O switch
`-AllowUnsignedDevelopmentBuild` existe somente para laboratório controlado e
não deve aparecer em distribuição, suporte ou automação de produção.

## Controles implementados no repositório

1. O executável possui recursos de versão com produto `HCH Editorial Worker`,
   empresa `HUBTECH-DEV` e versão `3.1.0.0`.
2. O manifesto Win32 declara identidade estável e `asInvoker`; o serviço não
   solicita elevação por conta própria.
3. `Build-HchWorkerService.ps1` produz o binário e a evidência
   `HchEditorialWorkerService.exe.release.json`.
4. `Sign-HchWorkerReleaseArtifact.ps1` assina com SHA-256, aplica timestamp RFC
   3161, verifica a cadeia e regenera a evidência após a assinatura.
5. `Test-HchWorkerReleaseArtifact.ps1` confere hash, recursos de versão,
   assinatura, timestamp e thumbprint esperado.
6. `Install-HchWorkerService.ps1` executa esse gate antes de parar ou alterar o
   serviço existente. O build elevado foi removido do instalador.
7. A CI Windows compila, testa e publica somente um artefato explicitamente
   nomeado como `unsigned`, destinado à etapa protegida de assinatura.

## Processo técnico da release

Em um runner Windows limpo:

```powershell
./ops/windows/editorial-worker/Build-HchWorkerService.ps1
node --test ops/windows/editorial-worker/tests/windows-service.test.mjs
node --test ops/windows/editorial-worker/tests/worker-cycle.test.mjs
node --test ops/worker-dashboard/test/dashboard.test.mjs
```

Na etapa protegida, com o certificado acessível pelo repositório de
certificados ou por um provedor compatível com SignTool:

```powershell
./ops/windows/editorial-worker/Sign-HchWorkerReleaseArtifact.ps1 `
  -CertificateThumbprint $env:HCH_WINDOWS_PUBLISHER_THUMBPRINT

./ops/windows/editorial-worker/Test-HchWorkerReleaseArtifact.ps1 `
  -BinaryPath ./ops/windows/editorial-worker/service/bin/HchEditorialWorkerService.exe `
  -ExpectedPublisherThumbprint $env:HCH_WINDOWS_PUBLISHER_THUMBPRINT
```

O pacote deve ser criado somente depois dessa etapa. Grave no sistema de
release o SHA-256 do executável e do pacote, o commit, o run de CI, a identidade
do certificado, o timestamp e um SBOM. Não altere nenhum arquivo depois de
assinar; qualquer alteração invalida a evidência.

## Confiança manual para instalação interna

Quando não for necessária reputação pública, um administrador pode validar o
thumbprint por canal separado e confiar manualmente no certificado público:

```powershell
./ops/windows/editorial-worker/Start-HchPublisherTrustElevated.ps1
```

A janela elevada exibe nome empresarial, thumbprint e validade antes de pedir
confirmação. Após a confirmação, o certificado público é adicionado a
`LocalMachine\Root` e `LocalMachine\TrustedPublisher`. A chave privada é não
exportável e não acompanha o instalador. Verifique o resultado com:

```powershell
./ops/windows/editorial-worker/Test-HchPublisherTrust.ps1
```

Esse modelo é apropriado para instalação interna controlada. Ele não cria
reputação pública de SmartScreen e não garante aceitação por políticas como
Smart App Control ou EDR corporativo.

## Ações externas ao desenvolvimento

### 1. Obter uma identidade de assinatura

Responsável: organização/jurídico/financeiro/segurança.

1. Definir a entidade jurídica que aparecerá como publicador.
2. Contratar certificado OV de code signing ou habilitar Microsoft Artifact
   Signing, conforme disponibilidade geográfica e política da organização.
3. Concluir a validação de identidade solicitada pelo provedor.
4. Guardar a chave em HSM/serviço de assinatura; não exportar PFX para o
   repositório, notebook ou secrets comuns de CI.
5. Informar ao pipeline somente a referência segura e publicar o thumbprint
   aprovado como variável protegida `HCH_WINDOWS_PUBLISHER_THUMBPRINT`.

### 2. Autorizar e governar a assinatura em CI

Responsável: DevOps/segurança.

1. Criar ambiente protegido de release com aprovação obrigatória.
2. Permitir assinatura somente para tags/releases protegidas e commits que
   passaram na CI.
3. Restringir o serviço de assinatura ao workflow e repositório oficiais.
4. Manter logs imutáveis de cada operação de assinatura.
5. Definir rotação, revogação e resposta a comprometimento do certificado.

### 3. Construir reputação e tratar falso positivo

Responsável: segurança/suporte do publicador.

1. Distribuir sempre com a mesma identidade de publicação válida.
2. Se uma release assinada for detectada como malware, preservar hash, nome da
   detecção, `ThreatID`, versão das definições e logs; não criar exclusão.
3. Enviar o arquivo no portal Microsoft Security Intelligence como
   `Software developer — false positive`.
4. Aguardar o parecer e atualização das definições antes do rollout amplo.
5. Reexecutar o teste em uma VM Windows limpa e atualizada.

### 4. Distribuição corporativa

Responsável: TI do ambiente consumidor.

1. Validar assinatura, thumbprint e hashes recebidos por canal separado.
2. Distribuir via Intune, Configuration Manager ou ferramenta corporativa com
   política de publicador aprovada.
3. Fazer canário em poucas máquinas antes da expansão.
4. Monitorar Defender, Smart App Control, EDR e eventos do SCM.
5. Não usar allowlist por pasta. Se uma regra corporativa for indispensável,
   prefira publicador assinado e versão, com prazo e revisão de segurança.

## Critério de liberação

A release Windows está apta somente quando o verificador retorna `valid=true`,
o Defender não encontra ameaça em uma VM limpa, o SCM inicia o serviço, o
dashboard responde exclusivamente em `127.0.0.1`, e os testes de `pause`,
`stop` e paralelismo passam. Assinatura reduz falsos positivos e estabelece
procedência; ela não substitui análise de segurança.
