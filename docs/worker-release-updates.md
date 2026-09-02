# Atualização de release dos workers

## Modelo implementado

O dashboard consulta automaticamente, a cada 15 minutos, a lista de releases
estáveis de `HUBTECH-DEV/hch-worker`. Ele seleciona a maior tag do sistema
operacional corrente (`windows-vX.Y.Z`, `linux-vX.Y.Z` ou `macos-vX.Y.Z`) e
aceita `vX.Y.Z` apenas como fallback legado até a ponte 3.1.1. Tags genéricas
posteriores são ignoradas. Releases de outro sistema são
ignoradas. A comparação usa SemVer estrito e ignora drafts e pré-releases.
Quando `latestVersion > worker.version`, o painel mostra o botão **Atualizar**.

A ponte 3.1.1 e toda release posterior precisam conter nas notas exatamente um
par coerente:

```text
HCH-Worker-Compatibility: compatible
HCH-Worker-Content-Impact: none
```

ou:

```text
HCH-Worker-Compatibility: incompatible
HCH-Worker-Content-Impact: generated-content
```

Ausência, valor desconhecido ou combinação cruzada falha de forma fechada e
não oferece atualização.

## Ponte explícita para clientes 3.1

O dashboard 3.1 instalado consulta `/releases/latest` e só entende tags
genéricas `vX.Y.Z`. Portanto, publicar diretamente `windows-v4.0.0` não faz o
3.1 reconhecer a atualização; se essa release virar `latest`, o 3.1 registra
`release-version-invalid`. Alterar apenas o parser da `main` não corrige os
binários já instalados.

A transição deve usar uma última ponte genérica **3.1.1**, compatível e sem
impacto de conteúdo, construída e testada para Windows, Linux e macOS:

1. publicar `v3.1.1` com os artefatos exatos
   `HCH-Worker-Setup-3.1.1-x64.exe`,
   `HCH-Worker-3.1.1-linux-x64.tar.gz`,
   `HCH-Worker-3.1.1-macos-universal.tar.gz`, `SHA256SUMS.txt` e
   `SHA256SUMS.p7s`; os três pacotes precisam estar cobertos pelos checksums,
   pela assinatura CMS e por attestations do commit protegido que os produziu;
   o EXE também precisa de Authenticode válido, timestamp e dos mesmos pins
   públicos do signer aprovado;
2. manter `v3.1.1` explicitamente como a release `Latest` durante a janela de
   migração, para que todo cliente 3.1 ainda descubra uma tag que consegue
   interpretar;
3. comprovar por telemetria/heartbeat que os Workers suportados instalaram a
   ponte e consultam a lista por plataforma;
4. publicar releases `windows-v*`, `linux-v*` e `macos-v*` com
   `--latest=false`; o dashboard novo as encontra pela lista sem mover o
   ponteiro legado;
5. encerrar o ponteiro legado somente por decisão de compatibilidade auditada,
   depois que não houver Worker 3.1 suportado dependente de `/releases/latest`.

O workflow de promoção consulta `/releases/latest` e
`/releases/tags/v3.1.1` diretamente, exige o mesmo release id, tag anotada,
commit fonte, release imutável, marcadores exatos, idade mínima de sete dias e
o conjunto de assets acima sem executáveis extras. Falha de API, hash, CMS,
attestation ou ambiguidade bloqueia a promoção; não existe input para ignorar
esse gate.

Antes de baixar qualquer asset, o gate rejeita tamanho zero, limita o EXE e
cada `.tar.gz` a 512 MiB, `SHA256SUMS.txt` a 64 KiB,
`SHA256SUMS.p7s` a 2 MiB e o conjunto completo a 1.280 MiB. Depois de conferir
o inventário, os tamanhos baixados e os hashes, ele abre os dois `.tar.gz` com
`tar`/`bsdtar` em modo fail-closed. Cada archive admite no máximo 4.096
entradas, somente arquivos regulares e diretórios sob uma única raiz
`hch-worker/`; caminho absoluto, traversal, barra invertida, segmento inseguro,
duplicata, symlink, hardlink ou entrada especial bloqueia a promoção.

Os dois archives contêm `hch-worker/VERSION` com os bytes ASCII exatos
`3.1.1` seguidos por um único LF, além de
`ops/linux/editorial-worker/worker.mjs` e
`ops/worker-dashboard/server.mjs`. O pacote Linux também contém
`scripts/hch-editorial-workerctl` e
`ops/systemd/hch-editorial-worker.service`. O pacote macOS também contém
`ops/macos/editorial-worker/hch-editorial-workerctl`,
`ops/macos/editorial-worker/install-launch-agents.sh` e o template
`launchd/online.hubtech.hch.editorial-worker.cycle.plist.in`. O gate confere no
header tar o bit executável do proprietário para `worker.mjs` e para os scripts
de controle/instalação. O produtor futuro ainda deve executar smoke tests em
Linux e macOS reais: a inspeção do header prova o modo empacotado, não o
funcionamento do entrypoint no sistema-alvo.

Não se deve editar silenciosamente uma release histórica, criar um alias
`v4.0.0` apenas para Windows nem transformar `windows-v4.0.0` em `Latest`
durante a janela. O fallback genérico existe para a ponte multiplataforma, não
para voltar a misturar os canais por sistema.

### Estado atual da ponte: produtor implementado; ativação administrativa pendente

O produtor versionado agora existe em `.github/workflows/bridge-package.yml`.
Ele testa a fonte portátil, cria arquivos Linux/macOS determinísticos, executa
smoke test real em Linux e macOS, gera o Setup Windows com versão injetada,
assina o EXE e o `SHA256SUMS.txt`, atesta os três pacotes e publica somente os
bytes exatos já validados. `push` e `pull_request` executam apenas os testes de
fonte; assinatura/publicação só existem em `workflow_dispatch` com
`publish=true`, `main` protegida e dois environments separados.

Isso conclui a automação de desenvolvimento, mas não declara que a ponte já
pode ser publicada. Ainda dependem de controles ou evidências externas:

- a imutabilidade de releases ainda não está registrada como política
  administrativa do repositório. O workflow exige
  `RELEASE_IMMUTABILITY_ENFORCED=true`, tag anotada protegida e revisão do
  environment antes de publicar; proteger apenas a tag não protege os assets;
- os environments `bridge-release-signing` e `bridge-release-promotion`, seus
  revisores, os pins públicos, a raiz pública e o segredo do certificado ainda
  precisam ser configurados no GitHub;
- a tag anotada `v3.1.1` ainda precisa ser criada sobre o commit exato da
  `main` somente depois que os checks obrigatórios passarem;
- o contrato da ponte continua usando o EXE legado, propositalmente. O MSI
  nativo pertence à linha Windows 4.x e nunca é renomeado como ponte 3.1;
- os pacotes impõem limites comprimidos e descomprimidos e smoke tests nos
  sistemas reais do CI; a execução sustentada em hosts da frota continua sendo
  evidência operacional, não evidência de build;
- as instalações 3.1 não configuram o backend administrativo chamado por
  `hch-worker-update.mjs`, portanto a release isolada mostra o aviso, mas não
  aplica a atualização;
- o runtime/orquestrador ainda não persiste uma prova auditável de
  `releaseDiscoveryProtocol=platform-release-list/v1` associada aos heartbeats;
- a declaração Windows 4.0.0 agora é versionada em
  `src/windows/release-compatibility.json`, incorporada ao conjunto de checksums
  e ao provenance do MSI. O workflow de promoção deriva os marcadores da
  release desse arquivo, sem aceitar um valor manual no `workflow_dispatch`.
  O arquivo é metadado humano revisado, protegido pelos hashes e assinaturas do
  conjunto; ele não prova sozinho a compatibilidade semântica. A promoção exige
  também o relatório de compatibilidade, o canário e a correlação operacional,
  enquanto o `contentContractHash` do manifesto assinado continua sendo a
  autoridade em runtime para uma mudança que afete conteúdo.

Os controles externos precisam ser concluídos antes da criação de `v3.1.1`.
Não se deve criar assets manuais para contornar o produtor, alterar o inventário
do gate ou declarar migração de frota sem a telemetria derivável.

A consulta ao GitHub é somente descoberta. Ela não autoriza a execução do
conteúdo publicado. O clique usa o mesmo endpoint local protegido por loopback,
same-origin e CSRF dos demais controles. A versão não é aceita do navegador: o
servidor refaz a consulta e fornece a versão-alvo ao executor local fixo.

Instalação automática sem intervenção permanece desabilitada. Isso preserva o
gate do projeto: a release pode ser detectada automaticamente, mas a mudança de
runtime depende da ação do operador e de um backend administrativo instalado no
host.

## Contrato do executor

O dashboard executa somente um arquivo canônico chamado
`hch-worker-update.mjs`, filho direto de uma raiz confiável. O handoff fornecido
em `ops/worker-updater/hch-worker-update.mjs` usa um lock exclusivo, registra
estado sem segredos em `worker-release-update.json` e chama um único backend
administrativo previamente configurado, sem shell.

Variáveis do processo do dashboard/supervisor:

```text
HCH_WORKER_RELEASE_REPOSITORY=HUBTECH-DEV/hch-worker
HCH_WORKER_RELEASE_CHECK_INTERVAL_MS=900000
HCH_WORKER_UPDATE_SCRIPT=/opt/hch-worker-updater/hch-worker-update.mjs
HCH_WORKER_UPDATE_SCRIPT_ROOT=/opt/hch-worker-updater
HCH_WORKER_UPDATE_STATE_DIR=/var/lib/hch-editorial-worker
HCH_WORKER_UPDATE_BACKEND=/usr/local/libexec/hch-worker-update-backend
HCH_WORKER_UPDATE_BACKEND_ROOT=/usr/local/libexec
```

No macOS, substitua os dois últimos diretórios por caminhos administrativos
locais e mantenha o estado em `~/Library/Application Support/HCH/...`. No
Windows, use caminhos absolutos em `ProgramData`/`Program Files`; o dashboard
continua invocando o handoff com o Node instalado e o backend realiza a elevação
por um serviço ou tarefa administrativa já registrada.

O backend recebe somente:

```text
hch-worker-update-backend apply --target-version X.Y.Z
```

Ele deve rejeitar qualquer argumento extra e implementar, nessa ordem:

1. obter a release e verificar tag/assinatura e SHA-256 dos artefatos;
2. recusar downgrade, versão igual, artefato de outra plataforma ou caminho
   fora da staging privada;
3. executar a suíte/self-test no conteúdo imutável antes da troca;
4. aplicar `pause` e aguardar `activeAssignments = 0`;
5. registrar versão, commit, hashes e configuração anteriores para rollback;
6. instalar em diretório versionado e trocar o ponteiro/serviço atomicamente;
7. executar bootstrap, `validate`, confiança Ed25519, heartbeat e healthcheck;
8. restaurar a capacidade anterior somente após todos os gates passarem;
9. em falha, reinstalar a versão anterior, validar o rollback e manter drain se
   a recuperação não puder ser provada.

O backend nunca deve confiar apenas em `latest`, executar comandos vindos dos
metadados da release, copiar chave privada, alterar publicação/aprovação
automática ou reconhecer a versão como implantada antes das validações.

## Habilitação por ambiente

### VPS (primeiro canário)

1. Instalar o handoff e o backend como arquivos `root:root`, não graváveis pelo
   usuário do worker.
2. Adicionar as variáveis à unit do systemd e executar `daemon-reload`.
3. Reiniciar o supervisor em drain e confirmar `/api/status`.
4. Publicar uma release de teste assinada e provar update, rollback ensaiado,
   bootstrap, heartbeat, claim e conclusão.

### macOS

1. Instalar handoff/backend em diretório não gravável pelo processo do worker.
2. Adicionar as variáveis ao LaunchAgent de ciclo.
3. Reinstalar os LaunchAgents em drain e validar o painel loopback.
4. Só habilitar a capacidade anterior depois do canário da VPS e da validação
   local completa.

### Windows

1. Instalar o backend assinado em `Program Files` e registrar a elevação fora do
   processo do dashboard.
2. Preservar o instalador versionado e `Restore-HchWorkerServiceVersion.ps1`
   como caminho de rollback.
3. Repetir os mesmos gates depois de VPS e macOS/Linux.

## Validação da interface

Sem release publicada, o painel mostra **Sem release** e não mostra o botão.
Com uma release estável simulada superior, mostra **Atualização disponível**.
O botão só é habilitado quando o executor fixo também estiver configurado; caso
contrário a interface informa `executor administrativo não habilitado`.

Testes:

```sh
npm run test:dashboard
npm test
npm run test:windows
```
