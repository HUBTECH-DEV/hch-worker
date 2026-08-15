# Atualização de release dos workers

## Modelo implementado

O dashboard consulta automaticamente, a cada 15 minutos, a última release
estável de `HUBTECH-DEV/hch-worker`. A comparação usa SemVer estrito e ignora
drafts e pré-releases. Quando `latestVersion > worker.version`, o painel mostra
o botão **Atualizar**.

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
