# Atualização do HCH Worker no macOS

Este runbook descreve a atualização reversível do nó `mac-worker-01`. A fonte
canônica é `HUBTECH-DEV/hch-worker`, e o desenvolvimento deve ocorrer na branch
do dispositivo `MacBook-Pro-de-Paulo`. Uma revisão só pode ser declarada como
nova versão depois que instalação, trust, heartbeat e um canário real forem
validados. Antes disso, trate-a como fix candidato.

## Evidência histórica de preparação em 2026-08-22

- configuração: `$HOME/workspaces/hch-mac-worker-ops/orchestrator/worker-config.json`;
- estado privado: `$HOME/workspaces/hch-mac-worker-ops/run/orchestrator/state`;
- runtime imutável preparado em testes: `/usr/local/libexec/hch-editorial-runtime-6c5c9a0846f9`;
- symlink de execução: `/usr/local/libexec/hch-editorial-runtime`;
- versão declarada do kit: `3.1.0`;
- Ollama: `0.32.6`, serviço único em `127.0.0.1:11434`;
- modelo: `qwen2.5:1.5b-instruct`, digest
  `65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b`;
- manifesto: sequência `5`, hash
  `9baff244f66727518f03b5a5b5a23a6ccfbf27803a8758af38ffc45f9588a8b9`;
- backup da implantação:
  `$HOME/workspaces/hch-mac-worker-ops/backups/device-update-20260822-134455`.

O LaunchAgent contínuo é
`online.hubtech.hch.editorial-worker.cycle`. Ele executa `worker.mjs supervise`,
mantém heartbeat e abre o dashboard somente em `127.0.0.1:4319`. O Ollama é
mantido separadamente por `com.hubtech.hch-orchestrator-ollama`.

## Estado seguro e decisão operacional em 2026-08-23

### Evidência confirmada

- os testes direcionados da correção anti-placeholder e da recuperação segura
  de lock passaram (`1/1` cada);
- `npm test` passou: Linux `62/62` e dashboard `30/30`;
- a suíte Windows terminou sem falhas: `36` passaram e `14` integrações
  específicas da plataforma foram ignoradas (`50` no total);
- no Mac, a leitura de `status.json` confirmou `state=draining`,
  `running=false`, `currentBatch=null`, capacidades solicitada, concedida e
  efetiva em `0` e zero assignments ativos; `worker-control.json` confirmou
  `acceptingClaims=false` e `drainRequested=true`;
- na VPS, o serviço contínuo foi reportado como ativo, mas os claims
  permaneceram drenados; nenhum deploy ou canário foi autorizado nesta janela;
- `3.1.0` continua sendo somente fix candidato: não há canário editorial
  aprovado, validação de runtime, tag, release ou promoção para `main`.

### Ensaio isolado inconclusivo

- o primeiro ensaio recebeu HTTP 200, mas reprovou a validação editorial; a
  tentativa de reparo terminou em HTTP 500 com stream fechado;
- o segundo ensaio recebeu HTTP 200, porém não preservou stdout nem o JSON final
  necessário para provar o resultado;
- nenhum ensaio produziu um `pass` editorial reproduzível. Foi enviado `TERM`
  ao PID `37040` às `20:59:17-03`, `7 s` após o deadline; a saída foi
  confirmada em `<=5 s`; nenhum PID operacional foi tocado.

O resultado permanece **inconclusivo**. Não execute nova inferência nem trate
HTTP 200 isolado como validação de runtime.

### Concorrência externa observada

Durante a janela, os contadores mudaram de `claimed=86`/`failed=24` para
`claimed=88`/`failed=26`. `worker-control.json` foi gravado às
`20:48:42-03` (`updatedAt=2026-08-23T23:48:42.552Z`) com `updatedBy=stop`,
`acceptingClaims=false` e capacidade `0`; `metrics.json` e o log de erro foram
gravados às `20:48:43-03`, terminando em `operator-stop-requested` e nos
contadores `88/26`.

As duas operações concluídas às `20:45:35-03` e `20:45:38-03` não registram
ação nem ator. A auditoria dos rollouts Codex da data não encontrou
`control-start`, `control-stop`, `set-parallelism` ou POST para a API de
controle nessa janela; o harness isolado chamou `generateEditorialDraft`
diretamente em diretório temporário, sem fila ou controle. A única atribuição
suportada é: ação externa ao harness, por um caminho que gravou
`updatedBy=stop`. A origem do `operator-stop-requested` é indeterminável pela
ausência de access/audit log durável. Dashboard, CLI, outro processo e a
identidade do ator também são indetermináveis. Não atribua pessoa.

### Gate atual

Canário, deploy e reabertura de claims estão bloqueados. Mantenha Mac e VPS em
drain, `acceptingClaims=false` e capacidade `0/0` até nova autorização explícita
do chat principal e até existir evidência editorial reproduzível.

## 1. Sincronizar sem alterar `main`

```sh
git fetch origin --prune
git switch MacBook-Pro-de-Paulo
git pull --ff-only origin MacBook-Pro-de-Paulo
git status --short --branch
npm run test:linux
npm run test:dashboard
npm run test:windows
```

Pare diante de divergência. Não faça merge, rebase, force push ou promoção para
`main` sem autorização separada. Antes do push, revise segredos e publique
somente a branch do dispositivo.

## 2. Entrar em drain e preservar o estado

```sh
export HCH_CONFIG="$HOME/workspaces/hch-mac-worker-ops/orchestrator/worker-config.json"
export HCH_STATE="$HOME/workspaces/hch-mac-worker-ops/run/orchestrator/state"
export HCH_RUNTIME="/usr/local/libexec/hch-editorial-runtime"

node "$HCH_RUNTIME/ops/linux/editorial-worker/worker.mjs" \
  control-pause --config "$HCH_CONFIG"
jq '{state,running,currentBatch,capacity}' "$HCH_STATE/status.json"
```

Somente prossiga com `running=false`, `currentBatch=null` e capacidades
solicitada/concedida/efetiva iguais a zero. Copie configuração, estado, plists,
symlink atual e versão do Ollama para um diretório privado de backup. Chaves
privadas e tokens nunca entram no Git.

`pause` deixa o assignment atual terminar. Para cancelar trabalho ativo de
forma auditável, use `control-stop`; o erro remoto deve ser
`operator-stop-requested`.

## 3. Validar o Ollama sem abrir claims

A versão observada e usada nos ensaios deste Mac é `0.32.6`. Isso não valida o
runtime editorial. O arquivo oficial `Ollama-darwin.zip` usado na preparação
possuía SHA-256
`cc708ee7a9366b73b97d3f2999e25bb24b0a86feb41a0d2ced784ff4d4855e6d`.
O LaunchAgent deve manter:

```text
OLLAMA_HOST=127.0.0.1:11434
OLLAMA_LOAD_TIMEOUT=30m
OLLAMA_KEEP_ALIVE=10m
OLLAMA_MAX_LOADED_MODELS=1
OLLAMA_NUM_PARALLEL=1
OLLAMA_NO_CLOUD=true
```

Valide sem claim:

```sh
/Applications/Ollama.app/Contents/Resources/ollama --version
curl -fsS http://127.0.0.1:11434/api/tags | jq .
curl -fsS http://127.0.0.1:11434/api/ps | jq .
```

Em máquinas com 8 GB, pressão de memória e HTTP 500 durante o prefill precisam
ser registrados como diagnóstico, não como prova de compatibilidade ou
incompatibilidade. Enquanto o gate de 2026-08-23 estiver ativo, não repita a
inferência e não abra claims.

## 4. Procedimento preparado para instalar uma revisão imutável

Este procedimento não está autorizado pelo registro de 2026-08-23. Execute-o
somente em uma janela aprovada, depois de backup e confirmação do drain.

```sh
export HCH_REPO="$PWD"
export HCH_COMMIT="$(git rev-parse --short=12 HEAD)"
export HCH_RELEASE_ROOT="/usr/local/libexec/hch-editorial-runtime-$HCH_COMMIT"

launchctl bootout "gui/$(id -u)" \
  "$HOME/Library/LaunchAgents/online.hubtech.hch.editorial-worker.cycle.plist" \
  2>/dev/null || true
sudo mkdir -p "$HCH_RELEASE_ROOT"
sudo rsync -a --exclude=.git --exclude=node_modules --exclude=.DS_Store \
  "$HCH_REPO/" "$HCH_RELEASE_ROOT/"
sudo chown -R root:wheel "$HCH_RELEASE_ROOT"
sudo chmod -R a-w "$HCH_RELEASE_ROOT"
sudo ln -shf "$HCH_RELEASE_ROOT" /usr/local/libexec/hch-editorial-runtime
launchctl bootstrap "gui/$(id -u)" \
  "$HOME/Library/LaunchAgents/online.hubtech.hch.editorial-worker.cycle.plist"
```

No ChatGPT Desktop, o mesmo bloco pode ser executado por `osascript` com
`administrator privileges`, gerando o diálogo nativo. Confirme o alvo com
`readlink`; no macOS, `mv` sobre symlink de diretório pode seguir o destino e
não deve ser usado como substituição.

O runtime 3.1.0 recupera `.worker.lock` somente quando o PID registrado é
comprovadamente inexistente. Lock malformado, PID vivo ou erro de permissão
permanecem fail-closed.

## 5. Critérios preparados para um único canário

Esta seção não autoriza execução. O chat principal precisa aprovar explicitamente
o canário e a abertura temporária de capacidade `1`.

Primeiro confirme o estado drenado:

```sh
launchctl print "gui/$(id -u)/online.hubtech.hch.editorial-worker.cycle"
node "$HCH_RUNTIME/ops/linux/editorial-worker/worker.mjs" \
  control-validate --config "$HCH_CONFIG"
node "$HCH_RUNTIME/ops/linux/editorial-worker/worker.mjs" \
  control-status --config "$HCH_CONFIG"
```

Quando autorizado, o canário deve usar capacidade 1 e fechar a capacidade assim
que o contador `jobs.claimed` aumentar em exatamente uma unidade. Não use um
`sleep` fixo: monitore `metrics.json` e execute `control-pause` imediatamente
após o claim.

Critérios de aceite:

- trust `verified`, root `hch-root-v3` e release `hch-release-v4`;
- heartbeat aceito e manifesto sequência 5;
- assignment no tier autorizado pelo servidor;
- progresso do gerador renovando o lease;
- conclusão `pending-review`;
- `automaticApproval=false` e `automaticPublication=false`;
- retorno final a `draining`, capacidade zero e `currentBatch=null`.

## 6. Limitação atual de tier do Mac

O control plane redefine o tier adaptativo para o maior nível (`full`) em toda
nova atestação. Ensaios anteriores usaram teto `minimum`, mas não produziram
validação editorial ponta a ponta. Alterar o banco manualmente não é uma solução
durável e exige autorização separada: a próxima renovação de prontidão volta a
`full`.

Até que o HCH preserve um teto por nó durante a atestação, mantenha o Mac em
drain. A correção pertence ao servidor HCH e deve ser aplicada na
branch do dispositivo correspondente; não integre automaticamente uma branch
divergente.

## 7. Plano de rollback não executado

O plano abaixo é um critério de preparação; sua execução exige autorização.

1. Execute `control-stop` se houver assignment ativo e aguarde a confirmação
   remota.
2. Descarregue o LaunchAgent do Worker.
3. Reponte o symlink para o runtime anterior registrado no backup.
4. Restaure somente configuração/plists necessários; preserve manifestos mais
   novos e a identidade do nó.
5. Recarregue em capacidade zero e revalide trust e heartbeat.

Nunca faça downgrade de trust verificado, apague estado em massa ou reabra
claims durante o rollback.
