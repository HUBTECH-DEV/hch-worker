# Ações de atualização do HCH Worker no Mac

Este roteiro deve ser executado **no Mac**, na branch
`MacBook-Pro-de-Paulo`. Ele incorpora os fixes validados no Windows/VPS sem
transportar tokens ou chaves privadas pelo Git.

## 1. Atualizar e integrar o código

```sh
git fetch origin --prune
git switch MacBook-Pro-de-Paulo
git pull --ff-only origin MacBook-Pro-de-Paulo
git merge --no-ff origin/NB-PE0FHWM9
npm test
```

O merge deve conter, no mínimo, os commits `6731c1b` (execução por symlink de
release imutável) e `57fe4ce` (ciclo portátil `run-one`). Resolva conflitos
preservando a integração macOS em `ops/macos/editorial-worker`.

## 2. Colocar o worker em drain e fazer backup

```sh
export HCH_REPO="$PWD"
export HCH_CONFIG="$HOME/Library/Application Support/HCH/editorial-worker/config.json"
export HCH_CTL="$HCH_REPO/ops/macos/editorial-worker/hch-editorial-workerctl"
export HCH_BACKUP="$HOME/Library/Application Support/HCH/backups/$(date +%Y%m%d-%H%M%S)"
mkdir -m 700 -p "$HCH_BACKUP"
/bin/sh "$HCH_CTL" set-parallelism 0
/bin/sh "$HCH_CTL" pause
cp -p "$HCH_CONFIG" "$HCH_BACKUP/config.json"
cp -Rp "$HOME/Library/Application Support/HCH/editorial-worker" "$HCH_BACKUP/state"
cp -Rp "$HOME/Library/LaunchAgents"/online.hubtech.hch.editorial-worker.* "$HCH_BACKUP/" 2>/dev/null || true
```

Aguarde o trabalho atual terminar. `pause` e paralelismo `0` não cancelam o
assignment em andamento. Não prossiga enquanto `currentBatch` não estiver
vazio.

## 3. Atualizar a confiança pública

Transfira por canal confiável **somente** `root-public.pem`. Nunca transfira a
chave raiz privada. Confirme fora do Git que o fingerprint recebido é:

```text
SHA256:wBbHjXmYqv63QAjNHKlKcLfEVrGjr7nva_h1t4zolLY
```

Faça backup do arquivo público e do `trust-state`, instale a nova chave no
`rootPublicKeyPath` definido pela configuração e atualize apenas o fingerprint
público configurado. Preserve identidade, chave privada, token e estado de
assignments. Se for necessário reancorar a confiança, mova o `trust-state`
anterior para o backup; não o apague.

## 4. Instalar a release imutável e o LaunchAgent

```sh
export HCH_COMMIT="$(git rev-parse --short=12 HEAD)"
export HCH_RELEASE_ROOT="/usr/local/libexec/hch-editorial-runtime-$HCH_COMMIT"
export HCH_NODE_BIN="$(command -v node)"
sudo mkdir -p "$HCH_RELEASE_ROOT"
sudo rsync -a --delete --exclude .git/ "$HCH_REPO/" "$HCH_RELEASE_ROOT/"
sudo ln -sfn "$HCH_RELEASE_ROOT" /usr/local/libexec/hch-editorial-runtime
HCH_RUNTIME_ROOT=/usr/local/libexec/hch-editorial-runtime \
HCH_WORKER_CONFIG="$HCH_CONFIG" HCH_NODE_BIN="$HCH_NODE_BIN" \
/bin/sh "$HCH_RELEASE_ROOT/ops/macos/editorial-worker/install-launch-agents.sh"
```

O processo contínuo do `launchd` deve usar `supervise`/`run-one`. O endpoint
legado `/execute` não faz parte do ciclo de execução.

## 5. Validar confiança, manifesto e execução

```sh
export HCH_RUNTIME_ROOT=/usr/local/libexec/hch-editorial-runtime
export HCH_WORKER_CONFIG="$HCH_CONFIG"
export HCH_NODE_BIN
/bin/sh "$HCH_CTL" validate
/bin/sh "$HCH_CTL" status
/bin/sh "$HCH_CTL" set-parallelism 1
/bin/sh "$HCH_CTL" start
launchctl print "gui/$(id -u)/online.hubtech.hch.editorial-worker.cycle"
open http://127.0.0.1:4319
```

Critérios de aceite:

- manifesto na sequência `5`, hash
  `9baff244f66727518f03b5a5b5a23a6ccfbf27803a8758af38ffc45f9588a8b9`;
- confiança verificada e heartbeat aceito;
- capacidade solicitada e concedida igual a `1` no canário;
- um assignment processado com progresso enviado nos heartbeats;
- dashboard acessível somente em `127.0.0.1:4319`;
- conclusão entregue como `pending-review`.

Depois do canário, ajuste o paralelismo desejado (por exemplo, `2`). O valor
`0` mantém pause sem cancelar o trabalho atual; `stop` cancela os trabalhos e
relata o encerramento ao orquestrador.

## 6. Rollback e encerramento

Se qualquer critério falhar, volte para paralelismo `0`, descarregue os agentes
candidatos, restaure os plists/configuração e a versão anterior do symlink a
partir do backup. Não faça downgrade de um manifesto válido mais recente.

Após aceite no Mac:

```sh
git status --short
git add -A
git commit -m "chore(mac): record worker deployment result"
git push origin MacBook-Pro-de-Paulo
```

Registre no commit somente código, testes e evidências sem segredo. Não inclua
configuração do host, tokens, chaves privadas, estado ou logs sensíveis.
