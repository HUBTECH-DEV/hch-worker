# Implantação de fix do HCH Worker no macOS

Este procedimento instala um candidato no macOS sem promovê-lo antecipadamente
a uma nova versão estável. Antes do aceite operacional, use uma identidade de
pré-release derivada da versão estável, por exemplo
`3.0.0-fix.<commit-curto>`.

## Gate de promoção

O candidato somente fica elegível para promoção depois de comprovar, nesta
ordem:

1. testes automatizados verdes;
2. drain sem interromper assignment ativo;
3. backup privado da configuração, estado, confiança e LaunchAgents;
4. bootstrap e validação da cadeia de confiança;
5. heartbeat assinado com capacidade concedida;
6. claim real;
7. conclusão do mesmo assignment como `pending-review`.

Tag, release e versão estável permanecem bloqueadas enquanto qualquer etapa
estiver pendente ou falhar. Aprovação e publicação automáticas continuam
desabilitadas.

## Preparação

Use um checkout destacado do commit candidato e aplique nele apenas a
identidade temporária do fix. Não altere tokens, chaves privadas ou a
configuração específica do host.

```sh
git worktree add --detach "$HCH_FIX_ROOT" "$HCH_CANDIDATE_COMMIT"
npm test --prefix "$HCH_FIX_ROOT"
```

Defina caminhos absolutos:

```sh
export HCH_RUNTIME_ROOT="$HCH_FIX_ROOT"
export HCH_WORKER_CONFIG="$HOME/Library/Application Support/HCH/editorial-worker/config.json"
export HCH_NODE_BIN="/opt/homebrew/bin/node"
```

Em Macs Intel, `HCH_NODE_BIN` pode ser `/usr/local/bin/node`.

## Drain e backup

Use `pause` no runtime contínuo. Ao migrar de 3.0.0, que ainda não expõe esse
comando, use `set-parallelism 0`. Aguarde `currentBatch: null` e
`code: batch-completed` antes de trocar os agentes.

```sh
./ops/macos/editorial-worker/hch-editorial-workerctl pause
# Compatibilidade 3.0.0:
./ops/macos/editorial-worker/hch-editorial-workerctl set-parallelism 0
```

O backup deve usar diretório com modo `0700`; arquivos de configuração, estado,
confiança e identidade devem permanecer `0600`. Nunca imprima chaves ou tokens
nos logs.

## Instalação e canário

```sh
HCH_RUNTIME_ROOT="$HCH_RUNTIME_ROOT" \
HCH_WORKER_CONFIG="$HCH_WORKER_CONFIG" \
HCH_NODE_BIN="$HCH_NODE_BIN" \
/bin/sh "$HCH_RUNTIME_ROOT/ops/macos/editorial-worker/install-launch-agents.sh"

HCH_RUNTIME_ROOT="$HCH_RUNTIME_ROOT" \
HCH_WORKER_CONFIG="$HCH_WORKER_CONFIG" \
HCH_NODE_BIN="$HCH_NODE_BIN" \
/bin/sh "$HCH_RUNTIME_ROOT/ops/macos/editorial-worker/hch-editorial-workerctl" validate

HCH_RUNTIME_ROOT="$HCH_RUNTIME_ROOT" \
HCH_WORKER_CONFIG="$HCH_WORKER_CONFIG" \
HCH_NODE_BIN="$HCH_NODE_BIN" \
/bin/sh "$HCH_RUNTIME_ROOT/ops/macos/editorial-worker/hch-editorial-workerctl" start
```

Confirme ainda:

- o LaunchAgent `cycle` em estado `running` e usando `supervise`;
- o LaunchAgent legado `heartbeat` descarregado;
- o dashboard somente em `127.0.0.1:4319`;
- `trust.status=verified`, TLS verificado e autenticação Ed25519;
- capacidade pedida e concedida iguais a `1` no canário;
- um assignment reivindicado e concluído como `pending-review`.

### Pressão no Darwin

`node:os.freemem()` não representa toda a memória recuperável do macOS, e o
load average do Darwin inclui trabalho executável e bloqueado. O runtime não
deve enviar essas duas amostras genéricas como sinais de redução de capacidade.
Só reporte CPU ou memória no Darwin quando um coletor específico da plataforma
fornecer a amostra correspondente. O teste de regressão deve cobrir essa regra.

## Rollback

Se bootstrap, validação, heartbeat, claim ou conclusão falhar:

1. volte o worker para drain;
2. descarregue os LaunchAgents candidatos;
3. restaure os plists e o runtime anterior do backup;
4. preserve o estado e a cadeia de confiança mais novos quando válidos; não
   faça downgrade de manifesto ou delegação assinada;
5. recarregue o runtime anterior, valide e somente então reabra capacidade;
6. registre a falha e mantenha o candidato sem tag ou release.

Um lock cujo PID não existe pode ser preservado como evidência no backup antes
de ser movido para fora do diretório de estado. Nunca remova um lock enquanto o
PID registrado ainda estiver ativo.
