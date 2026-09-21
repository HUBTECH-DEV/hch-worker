# HCH Worker 4 — pacote operacional Linux headless

Este diretório contém os artefatos operacionais do candidato Linux 4.0.0. Ele
não declara a versão estável nem promove o worker. Instalação, ativação, canário
e promoção são gates separados.

## Contrato e layout FHS

| Caminho | Conteúdo e propriedade |
| --- | --- |
| `/opt/hch-worker/releases/<version>` | payload imutável, `root:root` |
| `/opt/hch-worker/current` | symlink para a release selecionada |
| `/etc/hch-worker/config.json` | configuração, `root:hch-worker`, `0640` |
| `/etc/hch-worker/trust/` | chave pública raiz pinada |
| `/var/lib/hch-worker/state/` | identidade, journals e estado, `0700` |
| `/run/hch-worker/control.sock` | contrato proposto para IPC Unix local |
| `/var/log/hch-worker/` | evidências locais, quando não forem ao journald |

O runtime atual lê a configuração exclusivamente por
`HCH_WORKER_CONFIG_PATH`. `HCH_WORKER_CONTROL_SOCKET` reserva o caminho para a
implementação posterior do Unix Domain Socket; estes artefatos não afirmam que
o IPC Linux já está implementado.

## Estado inicial seguro

A configuração não guarda um campo de estado operacional. O runtime cria o
controle com `MaxConcurrentJobs=0`, `GrantedCapacity=0` e estado `Paused`.
O validador restringe o candidato a concorrência lembrada 1 e lote de claim 1.
Pins de confiança ausentes deixam o runtime `NotReady + Paused/Drain`; pins
presentes são aceitos somente como conjunto completo e pelo caminho gerenciado.

O instalador não habilita nem inicia o serviço por padrão. `--enable-now` deve
ser usado apenas depois de validar que a implementação Linux preserva essas
invariantes. A promoção exige evidência operacional independente.

## Preparação do payload

Produza uma publicação self-contained `linux-x64` em diretório separado. Ela
deve conter o executável `Hch.Worker.Service`, sem symlinks. Verifique hashes,
SBOM e assinatura antes da instalação; o script não substitui a política de
proveniência da release.

Copie `config/config.example.json` para fora do repositório, substitua apenas os
identificadores públicos e, quando disponível, o trio de pins de confiança. Não
grave tokens, credenciais ou chaves privadas no JSON nem em `environment`.

```sh
sudo ./scripts/install.sh \
  --payload /caminho/para/publish/linux-x64 \
  --version 4.0.0-candidate.1 \
  --config /caminho/seguro/config.json
```

Valide antes de habilitar:

```sh
sudo ./scripts/validate-install.sh
sudo systemctl enable --now hch-worker.service
systemctl status hch-worker.service
journalctl -u hch-worker.service --since today
```

Confirme nos logs e na API do orquestrador: `Paused/Drain`, capacidade
solicitada e concedida zero, nenhum claim, identidade correta, manifesto
assinado e digest exato do modelo. Não use `Resume` durante o smoke test.

## Atualização e rollback

Antes de instalar ou trocar uma instância ativa, aplique Paused/Drain pelo
controle autenticado, aguarde jobs ativos e reservados chegarem a zero e pare o
serviço. O instalador e o rollback recusam trocar o symlink enquanto o serviço
está ativo. Releases permanecem lado a lado:

```sh
sudo systemctl stop hch-worker.service
sudo ./scripts/rollback.sh 4.0.0-candidate.1
sudo ./scripts/validate-install.sh
sudo systemctl start hch-worker.service
```

Configuração, identidade, journals e trust ficam fora do payload e são
preservados. A compatibilidade desses dados entre releases deve ser comprovada
antes do rollback. O script não escolhe automaticamente uma versão, não apaga
estado e não reinicia o serviço.

## Desinstalação reversível

```sh
sudo ./scripts/uninstall.sh --preserve-state
```

A operação remove somente a unidade systemd e preserva todos os binários,
configurações e dados. Remoção destrutiva é deliberadamente ausente.

## Validação estática

```sh
./test/artifacts.test.sh
./scripts/validate-unit.sh
```

O teste valida sintaxe POSIX, hardening essencial da unidade, rejeição dos
placeholders e bloqueio de concorrência inicial acima de 1. Um canário real
ainda precisa comprovar bootstrap, heartbeat, claim, complete/fail, reinício e
rollback, permanecendo `PendingReview` até aprovação humana.

Não execute `systemd-analyze verify systemd/hch-worker.service` diretamente em
uma árvore de fontes: ele também verifica a existência do `ExecStart` absoluto
e, corretamente, falha antes de o payload existir em `/opt`. O helper
`validate-unit.sh` substitui somente esse caminho por `/bin/true` numa cópia
temporária e exerce `systemd-analyze` sobre todas as demais diretivas. Depois da
instalação, `validate-install.sh` verifica a unidade original contra o payload
real.
