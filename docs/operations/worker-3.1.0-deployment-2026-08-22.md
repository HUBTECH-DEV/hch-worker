# Preparação operacional do fix candidato HCH Worker 3.1.0 — 2026-08-22/23

## Escopo

Registro da preparação e das instalações técnicas originadas na branch
`MacBook-Pro-de-Paulo` do repositório `HUBTECH-DEV/hch-worker` para os nós Mac
e VPS. Este documento não é evidência de release nem promoção operacional.
Nenhuma alteração foi integrada ou enviada para `main`; aprovação e publicação
automáticas permaneceram desabilitadas.

O código declara `3.1.0`, mas a revisão continua sendo **fix candidato**. Em
2026-08-23, canário, deploy e claims permaneceram bloqueados e não houve
validação editorial de runtime.

## Revisões relevantes

- `f599330`: transporte Ollama em modo JSON portátil;
- `24ccfc1`: evidência enviada ao modelo limitada para reduzir o prefill;
- `4234180`: códigos seguros de validação no log;
- `6801010`: prontidão desacoplada da capacidade local;
- `128e354`: classificação segura de falhas de transporte/stream do Ollama;
- `6c5c9a0`: recuperação fail-safe de lock cujo PID está comprovadamente morto;
- `b8a070b`: serviço VPS usa o Node fixado em `/usr/local/libexec/hch-node`;
- `6c67fe5`: lote de prefill Ollama reduzido para 256 somente no Darwin;
- `3235ffc`: exige as chaves JSON canônicas da resposta editorial;
- correção local sob validação: remove o exemplo literal do prompt e declara
  requisitos de campo e regra anti-placeholder, sem alterar o schema de saída.

## mac-worker-01

### Instalação

- runtime base instalado: `/usr/local/libexec/hch-editorial-runtime-6c5c9a0846f9`;
- revisão Darwin final candidata: `6c67fe5b023f`;
- LaunchAgent: `online.hubtech.hch.editorial-worker.cycle`;
- Ollama `0.32.6`, `OLLAMA_LOAD_TIMEOUT=30m`, um modelo e uma inferência
  paralela;
- trust: `hch-root-v3` → `hch-release-v4` → manifesto sequência 5;
- backup:
  `$HOME/workspaces/hch-mac-worker-ops/backups/device-update-20260822-134455`.

### Evidência histórica de 2026-08-22

Um ensaio sem fila, com `num_ctx=8192`, `num_predict=768` e lote padrão 1.024,
concluiu. Sob maior pressão de swap, o canário real mínimo falhou durante o
prefill com HTTP 500 do Ollama. A revisão `128e354` classificou corretamente o
evento remoto como `local-generator-transport-failed`, sem conteúdo bruto.

Um segundo ensaio sem fila, já com `num_batch=256`, processou 1.669 tokens de
prompt sob a mesma pressão e transportou 769 chunks sem HTTP 500. O ensaio
terminou com `done_reason=length`, portanto não foi contado como conclusão
editorial; ele validou somente a mitigação de transporte/prefill.

O control plane ainda redefine o tier do Mac como `full` em toda atestação. O
tier `minimum` aplicado por CAS serve apenas ao canário e não sobrevive à
renovação de prontidão. Até a correção no servidor HCH, o estado seguro após os
testes é drain, capacidade zero.

### Validação determinística de 2026-08-23

- testes direcionados da correção anti-placeholder e da recuperação segura de
  lock: `1/1` passou em cada um;
- `npm test`: Linux `62/62` e dashboard `30/30`, sem falhas;
- suíte Windows: `36` passaram, `14` integrações específicas da plataforma
  foram ignoradas, zero falhas (`50` no total);
- nenhum desses testes acessou fila, abriu claims ou validou o runtime real.

### Ensaio isolado de 2026-08-23

O primeiro ensaio recebeu HTTP 200, mas reprovou a validação editorial; o reparo
terminou em HTTP 500 com stream fechado. O segundo recebeu HTTP 200, porém não
preservou stdout nem o JSON final necessário para prova. Nenhum dos dois
produziu um `pass` editorial reproduzível.

Foi enviado `TERM` ao PID `37040` às `20:59:17-03`, `7 s` após o deadline; a
saída foi confirmada em `<=5 s`; nenhum PID operacional foi tocado. O ensaio
permanece **inconclusivo**; não há runtime ou canário validado.

### Estado drenado e concorrência externa

A leitura final do Mac confirmou `state=draining`, `running=false`,
`acceptingClaims=false`, `currentBatch=null`, capacidade `0/0` e zero
assignments ativos. Durante a janela, porém, os contadores mudaram de
`claimed=86`/`failed=24` para `claimed=88`/`failed=26`.

O controle foi gravado às `20:48:42-03`
(`updatedAt=2026-08-23T23:48:42.552Z`) com `updatedBy=stop`, claims fechados e
capacidade zero. Um segundo depois, métricas e log registraram os contadores
`88/26` e o erro final `operator-stop-requested`. Duas operações concluídas às
`20:45:35-03` e `20:45:38-03` não contêm ação nem ator.

A auditoria dos rollouts Codex da data não encontrou comando de start, stop,
paralelismo ou POST de controle nessa janela. O harness isolado executou
`generateEditorialDraft` diretamente em diretório temporário, sem fila ou
controle. Assim, a evidência permite atribuir a mudança apenas a uma ação
externa ao harness por um caminho que gravou `updatedBy=stop`. A origem do
`operator-stop-requested` é indeterminável pela ausência de access/audit log
durável. Dashboard, CLI, outro processo e a identidade do ator também são
indetermináveis; não atribua pessoa.

## vps-primary

### Migração

O serviço one-shot legado estava preso por mais de 40 minutos. Foi emitido
`control-stop`, e o assignment terminou como `operator-stop-requested`. Em
seguida:

1. os timers legados `hch-editorial-republication`,
   `hch-editorial-node-heartbeat` e `hch-editorial-bootstrap` foram
   desabilitados;
2. o runtime imutável `b8a070b6cd45` foi instalado;
3. `hch-editorial-worker.service` foi habilitado como supervisor contínuo;
4. o dashboard passou a ser filho do supervisor em `127.0.0.1:4319`;
5. o nó permaneceu em drain antes do canário.

Na janela de 2026-08-23, o serviço contínuo foi reportado como ativo, com os
claims ainda drenados. Não houve canário, deploy adicional ou reativação de
capacidade autorizados.

Backup root-only da VPS:
`/var/backups/hch-worker/20260823T012700Z-pre-b8a070b`.

## Plano de rollback não executado

Os passos abaixo permanecem preparados para uma janela explicitamente
autorizada. Nenhum rollback foi executado nesta validação.

### Mac

Execute `control-stop` se houver assignment, descarregue o LaunchAgent, repunte
`/usr/local/libexec/hch-editorial-runtime` para o alvo anterior registrado no
backup e recarregue em capacidade zero.

### VPS

Execute `hch-editorial-workerctl stop`, aguarde o assignment zerar, pare o
supervisor, restaure unit, symlink, configuração e estado a partir do backup
root-only, execute `systemctl daemon-reload` e inicie somente em drain. Não
reative simultaneamente o supervisor e os timers legados.

## Critério de promoção

`3.1.0` só deve ser tratado como versão operacionalmente promovida em um nó
depois de `pending-review` real, retorno a drain e verificação pós-canário. Um
kit instalado, um heartbeat válido ou um ensaio Ollama isolado não substituem
essa evidência.

## Estado de release e decisão

- versão declarada no código: `3.1.0`;
- estado reconhecido: fix candidato, sem runtime validado;
- canário: bloqueado e não autorizado;
- deploy: bloqueado e não autorizado;
- claims Mac/VPS: fechados, capacidade `0/0`;
- tag, release, PR e integração em `main`: não realizados.

Decisão atual: **no-go**. Uma futura autorização de canário deve exigir estado
drenado comprovado, suíte determinística verde, evidência editorial
reproduzível, capacidade temporária máxima `1`, fechamento imediato após um
único claim e retorno confirmado a capacidade zero. Falha em qualquer gate
mantém o drain e aciona somente o plano de rollback previamente aprovado.
