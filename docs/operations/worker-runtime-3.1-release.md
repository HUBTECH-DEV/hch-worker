# HCH Worker Runtime 3.1.0

O incremento 3.1.0 unifica Windows, Linux e macOS em um serviço contínuo que
possui e supervisiona o painel local em `http://127.0.0.1:4319`. O painel não é
mais uma tarefa ou daemon independente.

## Contrato operacional

- `start`: volta a aceitar claims usando o último paralelismo positivo;
- `pause`: define capacidade local zero, bloqueia claims novos e preserva os
  assignments em execução;
- paralelismo `0`: equivale a `pause`; valores `1..64` definem o teto local,
  ainda limitado pela concessão do orquestrador;
- `stop`: bloqueia claims, aborta os geradores ativos e envia `fail` com código
  `operator-stop-requested`. Se a API estiver indisponível, o journal local
  conserva a evidência para reconciliação.

O dashboard aceita somente essas ações fechadas. Não recebe comandos, paths,
scripts, configuração de bootstrap ou segredos pelo navegador.

## Modelo por sistema operacional

- Windows: o executável nativo registrado no SCM cria o dashboard como filho
  direto de Node.js. A instalação confirma a resposta HTTP antes de remover a
  Scheduled Task legada.
- Linux: `hch-editorial-worker.service` executa `worker.mjs supervise`; o mesmo
  processo mantém heartbeat, pool de trabalho e dashboard.
- macOS: o LaunchAgent de ciclo usa `KeepAlive` e `supervise`. O instalador
  remove o LaunchAgent de heartbeat legado para evitar pulsos concorrentes.

Falhas do dashboard usam reinício limitado com backoff e não derrubam o ciclo
editorial. Parar o serviço pelo gerenciador do SO continua sendo encerramento
administrativo do host; a ação `stop` do painel deve ser usada quando os jobs
precisam ser cancelados e relatados.

## Migração e rollback

Atualize os artefatos de runtime, instale novamente a integração nativa e
confirme: serviço ativo, dashboard respondendo apenas em loopback, tarefa/agente
legado ausente e `status` em drain. A atualização não abre claims sozinha.

O rollback reinstala 3.0.0 e restaura sua definição anterior. Jobs já relatados
como `operator-stop-requested` não são reabertos pelo rollback.

O procedimento de build, assinatura, reputação e tratamento de falsos positivos
está em [windows-worker-release-trust.md](./windows-worker-release-trust.md).
