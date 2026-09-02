# ADR-0002: Migração e rollback do Worker Windows 3.1.0

- Status: Aceito
- Data: 2026-09-01

## Decisão

O 4.0.0 será instalado lado a lado com o 3.1.0. Quando existir
`C:\ProgramData\HCH\EditorialWorker`, o instalador não pode gerar outro
`nodeId` nem outra identidade. Ele executa uma migração transacional que
preserva exatamente o `nodeId`, a identidade operacional Ed25519 e os limites
locais, sem apagar, mover ou alterar qualquer arquivo da origem.

Estado assinado do runtime 3.1.0 não vira prontidão 4.x. `trust-state.json`,
`applied-manifest.json`, `ready.json`, enrollment legado, pending operations,
journals e evidências de update são retidos no backup imutável e descritos no
journal de migração. O único material de trust projetado no destino é o PEM
público raiz, depois de recalcular e conferir seu fingerprint contra o pin do
`trust-state` legado. O 4.x reconstrói manifesto, trust state, readiness e
atestação pelo protocolo atual, sempre em `Paused/Drain` e capacidade zero.

Antes da troca, o instalador deve:

1. derivar o nome SCM legado a partir do `nodeId` com o mesmo algoritmo do
   3.1.0 e comprovar que o serviço está `Stopped`, sem PID e com os locks de
   escrita disponíveis;
2. bloquear se houver `active-batch.json`, capacidade/progresso ativo, journal
   não terminal ou qualquer operação pendente — em especial `complete-*` e
   `fail-*`; apenas reconciliação confirmada no orquestrador libera a troca;
3. ler o PSD1 sem executar PowerShell e exigir os caminhos canônicos sob a raiz
   legada;
4. validar `identity.json` schema 2, `nodeId`, algoritmo e formatos; recalcular o
   fingerprint da SPKI pública, importar a privada PKCS#8 e provar que ambas
   formam o mesmo par Ed25519 e coincidem com `keyId`;
5. copiar `config`, `state` e `trust` para um backup create-only sob o estado
   privado 4.x, registrando SHA-256 de todos os arquivos, ACLs em SDDL e um
   receipt da definição do serviço SCM;
6. repetir inventário e preflight depois do backup e falhar se bytes, ACLs,
   serviço ou locks tiverem mudado;
7. converter a privada PKCS#8 somente em memória para PKCS#8 normalizado
   protegido por DPAPI `LocalMachine`, zerando os buffers temporários;
8. mapear `lastNonZeroParallelism` para `LastNonZeroMaxConcurrentJobs` e, pela
   semântica agregada do 3.1.0, também para o `ClaimBatchSize` inicial; publicar
   o controle como `Paused/Drain`, nunca como `Running`;
9. publicar identidade, PEM público raiz e por último `config.json`, com journal
   durável antes de cada rename atômico;
10. instalar/iniciar o novo serviço sem habilitar claims. Bootstrap, atestação e
    um `Start` explícito continuam sendo gates separados.

Se o formato, o par de chaves, o fingerprint, o `nodeId`, os ACLs ou o estado do
serviço não puderem ser provados, a migração falha fechada. Não há TOFU,
regeneração silenciosa de identidade nem fallback que apenas copie o trust.

O rollback consulta o journal e remove somente os artefatos que o migrador
registrou como inexistentes antes da transação e cujo hash ainda coincide. Um
arquivo alterado depois da migração bloqueia o rollback em vez de ser apagado.
Backup e journal permanecem como evidência; arquivos não relacionados e toda a
origem 3.1.0 permanecem intactos. O rollback não regenera trabalho, não apaga a
chave legada e não ignora commit ambíguo. Somente uma reconciliação concluída
pode liberar a troca de versão.

## Critério de promoção histórica

O 3.1.0 só recebe a classificação de versão histórica depois de um canário 4.0.0
com paralelismo 1 comprovar enrollment, bootstrap, heartbeat, claim, progresso,
complete/fail, restart e rollback. Histórico significa não recomendado para nova
instalação, nunca removido como opção de recuperação.
