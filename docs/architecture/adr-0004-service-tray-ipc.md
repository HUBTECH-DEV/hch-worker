# ADR-0004: IPC seguro entre serviço e tray

- Status: Aceito
- Data: 2026-09-01

## Decisão

Serviço e tray se comunicam por Named Pipe local, byte-framed e versionado. O
pipe é criado pela API nativa com `PIPE_REJECT_REMOTE_CLIENTS`, primeira
instância exclusiva e DACL protegida para SYSTEM, Administradores, SID do
serviço e SID do proprietário autorizado. O serviço obtém o SID por
impersonação em nível de identificação e valida a relação de propriedade após a
conexão; possuir acesso ao nome do pipe não autoriza comandos.

Cada mensagem tem versão, request ID, tipo, timestamp e payload limitado. A
lista de comandos é fechada:

- `GetSnapshot`;
- `Start`;
- `Pause`;
- `Stop`;
- `SetMaxConcurrentJobs`;
- `BeginEnrollment` e mensagens estritamente tipadas do onboarding;
- `ExportSanitizedLogs`.

O IPC rejeita shell, script, executável, argumento livre, path arbitrário,
serialização polimórfica e campos desconhecidos. Senha e chave privada nunca
atravessam o pipe. Token de enrollment pode ser entregue apenas por um canal
efêmero autenticado, consumido uma vez e imediatamente zerado da memória. Quando
a retomada exige persistência, somente esse token revogável pode usar Credential
Manager, em namespace fixo; senha e chave privada continuam proibidas.

Fechar o tray ou Options não altera o serviço. Parar o SCM é uma operação
administrativa diferente do comando operacional `Stop`.
