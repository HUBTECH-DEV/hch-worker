# Compatibilidade de conteúdo do manifesto

O contrato compartilhado do Worker recalcula o `contentContractHash` informado
pelo manifesto assinado. A validação acontece dentro da cadeia comum
raiz → chave de release → manifesto, antes que qualquer implementação de
Windows, Linux ou macOS aceite o payload.

## Projeção canônica

As entradas definidas pelo protocolo como fronteira do conteúdo participam do
hash:

- `adaptiveWorkPolicy`;
- `artifacts`;
- `editorial.pipelineVersion`, `editorial.policyHash` e
  `editorial.promptConfigHash`;
- identidade completa de `engine`;
- parâmetros de `generation`.

O protocolo atual inclui a declaração completa de `artifacts` de forma
conservadora, inclusive seus metadados de distribuição. Restringir essa parte à
identidade dos bytes exigirá uma alteração coordenada no orquestrador e no
Worker; um dos lados não pode mudar a projeção isoladamente.

Metadados de release, validade, sequência, capacidade, endpoints e versão do
runtime ficam fora dessa projeção. Assim, uma renovação operacional pode ser
classificada como compatível sem interromper um Worker cujo contrato de conteúdo
permaneceu byte a byte equivalente.

O objeto projetado é serializado por RFC 8785 (JCS) e resumido com SHA-256 em
hexadecimal minúsculo. Esse algoritmo deve permanecer idêntico ao implementado
pelo orquestrador.

## Gate do bootstrap 2.3.0

Manifestos do bootstrap `2.3.0` devem declarar:

- `classification`: `initial`, `compatible` ou `content-incompatible`;
- `contentContractHash` e, quando existir, `previousContentContractHash`;
- `minimumWorkerVersion` e `testedThroughWorkerVersion`;
- `contentImpact`: `none` ou `generated-content`.

O Worker falha fechado quando a declaração está ausente, malformada ou quando o
hash declarado não corresponde ao payload assinado. A classificação também
deve ser coerente com a cadeia: `initial` exige hash anterior nulo,
`compatible` exige hashes atual e anterior idênticos, e
`content-incompatible` exige hashes diferentes e impacto
`generated-content`. Manifestos anteriores ao bootstrap `2.3.0` continuam
aceitos sem essa extensão para preservar a migração gradual.

## Transição operacional

O hash validado é persistido em `applied-manifest.json`, `ready.json`,
`status.json`, `trust-state.json` e na atestação enviada ao orquestrador.
Windows, Linux e macOS aplicam a mesma decisão:

- hash igual: renovam bootstrap/attestation e atualizam somente metadados
  atômicos; não baixam nem reaplicam artefatos, não fecham o gate de claims e
  não cancelam assignments ativos;
- hash diferente: invalidam `ready.json`, fecham novos claims e entram em
  drain; assignments ativos continuam até terminar e somente então o próximo
  bootstrap executa download, apply e self-test; o heartbeat de presença
  continua sendo enviado com capacidade de novos claims igual a zero;
- falha durante refresh compatível: a prontidão anterior permanece válida até
  `readyUntil`; a falha é registrada como refresh adiado, sem converter o
  Worker em `update-failed`;
- falha durante mudança de conteúdo: permanece fail-closed e exige nova
  tentativa depois de corrigida a causa.

O recibo de um refresh compatível usa `result: "no-change"`, mesmo quando a
sequência e o hash do envelope de manifesto avançam. O journal local registra
os hashes de conteúdo anterior e atual para tornar essa decisão auditável.

## Expiração e fallback

O fallback de expiração existe somente para continuidade temporária do
manifesto já aplicado. Se o JWS do manifesto, seu payload ou a delegação da
chave de release expirou, o Worker exige simultaneamente o mesmo
`manifestHash` e a mesma sequência persistidos. Uma delegação expirada nunca
autoriza um manifesto novo, ainda que o payload dele esteja dentro da própria
janela de validade e todas as assinaturas sejam criptograficamente corretas.

## Progresso concorrente

O supervisor portátil serializa as transições de estado do pool. O término de
um assignment não pode zerar `jobs.running` nem remover `currentBatch` enquanto
outro assignment continua ativo. `currentBatch` publica total iniciado,
terminados, falhos e ativos; cada heartbeat de assignment continua enviando
seu progresso individual e monotônico ao orquestrador.
