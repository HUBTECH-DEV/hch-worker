# ADR-0006: Compatibilidade de runtime, conteúdo e atualização

- Status: Aceito, bloqueado por mudança aditiva no HCH
- Data: 2026-09-01

## Contexto

Wire protocol, documento OpenAPI, bootstrap, runtime e conteúdo editorial têm
versões distintas. O contrato atual exige igualdade exata de runtime e publica
toda atualização como obrigatória, o que impede coexistência segura 3.1.x/4.0.0.

## Decisão

O manifesto assinado deve separar:

- `latestAvailableWorkerVersion` — versão recomendada para download;
- `minimumRequiredWorkerVersion` — menor runtime ainda aceito;
- `acceptedWorkerVersions` ou faixa equivalente — runtimes que podem atestar;
- `contentContractHash` — tudo que pode alterar o resultado editorial;
- `protocolCompatibility` — wire protocol e schemas aceitos;
- `updateMode` — `available`, `recommended` ou `required`;
- compatibilidade de cada modelo por tipo de conteúdo.

Uma versão apenas disponível gera aviso e continua processando. Um manifesto
compatível pode renovar trust/readiness sem cancelar jobs ou impor apply de
artefato. Expiração do manifesto de download não invalida conteúdo já aplicado
e ainda dentro da sua janela operacional.

Mudança incompatível bloqueia novos claims e entra em drain; jobs ativos só são
interrompidos por stall, ausência de progresso no limite assinado, erro do
gerador, lease perdido ou `Stop` do operador. Uma diferença só é classificada
como incompatível editorial quando altera o contrato ou o resultado gerado.

Seleção de modelos é política assinada, medida por tipo de material e promovida
somente com benchmark e aprovação humana. Não há fallback silencioso.

## Regra de transição

Antes do canário, a frota suportada deve convergir para a ponte 3.1.1. Durante
o canário, 3.1.1 e 4.0.0 permanecem aceitos; a migração direta de uma instalação
3.1.0 continua possível, mas não substitui a evidência de transição integral da
frota. A promoção de 4.0.0 não
reescreve `minimumRequiredWorkerVersion` até a janela de compatibilidade ser
encerrada por decisão explícita.
