# Raiz de confiança do orquestrador

Instale `orchestrator-root.pem` neste diretório, ou no caminho indicado por
`RootPublicKeyPath`, usando um canal autenticado fora da API do orquestrador.
A chave precisa ser uma chave pública Ed25519 em SPKI PEM.

O kit não baixa nem substitui essa raiz pela API. Uma delegação de release só
é aceita depois de validada por essa chave pinada. Chaves privadas de workers
ficam em `StateRoot\identity` com ACL restrita ao usuário do serviço e a
`SYSTEM`; elas nunca são enviadas ao orquestrador.

Depois da verificação completa da cadeia, `StateRoot\trust-state.json`
persiste a maior sequência de delegação já aceita e o hash SHA-256 JCS do
envelope. Uma sequência menor é recusada mesmo antes da expiração da delegação;
a mesma sequência com outro hash é tratada como equivocação. Uma sequência
maior substitui simultaneamente as duas âncoras.

Não copie uma chave de exemplo para produção: este repositório não contém
nenhuma raiz válida.
