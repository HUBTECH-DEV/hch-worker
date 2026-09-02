# ADR-0003: Identidades distintas do usuário e do Worker

- Status: Aceito, bloqueado por mudança aditiva no HCH
- Data: 2026-09-01

## Decisão

Existem duas identidades Ed25519 independentes:

- a chave SSH do usuário, gerada ou escolhida na sessão do usuário;
- a chave operacional exclusiva do Worker, gerada e protegida no contexto da máquina.

O servidor persiste somente chaves públicas, fingerprints, finalidade, tenant,
proprietário, `nodeId` e auditoria. Chave privada nunca é exibida, copiada,
enviada, registrada em log ou incluída em diagnóstico.

A associação usa quatro vínculos explícitos: usuário→tenant, usuário→chave SSH,
usuário→Worker e Worker→chave operacional. Cada chave deve provar posse de um
nonce do servidor antes da ativação e pode ser revogada independentemente.

Para a chave SSH do usuário, o padrão é:

```text
%USERPROFILE%\.ssh\id_ed25519_hch_<node-id>
%USERPROFILE%\.ssh\id_ed25519_hch_<node-id>.pub
```

Arquivos existentes nunca são sobrescritos. Caminhos customizados devem ser
absolutos e locais; UNC, rede, mídia removível, symlink e reparse point são
rejeitados.

A identidade operacional usa Ed25519 RFC 8032 implementado no projeto isolado
`Hch.Worker.Security`. Como os reference assemblies do .NET SDK 10.0.400 não
expõem uma API BCL geral de Ed25519 e CNG não oferece esse contrato de forma
portável nas versões Windows homologadas, a implementação usa somente
`BouncyCastle.Cryptography` 2.7.0, com versão exata e `packages.lock.json`.

A seed privada permanece em um objeto opaco e descartável. PKCS#8 só pode sair
por chamada explícita no limite de persistência; o buffer deve ser imediatamente
protegido com DPAPI `LocalMachine`, zerado e gravado sob ProgramData com ACL para
serviço, SYSTEM e Administradores. DTOs, logs e diagnósticos expõem apenas SPKI,
OpenSSH público e fingerprint. Credential Manager guarda somente token opaco,
revogável e de curta duração; não guarda senha nem chave privada.

## Mudança necessária no HCH

O contrato atual `owner-key-mismatch` compara os dois materiais públicos. Ele
deve ser substituído por vínculo, prova de posse e auditoria antes do onboarding
4.0.0 ser habilitado em produção.
