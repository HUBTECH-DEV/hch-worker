# HCH Worker Desktop — decisão de distribuição do Beta

Status: decisão de arquitetura implementável  
Data: 2026-08-29

## Decisão

Adaptar o worker existente e reconstruir somente a camada distribuída ao usuário.

- Preservar contratos, Ed25519, manifesto, attestation, heartbeat, leases, geração local, revisão humana, telemetria e controles já testados.
- Preservar o shell Beta do orquestrador.
- Criar um aplicativo desktop proprietário separado para onboarding, pareamento HIH, tray, cofre local, WebUI e atualização.
- Manter o repositório público atual como protocolo/worker legado MIT. Código já publicado sob MIT não pode ser tornado retroativamente secreto.

## Arquitetura do produto

### Beta rápido

- Shell: Tauri 2.
- Frontend: a WebUI local reutilizada, empacotada sem source maps.
- Runtime: módulos atuais agrupados num único script e embutidos como Node SEA sidecar.
- Comunicação: IPC allowlisted entre Tauri e sidecar; painel exclusivamente loopback.
- Inferência: Ollama por HTTP local, sem exposição pública.

Node SEA elimina a distribuição de uma árvore de JavaScript solta, mas não impede engenharia reversa. Ele é uma ponte para o Beta, não a proteção final do núcleo.

### Produto definitivo

Portar incrementalmente para Rust:

1. identidade Ed25519 e cofre local;
2. cliente do orquestrador e pareamento HIH;
3. journal/state machine;
4. supervisor, capacidade e controle;
5. updater e rollback;
6. adaptador Ollama.

Os contratos JSON, testes vetoriais e a API do orquestrador permanecem estáveis durante a troca.

## Um aplicativo, cinco visões

Não criar cinco binários. O mesmo aplicativo oferece:

1. Contribuição — padrão recomendado;
2. Atividade e transparência;
3. Desempenho técnico;
4. Impacto comunitário;
5. Modo discreto/tray e preferências.

## Instaladores

| Sistema | Beta | Evolução |
|---|---|---|
| Windows | NSIS `.exe` x64 + MSI x64, Authenticode | arm64 e MSIX |
| macOS | `.app` + DMG arm64 e x86_64, Developer ID, notarização e stapling | binário universal |
| Linux | `.deb` Ubuntu 24.04 amd64 | arm64, RPM e AppImage |

O processo é por usuário no Beta:

- Windows: autostart do usuário;
- macOS: LaunchAgent;
- Linux: `systemd --user`.

Serviço global de máquina fica fora do Beta porque complica autoria, logout, múltiplos usuários e armazenamento de credenciais.

## Cofre e limites de dados

- macOS: Keychain;
- Windows: Credential Manager/DPAPI;
- Linux: Secret Service/libsecret;
- headless futuro: systemd credentials e, quando disponível, TPM2.

O worker não armazena senha, cookie ou token HIH. No pareamento Beta ele guarda apenas chave Ed25519, identificadores do pareamento estritamente necessários e recibo assinado do HCH. CPF, passaporte, endereço e contatos permanecem no HIH.

## Assinatura e atualização

Uma release exige três provas separadas:

1. assinatura/notarização do sistema operacional;
2. assinatura obrigatória do pacote de atualização;
3. autorização do protocolo HCH para substituir o executável somente após drain.

O canal de update deve produzir checksums, SBOM e provenance, usar rollout gradual `beta`/`stable` e provar rollback.

## Organização dos repositórios

- `HUBTECH-DEV/hch-worker`: público/MIT, protocolos, schemas, vetores e worker legado;
- `HUBTECH-DEV/hch-worker-orchestrator`: privado, fila e control plane;
- novo repositório privado proprietário para o desktop/core, nome sugerido `hch-worker-desktop`.

O novo repositório deve conter EULA, `THIRD_PARTY_NOTICES`, SBOM, política de vulnerabilidades e pipeline de release. A organização/destino remoto deve ser confirmada antes da criação porque o código proprietário não deve entrar no repositório público.

## Gates de release

- pareamento real pelo navegador e sessão HIH;
- gate de perfil completo e consentimento;
- attribution congelada em assignment e geração;
- nenhum token ou PII em logs, UI, state, crash report ou pacote;
- painel apenas loopback, Origin/Host/CSRF validados;
- instalador/upgrade/uninstall em VM limpa por plataforma;
- assinatura, notarização e updater verificados;
- SBOM, checksum e varredura de segredos;
- um canário controlado chega a `pending-review`; publicação automática continua ausente.

## Sequência de PRs

1. contrato de pareamento e elegibilidade;
2. atribuição no orquestrador;
3. Worker Beta/WebUI fail-closed;
4. scaffold privado Tauri 2 + cofre + tray;
5. sidecar Node SEA e paridade de testes;
6. Windows EXE/MSI;
7. macOS DMG notarizado;
8. Linux DEB;
9. updater, rollout e rollback;
10. portabilidade progressiva para Rust.
