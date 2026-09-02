# ADR-0001: Worker Windows 4.0.0 nativo em C#

- Status: Aceito
- Data: 2026-09-01
- Decisores: HubTech

## Contexto

O Worker Windows 3.1.0 registra um serviço no SCM, mas o host ainda supervisiona
PowerShell e Node.js. Isso exige runtime auxiliar instalado, amplia a superfície
de atualização e dificulta obter um serviço realmente independente de terminal.

## Decisão

O Worker Windows 4.0.0 será um produto público e único no repositório
`HUBTECH-DEV/hch-worker`, compilado para `net10.0-windows` e distribuído de forma
self-contained. Serviço, tray, Options, onboarding e instalador serão assinados,
versionados e atualizados juntos.

A solução será separada em:

- `Hch.Worker.Core` — estado operacional, capacidade, scheduler e contratos de domínio;
- `Hch.Worker.Protocol` — JCS, Ed25519, HTTP Message Signatures e DTOs do protocolo 2.0;
- `Hch.Worker.Service` — processo único registrado no SCM;
- `Hch.Worker.Ollama` — streaming NDJSON e geração editorial;
- `Hch.Worker.Persistence` — journals, migração e gravação atômica;
- `Hch.Worker.IPC.Contracts` — protocolo local estrito e versionado;
- `Hch.Worker.Tray` — WPF com `NotifyIcon` e janela Options;
- `Hch.Worker.Installer` — MSI/EXE, upgrade e rollback;
- `Hch.Worker.Tests` — unidade, contrato, integração, UI e instalador.

O serviço inicia no boot sem usuário conectado e sempre entra em `Paused/Drain`
após instalação, atualização ou recuperação. Nenhuma dessas operações habilita
claims automaticamente.

## Consequências

- PowerShell e Node.js continuam apenas na linha histórica 3.1.0 e em ferramentas
  de desenvolvimento; não fazem parte do runtime instalado 4.0.0.
- O tray é um processo de sessão, não um segundo serviço.
- O port somente pode ser promovido quando os vetores criptográficos e o ciclo
  editorial forem equivalentes ao protocolo atual.
- A versão 3.1.0 permanece recuperável durante o canário e a janela de rollback.
