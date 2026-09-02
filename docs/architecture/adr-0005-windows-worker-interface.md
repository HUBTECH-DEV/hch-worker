# ADR-0005: Tray, Options e onboarding do Worker Windows

- Status: Aceito
- Data: 2026-09-01

## Decisão

A interface será WPF com `NotifyIcon`, usando o layout “Central de Controle”. A
navegação lateral contém Visão geral, Trabalhos, Desempenho, Conexão, Identidade,
Logs, Atualizações e Preferências.

O tray oferece Start, Pause/Resume, Stop e Options, habilitados conforme o estado.
Ícones usam forma/overlay além de cor. Tooltip mostra nome, estado, trabalhos
ativos e idade do heartbeat.

Options separa estado do SCM e estado operacional e mostra, quando disponível,
CPU do Worker/sistema, memória atual/média/pico, GPU/VRAM, disco, rede, uptime,
versões, Ollama/modelo, conexão/latência/heartbeat, trust/readiness, capacidade,
jobs, progresso, throughput e último erro sanitizado. Ausência de coleta é
“Não disponível”, nunca zero inventado.

O primeiro uso permanece pausado e segue: serviço/conexão, conta HIH, chaves,
registro/enrollment e validação. A autenticação primária será “Entrar com o HIH”
no navegador do sistema com Authorization Code + PKCE/device flow. Campos
e-mail/senha só serão habilitados após existir endpoint desktop próprio; senha
vai somente ao HIH por TLS e permanece em memória pelo menor tempo possível.

Os textos auxiliares serão “Esqueci minha senha” e “Criar conta HubTech”, ambos
abrindo os fluxos oficiais do HIH.
