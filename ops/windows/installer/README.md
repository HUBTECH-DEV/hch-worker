# Instalador do HCH Worker para Windows

O caminho recomendado para uma instalação individual é o `Setup.exe`. Ele:

- solicita apenas URL do orquestrador, nome do nó, token e paralelismo;
- mantém o token fora da linha de comando e o remove da máquina ao concluir;
- gera a identidade Ed25519 localmente;
- instala o serviço nativo, o painel local e o Node.js assinado;
- preserva `parallelism = 0` como pausa sem desativar heartbeat ou prontidão;
- abre o painel somente em `http://127.0.0.1:4319`.

## Build

Execute em PowerShell a partir da raiz do repositório:

```powershell
.\ops\windows\installer\Build-HchWorkerSetup.ps1 `
  -NodePath 'C:\caminho\seguro\node.exe' `
  -RootPublicKeyPath 'C:\caminho\orchestrator-root.pem'
```

O Node.js precisa ter assinatura Authenticode válida. Quando
`HCH_WINDOWS_PUBLISHER_THUMBPRINT` estiver definido, o Setup também será
assinado e timestamped. Os artefatos locais ficam em `artifacts/`, que não deve
ser versionado.

O build também gera o manifesto de instalador para `winget`. A publicação no
catálogo comunitário só deve ocorrer depois que a mesma URL de release estiver
pública e o hash do artefato tiver sido confirmado.

## Segurança do enrollment

O formulário grava a resposta em um arquivo temporário com ACL restrita ao
usuário e Administradores. O script elevado usa o token somente durante o
enrollment, restaura o valor anterior da variável de máquina e apaga o arquivo
em `finally`. Token e chave privada não entram no pacote, logs ou argumentos de
processo.
