# HCH Worker 4 Linux host

Primeiro host executável headless do candidato 4.0.0. O projeto vincula os
fontes de domínio e Service existentes e troca apenas as bordas do sistema
operacional. O assembly e o apphost publicados se chamam
`Hch.Worker.Service`, alinhados ao pacote operacional Linux.

O host sempre compõe `WorkerControlState` em `Paused`, capacidade zero e sem
autorização de claim. O controle local usa Unix Domain Socket autenticado por
`SO_PEERCRED`, em `/run/hch-worker/control.sock` por padrão. O UID do serviço
pode executar os comandos do contrato v2; UID 0 é restrito a
`PrepareMaintenance`. Não existe fallback TCP. Uma tentativa explícita de
`Start` somente pode habilitar claims depois que a guarda de cutover comprovar,
de forma fail-closed, pidfile seguro, units legadas inativas/desabilitadas e
ausência de processo conflitante para o mesmo node. Boot e bootstrap continuam
sempre em Drain.

`HCH_WORKER_CONTROL_SOCKET` altera o caminho somente para ambientes controlados
como testes. O diretório e o socket precisam pertencer ao UID do processo e são
forçados a `0700` e `0600`, respectivamente. Um caminho preexistente, inclusive
socket antigo, é recusado em vez de removido sem prova de propriedade.

Build e publicação bloqueados pelo lockfile Linux:

```sh
/home/pjunior/.dotnet/dotnet restore \
  src/linux/Hch.Worker.Service.Linux/Hch.Worker.Service.Linux.csproj \
  -r linux-x64 -p:HchLinuxBuild=true -p:RestoreLockedMode=true
/home/pjunior/.dotnet/dotnet publish \
  src/linux/Hch.Worker.Service.Linux/Hch.Worker.Service.Linux.csproj \
  -c Release -r linux-x64 --self-contained true --no-restore \
  -p:HchLinuxBuild=true -p:RestoreLockedMode=true
```

O smoke test requer o diretório privado indicado pela fixture e deve terminar
por timeout, não por falha do host:

```sh
install -d -m 0700 /tmp/hch-worker-linux-host-smoke/state
HCH_WORKER_CONFIG_PATH="$PWD/src/linux/Hch.Worker.Service.Linux/test/smoke-config.json" \
  timeout --signal=TERM 5s \
  src/linux/Hch.Worker.Service.Linux/bin/Release/net10.0/linux-x64/Hch.Worker.Service
test "$?" -eq 124
```

Os testes Linux exercitam framing, credenciais do peer, permissões do socket,
Pause, a guarda de cutover e a recusa fail-closed de Start:

```sh
/home/pjunior/.dotnet/dotnet test \
  src/linux/Hch.Worker.Linux.Tests/Hch.Worker.Linux.Tests.csproj \
  -c Release -r linux-x64 -p:HchLinuxBuild=true -p:RestoreLockedMode=true
```

Limitações abertas: cliente/CLI Linux, atestação do PID dono do listener Ollama,
provisionamento inicial de identidade, enrollment local e testes de canário. O
guard Ollama aceita nesta etapa somente processos executados por
`root` ou pelo mesmo UID do Worker; instalações com usuário `ollama` separado
permanecem fail-closed até a política de UID explícita ser implementada.
