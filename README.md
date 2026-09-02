# HCH Worker

Public, cross-platform worker runtime for the HubTech Community Hub (HCH).

The repository contains the worker clients for Windows, Linux, and macOS, the loopback-only local dashboard, public protocol contracts, installer tooling, signature verification, and tests. The central orchestrator, administrative portal, enrollment-token database, production manifests, and private keys are intentionally maintained outside this repository.

## Release lines

- Windows: **4.0.0 candidate**, implemented as a native, self-contained .NET
  10 Windows Service and WPF tray application. It remains `Paused/Drain` after
  install, update, recovery, or onboarding until the owner explicitly selects
  **Start**.
- Linux and macOS: **3.1.0 stable source line**. The final generic
  **3.1.1 compatibility bridge** is prepared by the guarded bridge workflow so
  3.1 clients can discover OS-specific releases without stopping healthy work.

The 4.0.0 number identifies the Windows candidate source and binaries. It is
not an official release until the signed MSI, disposable lifecycle test,
sustained canary, rollback, and fleet-transition gates have all passed. The
3.1.0 Windows runtime is not historical before those gates pass.

## Platforms

- Windows: native C# Windows Service, WPF tray/options/onboarding, secure
  versioned Named Pipe IPC, and a WiX MSI. The installed runtime has no
  PowerShell, Node.js, or open-terminal dependency.
- Linux: long-lived systemd service and portable Node.js runtime.
- macOS: launchd integration over the portable runtime.

## Security boundary

Workers verify signed manifests and immutable generation plans before processing. Private worker identity keys remain local. This repository contains no enrollment tokens, production credentials, private signing keys, portal database code, or orchestrator deployment configuration.

The shared [`contentContractHash` compatibility contract](docs/manifest-content-compatibility.md) separates signed content inputs from operational manifest metadata.

See [SECURITY.md](SECURITY.md) and the platform READMEs under `ops/` before installing.

## Windows 4.0 development checks

The source-only gates do not require accepting the WiX license:

```powershell
dotnet restore src/windows/Hch.Worker.sln --locked-mode --runtime win-x64 -p:PublishReadyToRun=true
dotnet format src/windows/Hch.Worker.sln --verify-no-changes --no-restore
dotnet test src/windows/Hch.Worker.sln --configuration Release --no-restore
./scripts/windows/Test-HchWorkerInstallerSource.ps1
./scripts/windows/Test-HchWorkerReleaseWorkflow.ps1
# External production gate; it intentionally fails until HIH/HAH/HCH routes are deployed.
./scripts/windows/Test-HchWorkerOnboardingEndpoints.ps1
```

Building an MSI requires an explicit organizational review and acceptance of
the WiX 7 terms. Signing, release creation, installation, and canary execution
are separate protected operations. See
[`docs/operations/windows-worker-4.0.0-readiness.md`](docs/operations/windows-worker-4.0.0-readiness.md),
[`docs/operations/windows-worker-v4-installer.md`](docs/operations/windows-worker-v4-installer.md),
and [`docs/operations/windows-worker-v4-promotion.md`](docs/operations/windows-worker-v4-promotion.md).

## Portable-runtime tests

```bash
npm test
```

Platform-specific test commands are available in the root `package.json`.

## License

MIT License. See [LICENSE](LICENSE).
