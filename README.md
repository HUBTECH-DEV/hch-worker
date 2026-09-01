# HCH Worker

Public, cross-platform worker runtime for the HubTech Community Hub (HCH).

The repository contains the worker clients for Windows, Linux, and macOS, the loopback-only local dashboard, public protocol contracts, installer tooling, signature verification, and tests. The central orchestrator, administrative portal, enrollment-token database, production manifests, and private keys are intentionally maintained outside this repository.

## Version

Current worker runtime: **3.1.0**.

## Platforms

- Windows: native Windows Service, PowerShell 5.1 control plane, and manual publisher trust.
- Linux: long-lived systemd service and portable Node.js runtime.
- macOS: launchd integration over the portable runtime.

## Security boundary

Workers verify signed manifests and immutable generation plans before processing. Private worker identity keys remain local. This repository contains no enrollment tokens, production credentials, private signing keys, portal database code, or orchestrator deployment configuration.

The shared [`contentContractHash` compatibility contract](docs/manifest-content-compatibility.md) separates signed content inputs from operational manifest metadata.

See [SECURITY.md](SECURITY.md) and the platform READMEs under `ops/` before installing.

## Tests

```bash
npm test
```

Platform-specific test commands are available in the root `package.json`.

## License

MIT License. See [LICENSE](LICENSE).
