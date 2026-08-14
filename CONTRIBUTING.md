# Contributing

Contributions should preserve the same signed-manifest protocol and fail-closed behavior across Windows, Linux, and macOS.

Before opening a pull request:

1. Run the relevant platform tests.
2. Keep the local dashboard bound to loopback only.
3. Do not add remote-shell or arbitrary-command execution paths.
4. Do not commit secrets, private keys, enrollment tokens, production manifests, or machine-local configuration.
5. Document any change to the public protocol or trust boundary.
