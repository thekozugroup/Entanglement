# Security Policy

## Reporting a Vulnerability

Email **security@entanglement.dev** with:

- A description of the issue.
- The smallest reproducer you can produce.
- Affected version (commit SHA or release tag).
- Impact assessment if you have one.

A PGP key will be linked here once published; until then, plaintext email is acceptable but please do not include exploit code in plaintext for issues you believe are critical — instead, ask for an encrypted channel.

## Response timeline

- **Acknowledgement:** within 3 business days.
- **Triage:** within 7 business days.
- **Fix or detailed plan:** within 30 days for high/critical severity.
- **Public disclosure:** target 90 days from report, coordinated with the reporter.

## Scope

Report suspected vulnerabilities in the code shipped by this repository, including the following components.

- Signed plugin packaging, the publisher keyring, local and OCI installation, and release verification.
- The manifest validator, Wasmtime host, capability broker, daemon socket, and backup and recovery commands.
- Pairing, peer discovery, the optional tailnet adapter, authenticated QUIC work, bridge delegation, and the distributed scheduler.
- Streaming tasks, replica verification, and the optional host-configured inference provider.

Include the transport, trust role, operating system, and relevant configuration when they affect the report. Use a fresh test identity in any material you share. Design concerns about proposed features are also welcome.

## Security boundaries

The kernel verifies a plugin package with a trusted Ed25519 publisher key. The separate `entangle release verify` command checks the publisher signature on a release archive and its Sigstore bundle against the expected release workflow and tag. Operators need an independently trusted release publisher key. [Release verification](./docs/install.md)

The daemon checks its configured peer allowlist at multi-node startup. Discovery can supply an address. Remote work also requires an authenticated peer with a permitted role. A bridge grant binds the destination and includes rate, cumulative byte, and expiry limits. [Bridge authorization](./docs/testing/bridge-authorization.md)

The package loader executes supported WebAssembly components under Wasmtime. The optional tier-5 inference provider connects to an operator-configured local service. That service runs with the isolation and permissions of its own process. The OS sandbox check in `entangle doctor` reports host capabilities. Native agent-host execution still requires a sandboxed supervisor. Set `[security] max_tier_allowed` in the daemon configuration to limit the permitted tier. [Operational controls](./docs/operations.md)

The threat model covers untrusted plugin publishers, untrusted peers, and unprivileged local users. Host root compromise and side channels between co-tenants are outside the isolation guarantee. [Threat model](./docs/architecture.md)

## Acknowledgement

Reporters who follow responsible disclosure will be credited in the release notes (with their consent) and listed in `docs/security/hall-of-fame.md` once the project ships its first release.
