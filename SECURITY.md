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

**In scope (Phase 1):**
- `entangle-runtime`, `entangle-host`, `entangle-broker` — kernel and capability enforcement.
- `entangle-signing` — Ed25519 publisher signing, keyring, artifact verification.
- `entangle-manifest` — manifest parsing and tier validation.
- `entangle-cli` and `entangled` daemon — local-only mode (UDS RPC).

**Out of scope (Phase 2+):**
- Mesh transports (`mesh.local`, `mesh.iroh`, `mesh.tailscale`) — not implemented yet.
- Distributed compute scheduler — not implemented yet.
- Agent host plugin (Claude Code/Codex MCP gateway) — not implemented yet.
- Integrity policies (`Deterministic`, `SemanticEquivalent`, `TrustedExecutor`, `Attested`) — types only at present.

Reports against unimplemented features are welcome but will be tracked as design issues, not security advisories.

## Defense in depth

Per spec §3.6 the primary trust root is the publisher Ed25519 key in the user's keyring; sigstore/cosign signatures are added on release artifacts as a secondary check. Both must verify before a plugin loads.

Per spec §11 #16 the daemon refuses to start in multi-node mode without a populated peer allowlist; single-node mode is permitted with no allowlist.

## Acknowledgement

Reporters who follow responsible disclosure will be credited in the release notes (with their consent) and listed in `docs/security/hall-of-fame.md` once the project ships its first release.
