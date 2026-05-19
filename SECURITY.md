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

## Threat model summary

The full threat model is in `docs/architecture.md` §11; the highlights:

- **Trust roots:** Ed25519 publisher key in the operator's keyring (primary)
  plus sigstore/cosign signatures on release tarballs (secondary). Both must
  verify before a plugin loads.
- **Primary attacker classes:** a malicious plugin publisher; a malicious peer
  on the mesh; a malicious local user with shell access on the same host.
- **Explicit non-goals:** the runtime does **not** defend against an attacker
  who already has root on the same host, nor against side-channel attacks
  between plugins co-tenanted on the same OS sandbox primitive. Tier-5 is an
  honest escape hatch — it sits behind Landlock/Seatbelt and can be disabled
  globally with `plugin.max_tier_allowed = 4`.
- **Cross-node tokens** use biscuit-auth; tokens can only ever attenuate,
  never widen — enforced by `entangle-biscuits::verify_bridge` plus the
  five mandatory bridge-attenuation facts (`dest_pin`, `rate_limit`,
  `total_bytes_cap`, `ttl_le_3600s`, `bridge_marker`).
- **Rate limiting** is a deliberate non-goal at the runtime layer: the
  daemon does not throttle peers. Operators wanting per-peer fairness
  install it as a `mesh.policy` plugin.

## Acknowledgement

Reporters who follow responsible disclosure will be credited in the release notes (with their consent) and listed in `docs/security/hall-of-fame.md` once the project ships its first release.
