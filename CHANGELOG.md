# Changelog

All notable changes to Entanglement are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Covers the work since commit `43cdef5` (277 non-merge commits). Measured on `080ab0b`: 1552 tests passed, 0 failed, 10 ignored (624 / 0 / 28 before).

### Added

Transports and scheduling
- `mesh.tailscale` transport: liveness polling (active, stopped, uninstalled) with hysteresis.
- `mesh.tailscale`: mutually authenticated key exchange (X25519 + Ed25519), ChaCha20-Poly1305 sealed frames.
- `mesh.tailscale`: tailnet-only source filter, connection caps, `acl-mode` values `entangle-on-top` and `trust-tailnet` (alias `tailscale-only`).
- Protocol multiplexing and framed streams over Tailscale; the daemon serves the scheduler and stream protocols over it.
- Per-peer transport selection: local, then tailscale (only when active), then iroh; `[mesh] preferred` and `[mesh.overrides]`; fallback only on connect failure; transport label in metrics and diag.
- Hardware detection for scheduler adverts: memory, GPU backend and VRAM, NPU.
- `entangle diag mesh [--probe]`.

Integrity
- `SemanticEquivalent` with signed metric components (`entangle:integrity/metric` WIT), metric run on the verifier, output-size guard before the metric loads.
- Policy hash envelope (INV-INT-1) and `PolicyMutation` rejection.
- Per-peer per-policy reputation (EWMA).
- Majority hash quorum for `Deterministic` across distinct workers.
- Plugins `metric-bleu-4` and `metric-numerical-l2-relative`.

Streaming
- Streaming tasks: credit flow control, heartbeat with `PeerLost` after three missed pongs, signed chunks bound to the request, total-byte and chunk-count caps, partial-result policies.
- The daemon serves ALPN `entangle/stream/1` over Iroh and Tailscale; `stream-lines` plugin; `entangle compute stream` (dials over Iroh only).

Plugins and sandboxing
- New crate `entangle-sandbox`: Landlock (ABI probe), user and net namespace, seccomp socket-family filter, `no_new_privs`, rlimits, process groups; bubblewrap and Seatbelt profile generation.
- Tier-5 native plugins run under that sandbox; runtime-kind check (ATC-MAN-3); install refuses above the tier ceiling with no state change (ATC-MAN-4); `[security] allow_unsandboxed_native`.
- Capability grants for wasm plugins: `capability.fetch` through the broker, WASI preopens `/data`, `/shared`, `/shares/<n>`, `net.lan` and `net.wan` socket rules with pinned DNS, live revocation, `deny_capabilities`; stream plugins get the same grants.
- `entangle perms list|revoke`.
- Catalog plugins and the `native-echo` example.

Operations
- `entangle security set-max-tier`, `entangle config reload|validate`; lowering the ceiling drains in-flight calls and streams before unloading and records the unloaded plugins in `[plugins] disabled`; audit codes `W0214`, `I0215`, `I0216`, `I0217`.
- `entangle wrapper enable|disable|status|repair`; `doctor` detects shadowing; format-preserving config writer.
- `[plugins] disabled` is enforced at load by the daemon and the CLI's local kernel (`ENTANGLE-E0759`); `entangle plugins enable|disable <id>` (`enable` refused above the ceiling, `ENTANGLE-E0760`).
- `entangle backup` / `entangle restore`: passphrase-encrypted archive (Argon2id, XChaCha20-Poly1305, header as associated data) of identity, keyring and paired peers; restore is all-or-nothing and needs `--force` to replace an identity (`ENTANGLE-E0860`..`E0867`).
- Daemon `/metrics` endpoint (disabled by default, loopback by default); real metrics with bounded labels; `entangle metrics` over RPC.
- OTLP/HTTP JSON trace exporter (`http://` endpoints only); `traceparent` on the scheduler wire.

Agents
- MCP gateway HTTP server in `entangle-agent-host`: bearer auth, allow/deny policy, audit, stdio downstream servers, connection and size limits.
- `entangle agent run` with session-scoped configs for claude-code, codex and opencode; `--trust-project-servers` consent.
- HTTP downstream MCP servers (Streamable HTTP, JSON and SSE replies, `Mcp-Session-Id`, request-id remapping, cancellation on timeout); configured headers are sent, the gateway's bearer token never is; legacy `type: "sse"` servers are refused.

Distribution and release
- OCI registry client (token and basic auth, digest and size checks, redirects without leaking credentials); push and pull; `entangle plugins install oci://...`, `plugins publish`, `plugins tags`.
- Signed, expiring mirror listings with separate mirror keys (ATC-MIR-1/2); `entangle plugins mirror-sign`.
- Reproducible plugin archives, provenance, `entangle plugins verify --rebuild`; `Cargo.lock` required.
- `entangle release verify` (Ed25519 release key and cosign; the cosign identity is pinned to the artifact's tag, from `--tag` or the file name); `entangle release key split|combine` (Shamir secret sharing, 2-of-3 by default).
- `cargo xtask bus-factor` and `cargo xtask rotation-note-check`; `.github/workflows/reproducibility.yml`; `wasm32-wasip2` target in the CI test job.

Biscuits
- Bridge capability tests aligned with ATC-BRG-1..6; cumulative byte budget `BridgeBudget` (`ENTANGLE-E0425`).

Tests
- The §16 acceptance matrix gates: 35 of 35 IDs covered by live tests, no ignored-only IDs, no stubs. An audit strengthened 9 tests.

### Changed

- `entangle-mesh-tailscale` and `entangle-oci` are implemented (they were scaffolds).
- The workspace has 27 members (was 26).
- STATUS.md, README.md, tutorial, install guide and architecture status text updated to match the code.

### Fixed

- Pairing: the responder closed the connection before its final frame was delivered (36 of 100 runs failed under load before, 0 of 100 after).
- A gitignored test-only fixture key broke 17 tests on fresh checkouts; the key is now committed.
- Security fixes from review (each fix commit adds a test):
  - MCP gateway: a `tools/call` sent as a notification bypassed policy and audit.
  - MCP gateway: no header-read timeout or connection cap let a local process exhaust file descriptors; the audit log was capped by record count but not size.
  - OpenCode adapter wrote a config schema OpenCode does not read, so the user's servers bypassed the gateway.
  - Sandbox: the child now drops every capability, detaches from the parent's keyrings and cannot create namespaces; the opt-out keeps Landlock when only the network layer is missing.
  - Tailscale: established inbound connections are capped globally and per peer; pending handshakes are capped per source address.
  - Integrity: oversized answers refused by the transport or framing still trip INV-INT-2.
  - OCI: environment registry credentials are bound to `ENTANGLE_OCI_REGISTRY`.
  - Streaming: a stream's chunk count is capped, not only its bytes.
- Pairing: `PairingListener::wait()` could hang past the code's expiry when a dialer withheld QUIC stream credit, so `entangle pair --responder` kept its endpoint and mDNS beacon up past the advertised expiry.

### Deferred
- Biscuit capability tokens on remote paths (spec §6.6): remote tasks and streams are gated by the peer allowlist only; the broker can verify tokens but nothing presents one yet.

- `Attested` integrity: needs TEE hardware; returns `ENTANGLE-E0304`.
- Native Windows (Phase 5).
- bubblewrap and Seatbelt paths have not been run on a real host in this work (a Seatbelt test that runs `sandbox-exec` compiles only on macOS).
- Cross-host reproducibility and real cosign run only in CI; cosign identity is not pinned to the specific tag.
- Capability revocations last until the plugin is reloaded.
- OCI listing rollback protection (listings expire, but an older unexpired listing is accepted); a TLS handshake test for the OCI client.
- `RLIMIT_NPROC`, `RLIMIT_FSIZE`, cgroups and a per-host `net.wan` allowlist for native plugins.
- `entangle install`, `entangle logs`, `entangle upgrade`, `entangle trace task`.
- Bus-factor check fails by design (one holder per role).
- No published release; `install.sh` and Homebrew need a `v0.1.0` tag.
- In progress, not in this tree yet: Layer-2 1% replay spot-check; per-peer transport routing for `compute stream`; streaming invocation metrics.

### Earlier, before `43cdef5`

- Phase 1 architecture spec, tutorial, example plugins, Criterion benchmarks and the `.iterations/` sprint log.

## How releases work
1. Update this file under `## [Unreleased]`.
2. When ready, rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`.
3. Tag the commit `vX.Y.Z` and push. CI builds, signs, and publishes.
