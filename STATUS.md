# Status

Snapshot of the code on `claude/pensive-darwin-8e8jd5` at commit `080ab0b`.
Nothing is tagged or released.

## Build health

Measured on `080ab0b`:

| Check | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `RUSTDOCFLAGS=-D warnings cargo doc` | clean |
| `cargo test --workspace` | 1552 passed, 0 failed, 10 ignored (summed over all test binaries) |

Baseline at the start of this work (commit `43cdef5`): 624 passed, 0 failed, 28 ignored.

The tests that use a reproducibility fixture key were re-run after the key
(`tests/fixtures/repro-ci-key.pem`) was committed. Before that fix, 17 tests
failed on a fresh checkout because the key was gitignored.

`cargo deny` runs in CI. Rust 1.91 or newer is required.

## Acceptance matrix (architecture.md §16)

- 35 IDs are defined in §16. All 35 are covered by at least one live test.
- No ID is covered only by an ignored test, and none by a stub.
- Enforcement: `crates/entangle-atc-matrix/tests/matrix.rs`, test
  `atc_matrix_full_coverage`, is a normal (not ignored) test. It scans
  `crates/`, `plugins/` and `tools/` for functions named `atc_<group>_<n>_...`.
  It fails if a §16 ID has no live test, has only ignored tests, has a body that
  calls `unimplemented!` or `todo!`, or if a test name is malformed.
- An audit compared each test with the GIVEN/WHEN/THEN of its ID and
  strengthened 9 of them.
- Some IDs are implemented by tests that only run in CI (cross-host
  reproducibility, real cosign). The matrix counts a live test; it does not
  prove the CI job passed.

## Crates

27 workspace members: 26 crates under `crates/` and `tools/xtask`.

| Crate | Purpose |
|-------|---------|
| `entangle-types` | Tier, PluginId, PeerId, Task, IntegrityPolicy, resource types, error codes |
| `entangle-manifest` | `entangle.toml` schema and tier/capability validation |
| `entangle-signing` | Ed25519 publisher signing, BLAKE3 hashing, keyring, Shamir split/combine |
| `entangle-wit` | WIT package `entangle:plugin@0.1.0`, including the `entangle:integrity/metric` interface |
| `entangle-sdk` | Guest-side helpers and the `entangle_plugin!` macro |
| `entangle-host` | Wasmtime + WASI 0.2 host; `capability.fetch`, WASI preopens, socket rules with pinned DNS |
| `entangle-broker` | Capability broker: deny by default, audit log, grants and live revocation, `CrossNodePolicy` |
| `entangle-ipc` | In-process pub/sub bus (broadcast channels, topic globs) |
| `entangle-core` | Shared kernel utilities |
| `entangle-runtime` | Kernel: manifest, signature, broker, host; integrity validation; metric loader; native plugin launch |
| `entangle-sandbox` | OS sandbox for tier-5 plugins: Landlock, user and net namespace, seccomp, `no_new_privs`, rlimits, process groups; bubblewrap and Seatbelt profile generation; subprocess supervisor |
| `entangle-rpc` | Typed JSON-RPC 2.0 client for the daemon socket |
| `entangle-mesh-local` | mDNS-SD discovery on `_entangle._udp.local`; hardware detection (memory, GPU backend and VRAM, NPU) for adverts |
| `entangle-mesh-iroh` | Iroh QUIC transport, identity-bound; ALPNs for control, scheduler, agent, blobs, docs, stream |
| `entangle-mesh-tailscale` | Tailscale transport: liveness polling, authenticated key exchange, sealed frames, source filter, connection caps, protocol multiplexing, framed streams |
| `entangle-oci` | OCI registry client (token and basic auth, digest and size checks), push and pull, signed mirror listings |
| `entangle-peers` | Persistent peer allowlist (`~/.entangle/peers.toml`) |
| `entangle-pairing` | 6-digit code and fingerprint mutual-TOFU state machine |
| `entangle-biscuits` | biscuit-auth wrapper, bridge attenuation, cumulative byte budget (`E0425`) |
| `entangle-scheduler` | Worker pool, placement, dispatcher, multi-transport links, integrity validation and reputation, streaming task model |
| `entangle-agent-host` | MCP config adapters (claude-code, codex, opencode), per-session gateway HTTP server |
| `entangle-observability` | Tracing bootstrap, metrics registry and catalogue, OTLP/HTTP JSON exporter, trace context |
| `entangle-atc-matrix` | Cross-check of §16 IDs against test names (see above) |
| `entangle-cli` (`entangle`) | Operator CLI |
| `entangle-bin` (`entangled`) | Daemon: UDS RPC, scheduler serving over Iroh and Tailscale, `/metrics`, maintenance loop |
| `entangle-bench` | Criterion benchmarks |
| `tools/xtask` | `cargo xtask hello-world build`, `hash-it build`, `bus-factor`, `rotation-note-check` |

Plugins in the repository: `examples/` has `hello-world`, `hash-it` and
`native-echo` (tier 5). `plugins/` has `compress`, `csv-stats`, `image-resize`,
`json-query`, `markdown-html`, `qr-encode`, `stream-lines`, `metric-bleu-4` and
`metric-numerical-l2-relative`.

## What works end to end

Each item has tests in the workspace; none were verified on a multi-host
deployment in this environment.

- **Identity and config:** `entangle init`; format-preserving config edits.
- **Plugins:** `plugins new|build|load|unload|invoke|list|install`; `keyring`; signed `.tar.zst` packages; `plugins verify --rebuild` compares a rebuild with the package.
- **Capability grants (wasm):** `capability.fetch` through the broker; WASI preopens `/data`, `/shared`, `/shares/<n>`; `net.lan` and `net.wan` socket rules with pinned DNS (loopback, own-host and cloud-metadata addresses refused); live revocation; operator `deny_capabilities`; `entangle perms list|revoke`. Stream plugins get the same grants.
- **Tier-5 native plugins:** run under the Linux sandbox. The runtime-kind check (ATC-MAN-3) and the install-time tier ceiling check (ATC-MAN-4, no state change on refusal) are tested. `[security] allow_unsandboxed_native` exists.
- **Max tier and wrapper:** `entangle security set-max-tier`, `entangle config reload` and `config validate` drain in-flight calls and streams and use audit codes `W0214`, `I0215`, `I0216`, `I0217`. `entangle wrapper enable`, `disable`, `status`, `repair`; `doctor` detects shadowing.
- **Pairing:** 6-digit code over the network. A race where the responder closed the connection before its last frame was delivered is fixed (36 of 100 runs failed under load before, 0 of 100 after).
- **Transports:** `mesh.local`, `mesh.iroh`, `mesh.tailscale`. Per peer the scheduler tries local, then tailscale (only when active), then iroh; `[mesh] preferred` and `[mesh.overrides]` change the order. It falls back only when a connect fails. The transport label appears in metrics and `diag`.
- **Remote one-shot tasks:** `entangle compute dispatch`, gated on the peer allowlist.
- **Integrity:** `Deterministic` (majority hash quorum across distinct workers), `SemanticEquivalent` (signed metric component, metric runs on the verifier, output-size guard before the metric loads), `TrustedExecutor`, policy hash envelope (`INV-INT-1`), `PolicyMutation` rejection, per-peer per-policy reputation (EWMA).
- **Streaming tasks:** credit flow control, heartbeat with `PeerLost` after three missed pongs, signed chunks bound to the request, total-byte and chunk-count caps, partial-result policies, ALPN `entangle/stream/1` over Iroh and Tailscale, `entangle compute stream`.
- **Agents:** `entangle agent run` for claude-code, codex and opencode with a session-scoped config; the gateway authenticates a bearer token, applies allow/deny policy, writes an audit record, and starts stdio downstream servers with connection and size limits. Servers from the project's own config need consent (`--trust-project-servers`).
- **Observability:** `/metrics` (disabled by default, loopback by default), `entangle metrics`, OTLP/HTTP JSON traces (`http://` endpoints only), `traceparent` on the scheduler wire, `entangle diag mesh [--probe]`.
- **Distribution:** `plugins publish|tags|install oci://...`; signed mirror listings with separate mirror keys (ATC-MIR-1/2); reproducible archives and provenance; `Cargo.lock` is required.
- **Release tooling:** `entangle release verify` (Ed25519 release key and cosign), `release key split|combine` (Shamir 2-of-3), `cargo xtask bus-factor`, `cargo xtask rotation-note-check`, `.github/workflows/reproducibility.yml`. CI builds for `wasm32-wasip2` in the test job.

## Not done / deferred

| Item | State | Reason |
|---|---|---|
| `Attested` integrity | Returns `ENTANGLE-E0304` | Needs TEE hardware (SEV-SNP, TDX, Apple); none is available to test |
| Native Windows | Not started (Phase 5); WSL2 only | AppContainer and Job Objects do not give the same rigor as Landlock/Seatbelt without further work |
| bubblewrap and Seatbelt paths | Profiles generated and unit-tested; never run on a real bubblewrap or macOS host | No macOS or bubblewrap host was used in this work |
| Cross-host reproducibility, real cosign | Run only in CI workflows | Need macOS-14 and several Ubuntu runners and the cosign binary |
| cosign identity | Pinned to `release.yml` on any `v<semver>` tag, not to the tag being verified | `release verify --tag` is on a branch, not main |
| Capability revocation | Lasts until the plugin is reloaded | `deny_capabilities` is the permanent setting |
| OCI mirror listings | No replay protection | Not implemented |
| OCI client TLS | Paths untested | No test exercises TLS |
| Native plugin limits | No `RLIMIT_NPROC`, `RLIMIT_FSIZE` or cgroups | Not implemented; a plugin can fork or fill its writable directory |
| `net.wan` for native plugins | No per-host allowlist | Not implemented |
| `entangle install`, first-run wrapper prompt | Command does not exist | Not implemented; `entangle quickstart` and `plugins install NAME` exist |
| `entangle logs`, `entangle upgrade`, `entangle trace task` | Commands do not exist | Not implemented |
| Bus-factor check | Fails by design | One holder per role in `docs/maintainers/roles.toml` |
| Published release | None | `install.sh` and the Homebrew formula need a `v0.1.0` tag |
| Speculative execution, straggler mitigation, reputation gossip | Not implemented | Not started |

### On branches, not on main

| Item | Note |
|---|---|
| Layer-2 1% replay spot-check | Not available |
| Per-peer transport routing for `entangle compute stream` | On main it dials Iroh only |
| Streaming invocation metrics | Not available |
| `entangle backup` / `restore` | Not available |
| `[plugins] disabled`, `plugins enable` and `plugins disable` | The key parses; the daemon does not read it |
| `entangle release verify --tag` | Not available |
| HTTP downstream servers in the MCP gateway | `url` entries are refused with `ENTANGLE-E0664` |

## Release pipeline

- `.github/workflows/ci.yml` — fmt, clippy, tests (Linux and macOS, with the `wasm32-wasip2` target), docs, cargo-deny.
- `.github/workflows/release.yml` — matrix build, provenance, cosign, GitHub Release.
- `.github/workflows/reproducibility.yml` — ATC-PKG-1 and ATC-PKG-2.
- `.github/workflows/bus-factor.yml` — weekly bus-factor check (currently failing by design).

## Read next

- [`README.md`](README.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/tutorial.md`](docs/tutorial.md)
- [`docs/operations.md`](docs/operations.md)
- [`CHANGELOG.md`](CHANGELOG.md)
