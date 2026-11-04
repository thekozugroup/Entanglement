# Operations Runbook

A practical guide for operators running `entangled` (the daemon) in production —
install paths, the config schema, file/permission layout, health checks, error
codes, backup/restore, logging, and troubleshooting.

This is the *how do I run and diagnose it* document. For architecture and
rationale, see [`architecture.md`](architecture.md); for a guided walkthrough
of first-time setup, see [`tutorial.md`](tutorial.md); for the container
build itself, see [`../docker/README.md`](../docker/README.md).

---

## 1. Install paths

There are two supported ways to run `entangled` in production. Both resolve
the same on-disk layout under `~/.entangle/` (see §3) — there is no
config-directory command-line flag, so `$HOME` is the one setting that must be
right in either case.

### 1a. systemd (bare metal / VM)

Unit file: [`../packaging/entangled.service`](../packaging/entangled.service).
Install steps are in the unit's header comment:

```bash
sudo useradd --system --user-group --home /var/lib/entangle entangle
sudo install -m0755 entangled /usr/local/bin/entangled
sudo install -m0755 entangle  /usr/local/bin/entangle
sudo install -m0644 packaging/entangled.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now entangled
```

What the unit sets up:

- **`User=entangle` / `Group=entangle`** — the daemon never runs as root.
- **`Environment=HOME=/var/lib/entangle`** — required. The daemon has no
  config-dir flag; it resolves its config, identity, keyring, and socket from
  `$HOME/.entangle` (`crates/entangle-bin/src/config.rs`). Without `HOME` set,
  a systemd service has no usable home and startup fails.
- **`StateDirectory=entangle`, `StateDirectoryMode=0700`** — systemd creates
  and owns `/var/lib/entangle` for you, mode `0700`, and keeps it writable
  under `ProtectSystem=strict` below.
- **`Restart=on-failure`, `RestartSec=5`, `TimeoutStopSec=15`.**
- **Hardening:** `NoNewPrivileges=true`, `ProtectSystem=strict`,
  `ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`,
  `ProtectKernelTunables/Modules/Logs=true`, `ProtectControlGroups=true`,
  `ProtectClock=true`, `ProtectHostname=true`, `ProtectProc=invisible`,
  `RestrictSUIDSGID=true`, `RestrictRealtime=true`, `RestrictNamespaces=true`,
  `LockPersonality=true`, `SystemCallFilter=@system-service`,
  `SystemCallErrorNumber=EPERM`, `UMask=0077`.
- **`CapabilityBoundingSet=` / `AmbientCapabilities=`** (both empty) — all
  capabilities dropped; the daemon only binds a Unix socket inside its own
  `StateDirectory` and needs none.
- **`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`** — `AF_UNIX`
  for the RPC socket; `AF_INET`/`AF_INET6`/`AF_NETLINK` for `mesh.local` mDNS
  discovery and interface enumeration.
- **`MemoryDenyWriteExecute` is deliberately *not* set** — the daemon embeds a
  wasmtime JIT (Cranelift) that maps executable pages for compiled
  WebAssembly; W^X enforcement would break plugin execution.

The `entangle` CLI is a separate, per-user client — the unit runs only the
daemon.

### 1a'. launchd (macOS)

LaunchAgent: [`../packaging/io.github.thekozugroup.entangled.plist`](../packaging/io.github.thekozugroup.entangled.plist).
It runs `entangled run` as the logged-in user (the daemon reads
`$HOME/.entangle`, like the CLI), restarts it on a **non-zero** exit only
(`KeepAlive` → `SuccessfulExit = false`, the counterpart of systemd's
`Restart=on-failure`), at most every 5 s (`ThrottleInterval`), and writes the
JSON log lines to `~/Library/Logs/entangled.log`. Install steps are in the
plist's header comment:

```bash
sudo install -m0755 entangled /usr/local/bin/entangled
mkdir -p ~/Library/LaunchAgents ~/Library/Logs
sed "s#__HOME__#$HOME#g" packaging/io.github.thekozugroup.entangled.plist \
  > ~/Library/LaunchAgents/io.github.thekozugroup.entangled.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.github.thekozugroup.entangled.plist
```

(`brew services start entangle` uses the Homebrew formula's own service
definition instead, which restarts on every exit.) What a restart means for
in-flight work is in §21.

### 1b. Docker / docker-compose

See [`../docker/README.md`](../docker/README.md) for build/run commands and
the full hardening rundown (`read_only`, `cap_drop: ALL`,
`no-new-privileges`, `tmpfs` for `/tmp`). In short:

```bash
docker build -f docker/Dockerfile -t entangledev/entangle .
docker run -d --name entangled -v ent:/var/lib/entangle entangledev/entangle
```

The image sets `ENV HOME=/var/lib/entangle`, so the daemon's `~/.entangle`
resolves to `/var/lib/entangle/.entangle/` inside the container — all of it
persisted in the named volume, so config/identity/keyring/peers survive
container recreation. `network_mode: host` is required for `mesh.local` mDNS
discovery to reach the LAN, and — per the compose file's own comment — this
does **not** work through Docker Desktop on macOS (its "host" network is the
VM's, not the Mac's).

### 1c. Build from source

```bash
cargo install --path crates/entangle-cli   # `entangle` CLI
cargo install --path crates/entangle-bin   # `entangled` daemon
entangle init                              # generates identity + config
entangled run                              # foreground daemon (Phase 1: no daemonize)
```

`entangled run` is unconditionally foreground in Phase 1 — the `--foreground`
flag exists on `RunArgs` (defaulting to `true`) but the run loop doesn't
branch on it; foreground is the only mode there is. That's exactly what the
systemd unit's `Type=simple` and the Docker `ENTRYPOINT`/`CMD` rely on.

---

## 2. Config file schema

Path: `~/.entangle/config.toml` (TOML). Absent file → all defaults. Every
section uses **`deny_unknown_fields`** — a typo'd key is a loud startup/parse
error, not a silently-ignored setting (`crates/entangle-bin/src/config.rs`).

```toml
[runtime]
bus_capacity = 1024        # default 1024

[mesh]
transports = ["local"]     # default: [] (empty)
multi_node = false         # default: false
# preferred = "tailscale"  # daemon-only; see §20
# [mesh.overrides]         # daemon-only; see §20

[security]
max_tier_allowed = 5       # default: 5 (Tier::Native — most permissive)
allow_unsandboxed_native = false   # default: false
deny_capabilities = []     # default: none denied; e.g. ["net.wan", "storage.share.*"]

[wrappers]
install = false            # written by `entangle wrapper enable|disable` (§15)

[plugins]
disabled = []              # written by a `max_tier_allowed` lowering (§16)

[scheduler]                # daemon-only; see §11, §20
spot_check_probability = 0.01     # default 0.01 (spec §7.5: 1 %); 0 disables
spot_check_max_concurrent = 4     # default 4

[metrics]                  # daemon-only; see §14
enabled = false            # default: false
listen = "127.0.0.1:9464"  # default
allow_non_loopback = false # default: false

[telemetry.otlp]           # daemon-only; see §14
enabled = false            # default: false
endpoint = "http://localhost:4318"
service_name = "entangled"
```

| Section | Key | Type | Default | Meaning |
|---|---|---|---|---|
| `[runtime]` | `bus_capacity` | usize | `1024` | Buffered-envelope capacity of the daemon's lifecycle event bus. Daemon-only tuning knob; not written by the CLI. |
| `[runtime]` | `aot_cache` | bool | `true` | Keep compiled wasm components in `~/.entangle/aot` so a later load (or a restart) skips compilation (§23). `false` compiles every load. Also honoured by the CLI's `--allow-local` kernel (which shares the directory). |
| `[runtime]` | `aot_cache_max_mb`, `aot_cache_max_unused_days` | integer, integer | `512`, `30` | AOT cache limits: the maintenance loop removes entries unused this many days, then the least recently used above the size cap (§23). Daemon-only. |
| `[mesh]` | `transports` | array of strings | `[]` | Active mesh transports: `"local"` (mDNS on `_entangle._udp.local`; LAN dialling also needs `"iroh"`), `"iroh"` (the scheduler endpoint, `[scheduler]`), `"tailscale"` (also needs `[mesh.tailscale] enabled = true`, §10). See §20 for how a transport is chosen per peer. |
| `[mesh]` | `preferred` | string | absent | Daemon-only. `"local"`, `"tailscale"` or `"iroh"`: tried first for every peer; the others stay fallbacks in the spec order (§20). Anything else fails the load (`ENTANGLE-E0434`). |
| `[mesh.overrides]` | `"<peer-id>"` | string or array of strings | none | Daemon-only. Per peer (32-hex peer id): one transport forces it, a list gives the exact order; no fallback outside it (§20). A bad id, an empty list or a repeated transport fails the load (`ENTANGLE-E0435`). |
| `[mesh]` | `multi_node` | bool | `false` | When `true`, the daemon requires at least one trusted peer in `peers.toml` **before it will start**. See §5 for the exact failure. |
| `[scheduler]` | `spot_check_probability`, `spot_check_max_concurrent` | float in 0..=1, integer 1..=1024 | `0.01`, `4` | Daemon-only. Layer-2 spot-checks of accepted `deterministic` / `semantic-equivalent` tasks (§11): the share re-run on another executor, and how many may run at once. `0` disables them; out-of-range values fail the load. (`bind`, `peers`, `relay` configure the iroh scheduler endpoint, §20.) |
| `[metrics]` | `enabled`, `listen`, `allow_non_loopback` | bool, `ip:port`, bool | `false`, `127.0.0.1:9464`, `false` | Prometheus scrape endpoint (§14). A non-loopback `listen` is refused (`ENTANGLE-E0656`) unless `allow_non_loopback = true`. |
| `[telemetry.otlp]` | `enabled`, `endpoint`, `service_name` | bool, URL, string | `false`, `http://localhost:4318`, `entangled` | OTLP/HTTP trace export (§14). `endpoint` must be `http://`; `4318` is OTLP/HTTP (`4317` is gRPC, which is not spoken). |
| `[security]` | `max_tier_allowed` | integer 1–5 | `5` | Ceiling on the plugin tier the daemon will load (`Tier::Native` = 5 down to `Tier::Pure` = 1). A load above the ceiling is refused with `ENTANGLE-E0043` before anything is verified, granted or written. **`4` disables tier-5 native plugins globally; `3` disables every native plugin.** Out-of-range values (`0` or `>5`) fail to parse. |
| `[security]` | `allow_unsandboxed_native` | bool | `false` | Run native (tier 4–5) plugins on a host that has **no** OS sandbox primitive. Off: such plugins are refused with `ENTANGLE-E0700`. No effect on hosts that have one — the sandbox is then always engaged. See §12. |
| `[security]` | `deny_capabilities` | array of strings | `[]` | Capabilities the broker never grants to any plugin, whatever its manifest declares (spec §4.5): exact keys (`"net.wan"`, `"storage.share.photos"`, `"custom.telemetry"`), family prefixes (`"net.*"`, `"storage.*"`, `"storage.share.*"`, `"compute.*"`, `"custom.*"`) or `"*"`. A plugin that declares a denied capability **still loads, without it**; see §18. An invalid pattern (e.g. `"net.wann"`) is a startup error, `ENTANGLE-E0126`. Omitted from the file the CLI writes when empty. |
| `[wrappers]` | `install` | bool | `false` | Opt-in record for the shell shim. `entangle wrapper enable` sets `true`, `disable` sets `false`; setting `false` by hand silences an installed shim at once (it checks this key whenever an agent host is launched outside a session). The daemon ignores it. See §15. |
| `[plugins]` | `disabled` | array of strings | `[]` | Plugin ids the kernel refuses to load (`ENTANGLE-E0759`): written by a tier-ceiling lowering (§16) and by `entangle plugins disable <id>`; `entangle plugins enable <id>` removes an id. Honoured by the daemon (re-read before every `plugins load`, no restart needed) and by the CLI's `--allow-local` kernel. |

Notes:

- The `[mesh]`, `[security]` (including `deny_capabilities`), `[wrappers]`
  and `[plugins]` sections are **field-for-field shared** with the CLI's own
  config schema (`crates/entangle-cli/src/config.rs`), which is what
  actually writes the file (via `entangle init`, `entangle mesh
  trust`/`untrust`, `entangle wrapper`, `entangle security`). A round-trip
  test in `entangle-bin` pins this compatibility — every section in one
  file, in both directions — so the two schemas cannot silently drift. The
  CLI's edits are format-preserving: they change only the key they set and
  keep `deny_capabilities`, comments and the daemon-only sections.
  - One asymmetry to know about: the CLI stores `max_tier_allowed` as a bare
    `u8` (default `5`), while the daemon deserializes it into the `Tier` enum,
    which gets range validation for free — the wire representation (an
    integer 1–5) is identical either way.
- `[runtime]`, `[metrics]` and `[telemetry]` are daemon-only; the CLI never
  writes them and ignores them when it reads the file. So are the `[mesh]`
  keys `preferred`, `[mesh.overrides]` and `[mesh.tailscale]`: the CLI's
  `[mesh]` models only `transports` and `multi_node`, ignores the rest when
  reading, and leaves them alone when editing. Two keys that *used to*
  live under `[runtime]` (`multi_node`, `max_tier`) were relocated to `[mesh]`
  and `[security]` respectively — the old locations are now hard parse errors
  thanks to `deny_unknown_fields`, not silently-ignored dead settings.
- There is no daemon `--config` flag. The path is always
  `<default_config_dir>/config.toml`, where the default config dir is
  `$HOME/.entangle` — see §3 for the exact resolution rules (the config dir
  has no `$XDG_RUNTIME_DIR` fallback the way the socket path does; it hard-errors
  if no home directory can be found at all).

---

## 3. File / directory layout and required permissions

All daemon and CLI state lives under one directory, resolved as
`$HOME/.entangle` (falling back to `$XDG_RUNTIME_DIR/entangle` for the socket
only, if `$HOME` can't be resolved — see `default_socket_path` in
`crates/entangle-bin/src/config.rs`; there is deliberately no fallback to a
world-writable path like `/tmp`).

| Path | Contents | Required mode | Enforced by |
|---|---|---|---|
| `~/.entangle/` | Everything below | `0700` | Created at `0700` by `entangle init` and by the daemon's socket-bootstrap code; `entangle doctor`'s `dir-perms` check warns if group/other bits are set. |
| `~/.entangle/identity.key` | PEM-encoded Ed25519 keypair — the node's cryptographic identity. `peer_id` is derived from its public key. | `0600` | Created with `create_new` + mode `0o600` applied **atomically at creation** (no write-then-chmod window where it's briefly world-readable). `entangle doctor`'s `identity-perms` check warns otherwise. |
| `~/.entangle/config.toml` | Daemon/CLI config (§2). | no enforced mode | Absence is fine (defaults apply); a parse error fails `entangle doctor`'s `config` check and, in the daemon, fails startup outright. |
| `~/.entangle/keyring.toml` | Trusted publisher public keys (for verifying signed plugin artifacts). | `0600` | Enforced on every `save()`, including tightening an existing file found at looser permissions. |
| `~/.entangle/peers.toml` | Persistent trusted-peer allowlist (pairing results). | `0600` | Written atomically via a mode-`0600` sibling temp file + rename. |
| `~/.entangle/sock` | The daemon's Unix-domain RPC socket. | `0600` | The server **forces** mode `0600` after bind and **refuses to serve** if any group/other bit remains; every accepted connection is additionally checked against the socket owner's uid via `SO_PEERCRED` (defense-in-depth beyond the mode bit). |
| `~/.entangle/cache/`, `~/.entangle/logs/` | Plugin artifact cache; daemon logs. | — | Managed by the built-in maintenance loop (§7). |
| `~/.entangle/aot/` | AOT compilation cache: `cache.key` (32-byte per-node MAC key), `<key>.cwasm` (compiled component) + `<key>.meta` (sidecar with its keyed MAC). See §23. | `0700` directory, `0600` files | Created that way by the daemon; a directory or key file with group/other bits or another owner disables the cache (`ENTANGLE-E0786`); an entry file with them is refused and deleted. |
| `~/.entangle/plugins.state.toml` | Plugins loaded at shutdown, reloaded at the next start (§22). | `0600` | Written atomically (temp file + rename) with mode `0600` on every load, unload and reload. |
| `~/.entangle/data/` | Plugin storage: `plugins/<publisher>/<name>/` (each plugin's private directory, wasm `/data` or native `$ENTANGLE_DATA_DIR`), `shared/`, `shares/<name>/`. See §18. | `0700` on every directory the daemon creates | Created on demand when a storage grant is realised, without following symbolic links. |

`entangle doctor` (see §4) is the fastest way to audit all of the above at
once — its `identity-perms` and `dir-perms` checks specifically flag mode
deviations and suggest the `chmod` to fix them.

---

## 4. Checking health

Two independent tools answer "is it working," at different levels:

### `entangle doctor` — structured pre-flight / ongoing diagnostics

Runs 14 checks and prints one `[ok] / [warn] / [fail] / [skip]` line each,
then a summary (`crates/entangle-cli/src/cmd/doctor.rs`):

1. `identity` — `identity.key` present and parses as a valid Ed25519 keypair.
2. `identity-perms` — mode is `0600` (unix only).
3. `config` — `config.toml` absent (ok, defaults) or parses cleanly.
4. `keyring` — `keyring.toml` absent (ok) or parses, reporting trusted-publisher count.
5. `peers` — `peers.toml` state; **warns** if `multi_node = true` but the file is absent or empty (daemon will refuse to start — see §5).
6. `dir-perms` — `~/.entangle/` is `0700` (unix only).
7. `rust-toolchain` — reports the compiler version used to build the binary.
8. `wasm32-wasip2` — whether the Wasm target is installed (needed to build plugins, not to run the daemon).
9. `daemon-reachable` — connects to the RPC socket and calls `version`. **Only warns** (exit code stays 0) if the daemon is unreachable — it does not fail the overall check.
10. `daemon-version-match` — compares the daemon's reported version to the CLI's own; skipped if the daemon isn't reachable.
11. `OS sandbox` — the layers a tier-5 plugin without network access would run under on this host (e.g. `Landlock ABI 7 + seccomp + user/net namespace + Landlock TCP rules; network denied`), or why native plugins would be refused. Warns on reduced isolation. See §12.
12. `sandbox trial` — engages that sandbox for real on two trivial children: `true` must run, and `cat` of a file outside the profile must be denied. **Fails** if the child could read the file (sandbox not enforcing) or if engagement fails on a host that should support it.
13. `disk-space` — warns below 1 GiB free on the filesystem hosting `~/.entangle` (or `/tmp` if that dir doesn't exist yet).
14. `clock-skew` — compares the daemon's clock to the local clock via a `time` RPC; `warn` above 2s drift, **`fail`** above 30s (biscuit-auth tokens have only ±60s allowance, so severe drift breaks cross-node auth and pairing TOFU).

Exit code is `1` if any check is `fail`, else `0` — `warn` never fails the
command. Because check 9 (daemon reachability) only warns, **`entangle
doctor` is not a substitute for a liveness probe** — a hung daemon that still
holds its socket open long enough to fail the `version` RPC will still just
warn.

### `entangled status` — the actual liveness probe

```bash
entangled status                 # uses the default socket path
entangled status --socket /path/to/sock
```

Connects to the Unix socket and round-trips a `version` JSON-RPC request.
This is what the Docker `HEALTHCHECK` and the systemd deployment should use
for liveness: a hung, dead, or unreachable daemon causes the connection or
read to fail, and the process exits non-zero. One nuance: a **successful**
exit (0) only means the socket accepted a connection and one full response
line was read — it does not additionally inspect that line for a JSON-RPC
`error` object, so it prints the raw response for you to eyeball.

---

## 5. Multi-node startup requirement (`ENTANGLE-E0050`)

Setting `multi_node = true` in `[mesh]` tells the daemon to require at least
one trusted peer before it will start (spec §11 #16). This is
checked **before any mesh transport activates**
(`crates/entangle-bin/src/main.rs`, right after the peer store is opened):

```rust
let startup_policy = BrokerPolicy::new(cfg.security.max_tier_allowed, cfg.mesh.multi_node, &peer_store);
startup_policy.check_startup().context("startup policy check failed (spec §11 #16)")?;
```

If `multi_node = true` and `peers.toml` is absent or empty, `check_startup()`
returns:

```
ENTANGLE-E0050: daemon is in multi-node mode but peer allowlist is empty
```

and the daemon **refuses to start** — it never reaches the point of binding
the RPC socket or activating mesh transports. `entangle doctor`'s `peers`
check catches this ahead of time (warns, doesn't fail, since it's read-only)
so you can fix it before restarting the daemon.

**Fix:** pair at least one device first —

```bash
entangle pair              # initiator side; run `entangle pair --responder` on the peer
```

— which persists a trusted peer to `peers.toml`, then start (or restart) the
daemon. Single-node mode (`multi_node = false`, the default) never requires
peers.

---

## 6. Reading `ENTANGLE-Exxxx` error codes

Every structured error in the workspace carries a stable `ENTANGLE-Exxxx`
code in its `Display` output — grep your logs for the code, not the message
text, since the message wording can change while the code cannot (codes are
appended-only; retired codes are never reissued to a different meaning). The
canonical range table, maintained in
`crates/entangle-types/src/errors.rs`, is:

| Range | Domain |
|---|---|
| E0042–E0043 | Tier violations (plugin tier vs. capability requirement, or vs. daemon ceiling) |
| E0100–E0122 | Authentication / authorization (signature verification, publisher trust, capability grants) |
| E0123–E0127 | Capability broker: duplicate registration (E0123), operator `deny_capabilities` refusal (E0124), revoked capability (E0125), invalid `deny_capabilities` pattern (E0126), tier ceiling on a grant (E0127) — see §18 |
| E0200–E0203 | Manifest / plugin id validation; malformed (E0202) or unknown (E0203) capability parameters |
| E0300–E0301 | Task execution (output-size limit, timeout) |
| E0302–E0305 | Integrity policy enforcement (`entangle-runtime`) |
| E0306–E0349 | Integrity verification: metric trust and loading, policy envelope, semantic quorum, Layer-2 spot-check attestation failure (E0319) (`entangle-runtime::IntegrityError`; see §11) |
| E0350–E0399 | Streaming tasks (`entangle_scheduler::stream::StreamError`; see §17): integrity policy not usable for a stream (E0350), invalid task field or limit (E0351), chunk signature or sequence rejected (E0352), `max_total_bytes` (E0353) or `max_chunk_bytes` (E0354) exceeded, credit violation (E0355), peer lost after missed heartbeats (E0356), submitter unresponsive (E0357), cancelled (E0358), protocol violation (E0359), unsupported stream wire version (E0360), the other end closed the stream and said why (E0361), bad end-of-stream frame (E0362), transport failure under the stream (E0363; carries an E0430–E0433 routing error; E0434/E0435 are config errors raised before any stream exists), wall-clock timeout (E0364), input over `max_input_bytes` (E0365), operation on a closed stream (E0366), executor observed another policy hash (E0367), executor outside the `TrustedExecutor` allowlist (E0368), plugin failure (E0369), policy envelope rejected (E0370), chunk-count allowance exceeded (E0371) |
| E0430–E0449 | Scheduler transport selection (`entangle_scheduler::transport::RouteError`; see §20): no route to the peer on any usable transport (E0430), every candidate failed to connect (E0431), a transport failed after the request was sent and it was not retried (E0432), a frame over the transport cap (E0433), an unknown transport name in `[mesh] preferred` / `[mesh.overrides]` (E0434), an unusable `[mesh.overrides]` entry (E0435) |
| E0500–E0506 | Wasm host errors (`entangle-host`) |
| E0507–E0519 | Host artifact checks — `E0507` runtime kind mismatch; realising capability grants — `E0508` storage grant without a data directory, `E0509` a storage directory could not be created or opened (e.g. it is a symbolic link), `E0510` a share name or plugin id that is not one safe path component; `E0511` an invocation or stream stopped because a network grant it relied on was revoked (or the plugin unloaded, or the tier ceiling lowered below it) while it ran (`entangle-host`) |
| E0600–E0699 | Agent-host adapter (`entangle-agent-host`) |
| E0700–E0719 | OS-sandbox engagement (`entangle-sandbox`) — see §12 |
| E0720–E0739 | Native-plugin supervisor (`entangle-sandbox`) — see §12 |
| E0740–E0749 | Native-plugin staging / storage (`entangle-runtime::native`) |
| E0750–E0779 | Operator safety UX: shell wrappers and `max_tier_allowed` lowering (`entangle-cli`, `entangle-bin`) — see §15, §16 |
| E0780–E0799 | Runtime lifecycle — see §21–§24: AOT cache entry refused (E0785, logged) or cache unusable (E0786, logged), a core fault that exits the daemon (E0787), a contained panic in a plugin call (E0788) |
| E0900 | I/O |
| E9999 | Internal / unexpected |

A handful of other crates layer additional codes into gaps in that range for
domain-specific failures — these are not yet folded into the single-registry
contract test (`entangle-types/tests/error_codes.rs` currently covers
`entangle-types`, `entangle-runtime::integrity`, and `entangle-host::errors`
only), but each is still a stable, grep-able code:

| Code | Meaning |
|---|---|
| `ENTANGLE-E0050` | Multi-node mode with an empty peer allowlist — daemon refuses to start (§5). |
| `ENTANGLE-E0400` | Cross-node dispatch attempted but the remote transport is not implemented (Phase 2 scaffold). |
| `ENTANGLE-E0401` | Task input exceeds the dispatcher's configured `max_input_bytes`. |
| `ENTANGLE-E0410`–`E0413` | Biscuit-auth parse / mint / verify / malformed-claim failures. |
| `ENTANGLE-E0420`–`E0425` | Bridge (cross-node relay) biscuit attenuation violations — missing fact, TTL/rate/byte-cap ceiling exceeded, or destination-pin mismatch (E0420–E0424); E0425 is a relay whose cumulative `total_bytes_cap` budget is exhausted. |
| `ENTANGLE-E0620`–`E0624`, `E0660`–`E0671` | MCP gateway and agent sessions — see [agents.md](agents.md). E0620 is retired. |
| `ENTANGLE-E0630`, `E0640` | Retired `NotImplemented` codes for `mesh.iroh` and `mesh.tailscale`; both transports are implemented. |
| `ENTANGLE-E0651`–`E0654` | OTLP trace export: invalid `[telemetry.otlp]` endpoint (E0651; `https://` is not supported), empty `service_name` (E0652), an out-of-range exporter setting (E0653), the export thread could not start (E0654). `E0650` is retired. See §14. |
| `ENTANGLE-E0655`–`E0657` | Metrics endpoint: `[metrics] listen` is not an `ip:port` (E0655), a non-loopback `listen` without `allow_non_loopback = true` (E0656), the socket could not be bound (E0657). See §14. |
| `ENTANGLE-E0750` | Daemon refused `security/apply-max-tier`: the new ceiling would unload plugins and the caller did not authorise unloading (§16). |
| `ENTANGLE-E0751` | A shell rc file has a damaged or duplicated wrapper block; run `entangle wrapper repair` (§15). |
| `ENTANGLE-E0752` | `max_tier_allowed` outside 1..=5 (argument or `config.toml`) (§16). |
| `ENTANGLE-E0753` | Lowering `max_tier_allowed` over loaded plugins refused: no terminal and no `--force-unload` (§16). |
| `ENTANGLE-E0754` | `config.toml` could not be edited (not valid TOML, or a section has the wrong shape). |
| `ENTANGLE-E0756` | A shell rc file could not be read or written (or `$HOME` is unset, or the file is not UTF-8) (§15). |
| `ENTANGLE-E0757` | `entangle wrapper repair` while wrappers are not enabled (§15). |
| `ENTANGLE-E0758` | Daemon refused `security/apply-max-tier`: a plugin above the new ceiling was not on the list the operator confirmed (loaded while the prompt waited); nothing changed, re-run to see the current list (§16). |
| `ENTANGLE-E0759` | A plugin id listed in `[plugins] disabled` was refused at load; run `entangle plugins enable <id>` (§16). |
| `ENTANGLE-E0760` | `entangle plugins enable` refused: the plugin's tier is above the current `max_tier_allowed`; raise the ceiling first (§16). |
| `ENTANGLE-W0214` | **Warning (audit).** A plugin was unloaded and disabled because `max_tier_allowed` was lowered below its tier; one entry per plugin (§16). |
| `ENTANGLE-I0215` | **Info (audit).** Summary written after a ceiling lowering completes (§16). |
| `ENTANGLE-I0216` | **Info (audit).** The operator cancelled a ceiling lowering; the previous ceiling stays (§16). |
| `ENTANGLE-I0217` | **Info (audit).** `max_tier_allowed` was raised (spec §9.4.1: raising is an audited operation) (§16). |

If you hit a code not listed above, the fastest way to find its exact meaning
and the crate that owns it is:

```bash
grep -rn "ENTANGLE-E<code>" crates/*/src/
```

---

## 7. Backup / restore

`identity.key` is the node's Ed25519 private key. **The daemon's `peer_id` —
and every existing pairing — is derived from its public key.** There is no
recovery path for a lost key:

> **WARNING:** losing `identity.key` (or overwriting it without a backup)
> permanently breaks every existing pairing. Every peer that trusted this
> node's old public key will reject the new one; you must re-pair from
> scratch on every peer with `entangle pair`.

### Backup

```bash
entangle backup --to /secure/offline/node.entangle-backup            # prompts twice
entangle backup --to node.bak --include-config --passphrase-file ~/.bk-pass
ENTANGLE_BACKUP_PASSPHRASE=... entangle backup --to node.bak          # automation
```

The archive holds `identity.key`, `keyring.toml`, `release-keyring.toml` and
`peers.toml` (whichever exist) and, with `--include-config`, `config.toml`.
Plugin data under `~/.entangle/data` is **not** archived (a deviation from
architecture.md §9.6; back that directory up with your usual file backup). It
is encrypted with a passphrase: Argon2id (64 MiB, 3 passes, 1 lane; above the
OWASP minimum) derives a key for XChaCha20-Poly1305, and the format header
(magic, version, KDF parameters, salt, nonce) is authenticated as associated
data, so changing any byte of the file makes it unreadable. The passphrase
comes from `--passphrase-file <file>` (first line), else from
`ENTANGLE_BACKUP_PASSPHRASE` when it is set (even at a terminal; the command
says so on stderr), else from a TTY prompt (asked twice); at least 8
characters. It is never accepted on the command line. Without a TTY and without one of those
sources the command fails instead of hanging. The archive is written with mode
`0600`, atomically; an existing `--to` file is only replaced with `--force`.
A successful backup touches `~/.entangle/.identity_backed_up`, which silences
the maintenance loop's "identity has no backup" warning
(`crates/entangle-bin/src/maintenance.rs`, `warn_backup`). The loop also warns
once the key is older than `key_rotation_warn_days` (default 365 days),
counting from the older of the file's creation and modification times; the
archive records that time and `restore` puts it back as the restored file's
modification time, so a restored key keeps its age.

Keep the passphrase separate from the archive: without it the archive cannot
be opened, and there is no recovery.

### Restore (new device or disaster)

Stop the daemon, then:

```bash
systemctl stop entangled          # or: docker stop entangled
entangle restore --from /secure/offline/node.entangle-backup
systemctl start entangled         # or: docker start entangled
```

The passphrase is read like for `backup` (once). Decryption and validation
happen entirely before anything is written, so a wrong passphrase, a modified
or truncated archive, or an archive that is not a backup leaves the target
untouched. Restored files get mode `0600` (`~/.entangle/` `0700` if it had to
be created). The restored node has the same `peer_id`, the same keyring and
the same peer list, and every biscuit issued earlier stays valid, since
biscuits are bound to keys, not to the device.

If this device already has an identity, keyring or peer list that differs from
the archive, `restore` refuses (`ENTANGLE-E0864`). With `--force` it first
copies every file it is about to replace into
`~/.entangle/restore-backup-<unix_ts>/` (mode `0700`, files `0600`), then
writes the archive's files: each is first written to a temporary file
next to its target and only then renamed into place, so a write failure
(full disk, file-size limit) changes nothing, and if a rename fails the files
already replaced are put back; the error (`ENTANGLE-E0867`) says which
happened and where the copies are. Managed files the archive does not contain
(for example `peers.toml` when the source had no pairings) are moved to that
directory too, because they would be stale against the restored identity.
`config.toml` is touched only when the archive contains it.

| Code | Meaning |
|------|---------|
| `ENTANGLE-E0860` | No usable passphrase (no TTY and no file/env, empty, too short, prompts differ) |
| `ENTANGLE-E0861` | Not a backup, unsupported version, truncated, or KDF parameters out of range |
| `ENTANGLE-E0862` | Wrong passphrase, or the archive was modified |
| `ENTANGLE-E0863` | Decrypted payload is invalid (bad identity, unexpected file, malformed TOML) |
| `ENTANGLE-E0864` | Restore would overwrite existing state; pass `--force` |
| `ENTANGLE-E0865` | `backup --to` path exists; pass `--force` |
| `ENTANGLE-E0866` | No readable `identity.key` to back up |
| `ENTANGLE-E0867` | I/O error while writing |

`entangle init` can also import a bare PEM (option `i` in the wizard): if an
identity already exists and differs it requires confirmation, takes an
automatic `identity.key.bak-<unix_ts>` copy (mode `0600`) and offers to clear
`peers.toml`. `entangle restore` is the way to move a whole node.

---

## 8. Log configuration (`RUST_LOG`)

Both `entangle` and `entangled` initialize logging through the same shared
bootstrap function (`crates/entangle-observability/src/lib.rs`,
`init_with_filter`), but each binary supplies its own default filter string:

- **`entangled` (daemon) default:** `info,tokio=warn,wasmtime=warn`
  (via `init_default()`, called from `main.rs`).
- **`entangle` (CLI) default:** `warn,entangle=info` — quieter by default
  since it's an interactive, short-lived process (set directly in
  `entangle-cli/src/main.rs`).
- **Override (either binary):** set the standard `RUST_LOG` environment
  variable (e.g. `RUST_LOG=debug`, `RUST_LOG=entangle_broker=trace,info`) —
  it takes precedence over whichever default the binary supplies, the moment
  it's set to anything parseable.
- **Format is auto-detected from the output stream:** a TTY stderr (running
  interactively) gets a compact human-readable format; a non-TTY stderr
  (systemd, Docker, or any log aggregator reading a pipe) gets
  newline-delimited JSON — no separate flag needed to switch between the two.

For systemd, `journalctl -u entangled -f` will show the JSON lines (stderr
isn't a TTY under systemd); set `Environment=RUST_LOG=debug` in the unit (or
an override file via `systemctl edit entangled`) to raise verbosity. For
Docker, `docker logs -f entangled` shows the same JSON stream; pass
`-e RUST_LOG=debug` on `docker run`, or add it under `environment:` in
`docker-compose.yml`.

---

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Daemon exits immediately with `ENTANGLE-E0050` in the log | `multi_node = true` in `config.toml` but `peers.toml` is absent/empty | Run `entangle pair` to add at least one trusted peer, then restart. See §5. |
| Daemon fails to start with a TOML parse error mentioning an unknown field | A typo'd config key, or a key left over from an old schema (e.g. `[runtime] multi_node` or `[runtime] max_tier`, which moved to `[mesh]`/`[security]`) | Fix or remove the offending key — `deny_unknown_fields` means every section rejects keys it doesn't recognize. Cross-check against the schema table in §2. |
| Daemon fails to start: "cannot resolve a private socket path" / "cannot resolve the config directory" | `$HOME` is unset (common in minimal container/service environments) and no absolute `$XDG_RUNTIME_DIR` is set either | Set `HOME` explicitly (systemd: `Environment=HOME=...`; Docker: `ENV HOME=...`, already done in the shipped image). The code deliberately refuses to fall back to a world-writable path like `/tmp`. |
| Daemon logs "socket … is group/world accessible; refusing to serve" | Something (or someone) loosened the permissions on an existing socket path before bind, or a very permissive umask affected the parent dir | Remove the stale socket / fix the parent directory to `0700`, then restart. The server will not serve on a socket it can't restrict to `0600`. |
| `entangle`/`entangled` fail identity checks with "PEM parse failed" / corrupt key | `identity.key` truncated, corrupted, or edited by hand | Restore from backup (§7, `entangle restore`); if none exists, `entangle init` can generate a fresh identity — but every existing pairing must be redone via `entangle pair`. |
| `entangle doctor`'s `identity-perms` or `dir-perms` check warns | File/dir permissions loosened outside the tool (e.g. by a backup/restore process, or an `umask` override) | `chmod 600 ~/.entangle/identity.key` / `chmod 700 ~/.entangle` as suggested in the check's own output. |
| `entangled status` fails / hangs | Daemon not running, socket path mismatch, or daemon wedged | Check `systemctl status entangled` / `docker ps`; confirm the socket path matches (`--socket` override vs. default `$HOME/.entangle/sock`); check logs for the last activity before it stopped responding. |
| Native plugin refused with `ENTANGLE-E0700` / `E0701` | No sandbox primitive on this host (E0700), or one exists but cannot take the network away (E0701) | Run `entangle doctor` (§12). Enable Landlock / install bubblewrap; or grant the plugin `net.*`; or, knowingly, set `allow_unsandboxed_native = true`. |
| Native plugin invocation fails with `ENTANGLE-E0726` | A sandbox step failed in the child before `exec` (fail-closed), e.g. user namespaces blocked by a container's seccomp profile after the probe | Check `entangle doctor`'s `sandbox trial` line; the error carries the OS errno. |
| Plugin load refused with `ENTANGLE-E0507` | The artifact is not what `runtime` declares (an executable shipped as `wasm`, a component shipped as `native`, or a binary for another OS) | Rebuild with `entangle plugins build`, which picks the artifact kind from the manifest. |
| Plugin load refused with `ENTANGLE-E0043` | Plugin's declared tier exceeds `[security] max_tier_allowed` in `config.toml` | Either raise `max_tier_allowed` (understand the tier's capability implications first — see spec §4.2) or use a lower-tier plugin build. |
| Cross-node capability grant refused with `ENTANGLE-E0100`/`E0101` | Biscuit signature doesn't verify, or the publisher/peer key isn't in the trust roots | Re-check the peer is actually paired (`entangle mesh peers`) and its key matches what's in `peers.toml`/`keyring.toml`. |
| `clock-skew` check in `entangle doctor` reports `fail` | Local and daemon-host clocks have drifted >30s | Sync via NTP/chrony. Biscuit-auth tokens only tolerate ±60s, so severe drift breaks pairing TOFU and cross-node auth outright. |
| mDNS peer discovery doesn't work under Docker on macOS | Docker Desktop's `network_mode: host` is scoped to its internal Linux VM, not the Mac's real network | Use a Linux host/VM for mDNS-dependent testing, or run `entangled` natively on macOS for local dev. See [`../docker/README.md`](../docker/README.md). |

## 10. `mesh.tailscale` (tailnet transport)

Opt-in; the daemon never uses a tailnet it merely found running. It runs
only when **both** `[mesh.tailscale] enabled = true` and `"tailscale"` in
`[mesh] transports` are set; with only the first, the daemon logs a warning
at startup and `entangle doctor` shows the transport as inert.

```toml
[mesh]
transports = ["tailscale"]

[mesh.tailscale]
enabled = true
port = 41643                   # TCP, between tailnet IPs
acl-mode = "entangle-on-top"   # or "trust-tailnet" (alias "tailscale-only")
tailscale-cli = ""             # empty = `tailscale` on $PATH
# bind-ip = "100.101.102.103"  # omitted = all interfaces
```

* Only tailnet source addresses (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) are
  served: a connection from any other address (LAN, Docker bridge, the
  internet) is closed before a byte is read or sent, whatever `bind-ip` is.
  Discovery and outbound connections likewise never dial a non-tailnet
  address, even if `tailscale status` lists one.
* Inbound limits: at most 8 handshakes in flight per source address (64 in
  all), and at most 16 established connections per peer (256 in all). A peer
  over a limit is told so after the handshake (`connection limit`) and can
  retry once one of its connections closes.
* Outbound, the scheduler stays under those limits on its own: each task
  or stream to a peer holds one connection (until the answer, or for the
  stream's life), and the node runs at most 4 connection setups and holds
  at most 16 connections per peer at a time. Work beyond that waits for a
  slot (up to the 30 s request timeout) instead of failing; the wait counts
  as connecting, so a peer also reachable another way may be served there
  meanwhile (§20).

* Traffic is TCP over WireGuard. A mutual Ed25519-signed X25519 handshake
  authenticates the remote `PeerId` and agrees session keys; every frame after
  it is sealed (ChaCha20-Poly1305), so a tailnet node that relays the
  connection can neither read nor inject. A `PeerId` that answers discovery
  from two tailnet nodes at once is skipped for that round (logged at warn).
  `entangle-on-top` drops any authenticated
  peer that is not in `peers.toml` before reading a request, and re-checks
  the allowlist for every request, so `entangle peers remove` also ends
  service on that peer's open connections; `trust-tailnet` skips the
  allowlist but still authenticates identity.
* Liveness (`active` / `stopped(reason)` / `uninstalled`) is polled every 5 s
  (5 min once uninstalled); a change must persist for two polls and leaving
  `active` needs 30 s of grace. One log line per transition, target
  `entangle::mesh::tailscale`.
* `entangle doctor` reports the current state in its `tailscale` row.
* Errors: `ENTANGLE-E0640`..`E0649`. Handshake failures are logged at debug.

**What the listener serves.** The scheduler protocols, exactly as the iroh
endpoint does: one-shot tasks (`entangle/scheduler/1`) and streaming tasks
(`entangle/stream/1`, §17), by the same task and stream servers (so the
in-flight tables and the 64-stream limit span both transports). A
connection names its protocol in its first sealed record after the
handshake, the tailnet's equivalent of an ALPN; the daemon answers
"served" or "not served" before anything else, and closes a connection
that sends anything else. Two gates apply, in order:

1. the transport's: the handshake authenticates the peer's `PeerId`, and in
   `entangle-on-top` the peer must be in `peers.toml` before it can even
   select a protocol (re-checked for every request and stream frame);
2. the scheduler's: the peer must be trusted in `peers.toml` (and not
   revoked) before any frame it sends is decoded, or it gets
   `not-authorized`.

`acl-mode = "trust-tailnet"` relaxes only the first gate (who may connect);
who may run work is always the peer store. Frames are capped at 16 MiB +
64 KiB, as on iroh (one maximal task input plus envelope).

Outbound, the tailnet is one of the transports remote dispatch chooses from
per peer (§20). It is used only while liveness is `active`: in `stopped` or
`uninstalled` the discovery candidates are dropped and the router skips the
transport, so peers also known over iroh or the LAN are re-routed there, and
peers known only over the tailnet fail fast with `ENTANGLE-E0430` instead of
dialling.

Each discovery round also feeds the trusted, non-revoked peers it found into
the scheduler's worker pool, so a peer reachable only over the tailnet (no
mDNS sighting) can be chosen for remote work. The tailnet says nothing about
hardware, so such a peer is entered with a conservative default (one core, no
memory or GPU) and only light tasks fit it; if mDNS also describes the peer,
its advertised capabilities are kept. Entries the tailnet added are removed
when the peer leaves the tailnet or the tailnet stops being `active`.

---

## 11. Replicated integrity: `Deterministic` and `SemanticEquivalent`

Spec §7.5. The node that **submits** a task verifies it; the workers only run
it. Both policies place their replicas on **distinct** trusted peers (best
placement score first, skipping peers whose reputation for that policy is
below 0.80); replicas without a remote target run on the submitter's own
kernel.

* `--integrity deterministic --replicas N` — a hash quorum: a strict
  majority of the `N` outputs (`N/2 + 1`, e.g. 2 of 3) must be byte-identical
  (BLAKE3), so up to `(N-1)/2` faulty or unreachable workers are tolerated.
  Workers outside the majority lose reputation.
* `--integrity semantic-equivalent` — outputs are compared pairwise by a
  signed **metric component**; a pair agrees when its distance is
  `< --threshold`. The returned output is the replica that agrees with the
  most others (ties: most agreeing pairs among it and the replicas that agree
  with it, then smallest total distance, then smallest output BLAKE3), and the
  task is accepted when at least `--quorum` agreeing pairs back **that**
  output — agreeing pairs in an unrelated group of replicas do not count.

### Setting up a metric

Metrics are wasm components implementing `entangle:integrity/metric@0.1.0`.
Two ship in the catalog: `metric-bleu-4` (text) and
`metric-numerical-l2-relative` (number lists). Install one on the submitter:

```bash
entangle plugins install metric-bleu-4      # builds, signs with your key, trusts it — never loaded
entangle compute dispatch <plugin-id> --input 'translate: bonjour' \
  --integrity semantic-equivalent --metric <your-fingerprint>/metric-bleu-4@0.1.0 \
  --replicas 3 --quorum 2 --threshold 0.15 --json
```

`--metric-dir` defaults to `~/.entangle/plugins/<metric name>`. The metric's
publisher key must be in the **submitter's** keyring (`entangle keyring list`);
anything else is refused with `ENTANGLE-E0307` before a single replica is
sent. The daemon reads `keyring.toml` once, at startup: if `entangled` was
already running when `plugins install` (or `keyring add`) trusted the key,
**restart the daemon** before dispatching, or it answers `ENTANGLE-E0307`
even though `entangle keyring list` shows the key. The metric runs only on the submitter, at tier 2 (no filesystem, no
network, 256 MiB memory, 10 s per comparison) — workers never load it.

### What the verifier refuses

| Code | Meaning | What to do |
|---|---|---|
| `ENTANGLE-E0300` | A replica returned more than `max_output_bytes`. Checked before any metric is loaded; logged as an `OutputSizeExceededWarning` event (target `entangle::telemetry`) and the peer's reputation drops. | Investigate the named peer; raise `max_output_bytes` only if the output really is that large. |
| `ENTANGLE-E0302` | Too few replicas produced output (unreachable peers). | Check `entangle mesh peers`; the first underlying failure is reported instead when there is one. |
| `ENTANGLE-E0304` | `Attested` policy — TEE attestation is not supported yet. | Use `trusted-executor` for your own hardware. |
| `ENTANGLE-E0305` | No strict majority of the `deterministic` replicas returned identical output. Nobody loses reputation (there is no majority to disagree with). | The workload is not deterministic, or several peers are faulty. |
| `ENTANGLE-E0306` | `SemanticEquivalent` sent straight to a kernel. | Submit through the daemon / `compute dispatch`. |
| `ENTANGLE-E0307` | Metric publisher not in your keyring (as the running daemon loaded it). | `entangle keyring add` the publisher you actually trust, or use your own build; then restart the daemon, which reads the keyring only at startup. |
| `ENTANGLE-E0308`–`E0310` | Metric reference inconsistent, not loaded, or package rejected (bad signature, tier > 2, capabilities, not a metric component). | Rebuild/reinstall the metric; check `--metric-dir`. |
| `ENTANGLE-E0311`–`E0312` | The metric trapped / timed out / ran out of memory, or returned `NaN` or a negative distance, on **every** pair. When only some pairs fail, each failed pair counts as incomparable (a `MetricComparisonFailed` event at `entangle::telemetry`) and the task is still decided by the rest; a replica none of whose comparisons succeeded is reported `failed` with this error and loses reputation. | Fix the metric (a metric may return `+inf` for "incomparable"), or investigate the peer whose replica is reported `failed`. |
| `ENTANGLE-E0313` | Unusable policy: `replicas` outside 2..=16, `quorum` outside 1..=pairs, threshold not a finite number > 0. | Fix the flags. |
| `ENTANGLE-E0314` | Not enough agreeing replica pairs back any one output. When a strict majority of the replicas did agree, the remote replicas that agreed with none of them lose reputation. | The outputs genuinely differ, or the threshold is too strict for the metric. |
| `ENTANGLE-E0315` | A worker reported running under a different policy hash (INV-INT-1). The peer loses reputation. | Investigate the peer. |
| `ENTANGLE-E0316` | A control frame tried to change the policy of an in-flight task; the worker refused (the policy is immutable for a task's lifetime). | Submit a new task instead. |
| `ENTANGLE-E0318` | Two groups of replicas agree internally, equally well, but contradict each other, so there is no single answer to return. Nobody loses reputation. | Re-run with more replicas or a higher `--quorum`; if it recurs with the same peers, investigate them. |
| `ENTANGLE-E0319` | Not returned to the caller: logged (`SpotCheckAttestationFailure`) when a Layer-2 spot-check's re-run did not reproduce an output that was already accepted and returned (see below). The replicas behind that output lose reputation. | Treat results those peers returned as suspect; investigate them. Repeated failures exclude them from placement for that policy. |

Every successful dispatch reports the task's `policy_hash` (SHA-256 of the
canonical policy encoding) and, with `--json`, one record per replica: peer,
local/remote, status (`canonical`, `agreed`, `disagreed`, `failed`) and the
policy hash that replica observed.

### Spot-checks (Layer 2)

Replication only compares the replicas of one task with each other, so
replicas that collude — return the same wrong answer — win their vote. The
Layer-2 spot-check (spec §7.5) is the counterweight. After a
`deterministic` or `semantic-equivalent` task is **accepted** and its result
returned, the daemon re-runs it, with probability
`[scheduler] spot_check_probability` (default `0.01`, i.e. 1 %), on an
executor that ran none of its replicas: this node's own kernel if it has the
plugin loaded (the one executor it can trust), else a trusted peer whose
reputation for that policy is not excluded, **drawn at random** (else the
check is skipped). If this node's kernel ran a replica and the remote
majority outvoted it, that output is the re-run (nothing runs again). An
executor that cannot produce a comparable re-run (the plugin is not
installed there, it is unreachable, it breaks a guard) is followed by the
next one, up to four. The re-run is compared with the accepted output on
this node, as replicas are: byte-identical (BLAKE3) for `deterministic`,
metric distance `< --threshold` for `semantic-equivalent` (in acceptance's
pair order).

One re-run never outweighs the replicas on its own word. A re-run that does
not reproduce the accepted output is decisive only when it is a
`deterministic` re-run on this node's own kernel; otherwise (a remote
checker may lie; a `semantic-equivalent` re-run may be an honest outlier) the
next executor re-runs the task to break the tie.

* **Match** (counted as `confirmed`): the remote replicas behind the
  accepted output are credited — also when a tie-breaker reproduced the
  accepted output, in which case a remote checker that contradicted it loses
  standing (reason `spot-check-dissent`).
* **Mismatch** — an attestation failure, `ENTANGLE-E0319`: decisive, or
  corroborated by the tie-breaker. Every remote replica that produced or
  agreed with the accepted output loses reputation for that policy (reason
  `spot-check-mismatch`), a `SpotCheckAttestationFailure` warning is logged
  at target `entangle::telemetry` (task id, plugin, policy hash, checker,
  tie-breaker, both BLAKE3 digests, the metric distance, the penalised peers)
  and counted as `mismatch`.
* **Inconclusive**: no executor produced a comparable re-run (each failed,
  timed out, was oversized or echoed another policy hash), the metric could
  not compare it, or a contradiction could not be settled (no tie-breaker
  left, or it agreed with neither side). Nobody behind the accepted output is
  blamed (a remote executor that broke the size or policy-hash guard loses
  standing itself). With only remote checkers, blaming anyone needs two
  spare peers; a mesh with one spare peer and the plugin not loaded here
  can confirm results but not catch colluders.

It is **detective, not preventive**: the check starts after the caller has
its result and never changes it. A wrong answer that colluders got accepted
is not recalled; what changes is that they are caught at the sampling rate
and, after a few failures, excluded from placement for that policy (§11
reputation tiers). If a single task must not be wrong, ask for more replicas.

Not checked: `none`, `trusted-executor` (spec §7.5 exempts them) and tasks
whose accepted output this node's own kernel already produced or agreed with
(a local replica). At most `spot_check_max_concurrent` (default 4) run at
once; a sampled task that finds them all busy is skipped and counted
(`skipped_saturated`), never queued. `compute dispatch --json` reports the
decision as `spot_check`: `scheduled`, `not-sampled`, `skipped-saturated`,
`skipped-no-checker`, `exempt-policy`, `exempt-reproduced-locally` or
`disabled`; the verdict itself goes to the log and the
`entangle_integrity_spot_checks_total` metric (§14a), never back into the
result. Set `spot_check_probability = 0` to turn spot-checks off (every
spot-check is one more execution of the task on someone's machine).

Known limitations:

* **Colluders that outvote the local kernel.** When this node's own kernel
  ran a replica and was outvoted, its output counts as the spot-check re-run
  only if the task was sampled. With `spot_check_probability = 0` nothing is
  ever re-run, and at the default rate colluding peers that outvote the
  submitter's own kernel are penalised only on the sampled share of such
  tasks.
* **Executors can tell a spot-check from the policy.** The sealed policy shows
  `replicas: N` to every executor. A worker that is never best-ranked for a
  `Deterministic { replicas: 1 }` task can therefore tell that a frame it
  receives is a spot-check, and answer it honestly (for a lie it told as a
  replica) or make it inconclusive. A remote checker's contradiction needs an
  independent tie-breaker, which bounds framing, but this does not hide the
  check from a colluder. Nothing in the code changes this; mitigate with more
  replicas.

Scheduler wire version: v2 (task frames carry the policy and its hash). A
node running an older build answers `unsupported-version`; upgrade both ends.

---

## 12. Native (tier 4–5) plugins and the OS sandbox

A native plugin is a host executable (`runtime = "native"`, packaged as
`plugin.bin`). It is signature-verified exactly like a wasm component, then
run as a **sandboxed subprocess**, one fresh process per invocation, spoken
to over length-prefixed frames on stdin/stdout (`crates/entangle-sandbox`).

**Disable them.** `[security] max_tier_allowed = 4` refuses every tier-5
plugin; `= 3` refuses every native plugin. Refusal happens before signature
work, capability grants, or any file write (`ENTANGLE-E0043`).

**What the sandbox is made of.** The capabilities the broker grants become
the profile; everything else is denied.

| Layer (Linux) | What it does |
|---|---|
| Landlock (ABI ≥ 1) | Filesystem allowlist: the staged binary (read+exec), system libraries and loader cache (read+exec), the package directory (read), the plugin's storage scopes (read+write, never exec), `/dev/null`. Scopes are resolved without following symbolic links (the daemon resolves its own data and package directories first), so a plugin that can write into a share cannot redirect another plugin's grant with a planted link. ABI ≥ 4: TCP bind/connect denied unless networking is granted. ABI ≥ 6: signals and abstract Unix sockets scoped to the sandbox (the plugin cannot signal the daemon). Below ABI 6 the plan is reported as *reduced*: the plugin runs under the daemon's uid with no PID namespace and can signal it. |
| user + network namespace | When unprivileged user namespaces work: the plugin sees only a downed loopback. |
| seccomp-bpf | `socket()` and `socketpair()` refused for every address family not granted (`AF_UNIX` only with `host.docker-socket` — this is what keeps the daemon's RPC socket out of reach); creating or joining namespaces refused (`clone3` reports `ENOSYS`, libc falls back to `clone`); `prlimit`/`setpriority`/`sched_set*`/`ioprio_set` refused on any process but the plugin itself (it shares the daemon's uid); `keyctl`/`add_key`/`request_key` refused; `setsid`/`setpgid` refused (descendants stay in the group that is killed); `io_uring_setup`, x32 and foreign-arch syscalls refused. |
| process | no capabilities (ambient, bounding, effective, permitted and inheritable sets emptied — a daemon run as root does not hand root to its plugins), a fresh, empty session keyring (the daemon's or login session's keys are not reachable; with seccomp the key syscalls are refused outright), `no_new_privs`, `RLIMIT_CORE=0`, address-space / CPU-time / fd rlimits, inherited fds closed at exec, empty environment, own process group (killed on timeout or when the invocation is dropped), killed if the spawning daemon/CLI dies (`PR_SET_PDEATHSIG`). |

Fallbacks: **bubblewrap** when Landlock is absent; **Seatbelt** (`sandbox-exec
-p <generated profile>`) on macOS. On hosts that restrict unprivileged user
namespaces (Ubuntu ≥ 23.10 by default) network denial still holds via seccomp
and Landlock's TCP rules; if only Landlock TCP rules remain, the plan is
reported as *reduced* (UDP not isolated) rather than silently accepted.

**Capability → access.**

| Capability | Child gets |
|---|---|
| `storage.local { scope = "plugin" }` | `~/.entangle/data/plugins/<publisher>/<name>` = `$ENTANGLE_DATA_DIR` = `$HOME` = cwd; rw, or ro with `mode = "ro"` |
| `storage.local { scope = "shared" }` | `~/.entangle/data/shared` = `$ENTANGLE_SHARED_DIR`; rw, or ro with `mode = "ro"` |
| `storage.share.<n>` | `~/.entangle/data/shares/<n>` (ro / rw / rw-scoped per mode) = `$ENTANGLE_SHARE_<N>`; `<n>` must match `[a-z0-9][a-z0-9_-]*`, so a share can never name a path outside `shares/` (`ENTANGLE-E0743`) |
| `net.lan`, `net.wan` | IP networking as a whole (no per-host allowlist yet — wasm plugins get per-address rules, §18); an operator denial of either refuses both to a native plugin |
| `compute.gpu` | read, write and ioctl on `/dev/dri`, `/dev/kfd`, `/dev/nvidia*` when present (ordinary scopes never get device ioctls) |
| `host.docker-socket` | rw `/var/run/docker.sock` + `AF_UNIX` sockets |

**Where things live.** Verified binaries are staged (never run from the
package directory) under `~/.entangle/native/entangle-native-<name>-<random>/`
(`0700`, binary `0500`), removed on unload. The process using a copy holds a
lock on it; copies left behind by a daemon that was killed (SIGKILL, OOM) are
removed when the next daemon or local (`--allow-local`) kernel starts, while
copies a running daemon still uses are kept. Plugin stderr is logged under the
`entangle::native` tracing target, bounded per invocation.

**No primitive at all.** Native plugins are refused with `ENTANGLE-E0700`
unless the operator sets `allow_unsandboxed_native = true`, in which case
they run with only the process layer (and seccomp/namespaces if available) —
`entangle doctor` then warns on every run.

**Check a host.** `entangle doctor` (checks 11–12) and `entangle
print-platform` show the exact layers and run a real trial engagement.

Known limits: on a host without seccomp, descendants that call `setsid()`
escape the timeout kill (they stay sandboxed); no cgroup accounting; Landlock (through ABI 7) does not cover
path-based Unix sockets, which is why the seccomp `AF_UNIX` rule matters — on a
host without seccomp that protection is absent, and the plan is reported as *reduced*.

---

## 13. OCI registries and mirrors

`entangle plugins install oci://registry[:port]/repo[:tag|@sha256:<hex>]`,
`entangle plugins publish`, `entangle plugins tags` and
`entangle plugins mirror-sign` use the `entangle-oci` client (OCI Distribution
v1.1). Error codes are `ENTANGLE-E0800`..`E0829`.

**Trust model.** Only your publisher keyring (`~/.entangle/keyring.toml`)
decides whether a pulled package installs. The registry's name, TLS identity,
your credentials for it, and any mirror listing are not inputs to that
decision (ATC-MIR-1): a package signed by an unknown key is rejected
(`ENTANGLE-E0814` wrapping `E0101`) even from a registry you operate. After
verification the install also enforces `security.max_tier_allowed`
(`ENTANGLE-E0043`) and the kernel's load-time checks; the daemon-less
fallback kernel applies the same `max_tier_allowed` ceiling.

**What is installed is what you asked for.** A valid signature proves who
signed the bytes, not that they are the plugin you named, so the install also
requires the package's plugin name to equal the last component of the
repository (`oci://r/acme/hello:1.0.0` must serve a plugin named `hello`) and,
when the tag is a full `MAJOR.MINOR.PATCH` version, the package's version to
equal it. Floating tags (`latest`, `stable`) and digests make no version
claim. The package is staged in a sibling directory and swapped into place, so
a failed install never leaves a half-written directory. Without `--out`, an
existing `~/.entangle/plugins/<name>` that holds another publisher's plugin is
not overwritten; pass `--out`. Catalog-only flags (`--catalog`, `--key`,
`--wasm`, `--target`) are refused for `oci://` references rather than ignored.

### Authentication

Resolved per registry (`host[:port]`, spelled as in the reference, ASCII case
ignored), first match wins; credentials are never logged or printed:

1. `ENTANGLE_OCI_TOKEN` - a bearer token sent directly, or
   `ENTANGLE_OCI_USERNAME` + `ENTANGLE_OCI_PASSWORD` - Basic credentials, also
   used against the registry's token endpoint (the standard Bearer flow:
   `WWW-Authenticate` realm/service/scope). Environment credentials apply
   **only** to the registry named by `ENTANGLE_OCI_REGISTRY=<host[:port]>`;
   every other registry is treated as if they were unset (it falls through to
   the file below, or anonymous). Setting them without `ENTANGLE_OCI_REGISTRY`
   is an error (`ENTANGLE-E0815`), so a CI token exported for one registry is
   never offered to another.
2. `~/.entangle/oci-auth.toml`, which must be mode `0600` on Unix:

   ```toml
   [registries."ghcr.io"]
   username = "you"
   password = "<personal access token>"

   [registries."registry.internal:5000"]
   token = "<bearer token>"
   ```

With none of these the client is anonymous and still follows the token flow
for public repositories. `Authorization` is only ever sent to the registry's
own `host:port`, plus, for Basic credentials, the token endpoint (`realm`) that
registry names in its Bearer challenge (standard token flow; that endpoint may
be on another host, e.g. a separate auth service): blob redirects to a CDN on
another host are followed without it. Redirects are capped at 5; only HTTP 429 and 5xx are retried (4 attempts,
exponential backoff, `Retry-After` honoured up to 8 s). A chunk upload
(`PATCH`) that fails that way is not resent blindly: the client asks the
registry how much of the upload it holds (`GET` on the upload URL, `Range`
header) and continues from there, since a proxy can answer 5xx after the
registry already stored the chunk. Chunks are at least the registry's
`OCI-Chunk-Min-Length`, when it advertises one.

### HTTPS and insecure registries

HTTPS is mandatory, using the bundled web roots plus the system trust store
(`SSL_CERT_FILE` is honoured, so a private CA works). Plain HTTP is allowed
only for loopback registries (`localhost`, `127.0.0.0/8`, `::1`; the resolved
peer must really be loopback) or when you pass `--insecure-registry`, which
makes the client speak plain HTTP to that registry (and to token endpoints and
redirect targets it names). Use it on trusted networks only; it does not
weaken artifact verification, but it exposes your registry credentials.

### Size limits

Blobs are capped at 512 MiB (checked from the descriptor before any bytes are
requested and enforced while streaming; a registry that sends more than the
descriptor says is cut off), manifests at 4 MiB, a decompressed package at
256 MiB. A blob whose SHA-256 differs from its descriptor is rejected
(`ENTANGLE-E0807`).

### Mirror keys and signed listings

A mirror can publish a signed listing of a repository's tags (see
`docs/plugin-authoring.md` section 7). Configure the keys you accept for
listings in `~/.entangle/mirror-keys.toml`, same schema as `keyring.toml`:

```toml
[[entries]]
fingerprint = "<32 hex>"
public_key = "<64 hex>"
publisher_name = "example mirror"
added_at = 0
note = "listing key"
```

(`entangle plugins tags --mirror-keys <FILE>` uses another file.) Mirror keys
are a separate trust root: a mirror key can sign listings but never artifacts,
and publisher keys are not accepted for listings. `entangle plugins tags`
warns if one key is in both files. `plugins tags` prints the listing's recorded
verification status:

| Status | Meaning |
|--------|---------|
| `verified (mirror key <fp>)` | signed by a configured mirror key, for this repository, not expired; tag digests shown come from the signed listing |
| `unsigned` | no listing, or a listing without a signature; tags shown are the registry's own and carry no digests |
| `INVALID: <reason>` | unknown signer, bad signature (tampered), wrong repository, malformed |
| `EXPIRED` | correctly signed but past `expires_at`; treat as stale |

`--require-verified` makes `tags` exit non-zero unless `verified`. Mirror
operators publish with `entangle plugins mirror-sign` (refuses a key that is
trusted as a publisher on that machine).

---

## 14. Observability: metrics, tracing, `entangle diag mesh`

Everything here is **off by default** and costs nothing until enabled. The
daemon owns one metrics registry, which the kernel, broker, scheduler and
mesh code record into; the scrape endpoint and `entangle metrics` both render
it.

### 14a. Metrics

```toml
[metrics]
enabled = true
listen = "127.0.0.1:9464"
# allow_non_loopback = true   # only to expose it deliberately
```

`GET /metrics` returns the Prometheus text format 0.0.4
(`Content-Type: text/plain; version=0.0.4; charset=utf-8`). `HEAD /metrics` is
allowed, any other method on it is `405`, any other path is `404`.

The endpoint has **no authentication**. It therefore refuses to start on a
non-loopback address unless `allow_non_loopback = true`
(`ENTANGLE-E0656`); if you do open it, firewall it. It serves one request per
connection, gives clients 5 s to send their request head and 15 s in total,
and serves at most 32 connections at once (extras are closed).
`listen` must be an IP literal and port (`localhost` is not accepted).

`entangle metrics` prints the same text by asking the running daemon over the
RPC socket, so it works with `[metrics] enabled = false`. If the daemon is not
running it fails with `daemon not running at ~/.entangle/sock`.

Prometheus scrape job:

```yaml
scrape_configs:
  - job_name: entangled
    static_configs: [{ targets: ["127.0.0.1:9464"] }]
```

#### Metric catalogue

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `entangle_plugin_invocations_total` | counter | `plugin`, `outcome` (`ok`/`error`) | Plugin invocations through the kernel. Calls for an id that is not loaded count under `plugin="unknown"`. |
| `entangle_plugin_invocation_duration_seconds` | histogram | `plugin` | Wall-clock duration of each invocation. |
| `entangle_plugin_errors_total` | counter | `plugin`, `class` | Failed invocations (one-shot calls and streams) by error-code class: `E05xx` is `ENTANGLE-E05..`, `none` if the error carries no code. |
| `entangle_plugin_streams_total` | counter | `plugin`, `outcome` (`ok`/`error`/`cancelled`) | Stream-plugin invocations through the kernel, one per stream (§17). `cancelled`: the stream was torn down (cancel, peer lost, a size cap, the timeout) before the plugin returned. Streams are not counted in `entangle_plugin_invocations_total`. |
| `entangle_plugin_stream_duration_seconds` | histogram | `plugin` | Wall-clock duration of each stream; buckets reach the 1 h stream ceiling. |
| `entangle_plugins_loaded` | gauge | — | Plugins currently loaded. |
| `entangle_plugin_uptime_seconds` | gauge | `plugin` | Seconds since each loaded plugin was loaded (series vanish on unload). |
| `entangle_capability_grants_total` | counter | `capability` | Broker grants: one per declared capability when a plugin loads (its standing grant), plus one per successful plugin `capability.fetch`. |
| `entangle_capability_denials_total` | counter | `capability`, `reason` (`not_declared`, `operator_policy`, `tier_ceiling`, `revoked`, `biscuit_invalid`) | Broker denials, at load (`operator_policy`) and for every refused `capability.fetch`. |
| `entangle_biscuit_verification_seconds` | histogram | `outcome` (`ok`/`denied`) | Latency of cross-node biscuit verification. |
| `entangle_rpc_requests_total` | counter | `method`, `outcome` (`ok`/`error`) | RPC requests. |
| `entangle_rpc_request_duration_seconds` | histogram | `method` | RPC handling time. |
| `entangle_remote_dispatch_total` | counter | `outcome`, `transport` | Tasks this node sent to a peer: `ok`, `transport_error`, `output_too_large`, `error`, or `rejected_<code>` for a peer's refusal (`rejected_not_authorized`, `rejected_plugin_not_loaded`, ...). `transport` is the one that carried it (or was being tried when it failed): `local`, `tailscale`, `iroh`, or `none` when no transport had a route. |
| `entangle_remote_serve_total` | counter | `outcome`, `transport` | Frames this node answered for peers: `ok`, `ack`, or the refusal code (`not-authorized`, `plugin-not-loaded`, ...). `transport` is the one the frame arrived on: `iroh` (which includes LAN dialling, `local` on the sender's side) or `tailscale`. |
| `entangle_remote_stream_opens_total` | counter | `outcome` (`ok`, `transport_error`, `no_route`), `transport` | Streams this node opened to peers through the transport router (§20). |
| `entangle_integrity_verdicts_total` | counter | `policy`, `outcome` | One per `compute/dispatch`: `policy` is `none`, `deterministic`, `semantic-equivalent`, `trusted-executor` or `attested`; `outcome` is `accepted`, `rejected` (integrity refusal), `output_size_exceeded` or `failed` (placement/transport/execution). |
| `entangle_integrity_spot_checks_total` | counter | `policy`, `outcome` (`confirmed`, `mismatch`, `inconclusive`, `skipped_saturated`, `skipped_no_checker`) | Layer-2 spot-checks (§11): finished re-runs by verdict (`mismatch` is an attestation failure, `ENTANGLE-E0319`), and sampled tasks that were not re-run. |
| `entangle_integrity_spot_checks_inflight` | gauge | — | Spot-checks running right now (at most `[scheduler] spot_check_max_concurrent`). |
| `entangle_integrity_output_size_exceeded_total` | counter | — | Replica outputs over `max_output_bytes` (the `OutputSizeExceededWarning` events, `ENTANGLE-E0300`). |
| `entangle_reputation_peers` | gauge | `policy`, `tier` (`trusted`/`good`/`probation`/`excluded`) | How many observed peers sit in each reputation tier. |
| `entangle_mesh_peers` | gauge | `state` (`trusted`, `observer`, `revoked`, `sighted`) | Peer-store (one per trust level) and mDNS counts. `sighted` is unauthenticated and exists only with `mesh.local`. |
| `entangle_scheduler_inflight_tasks` | gauge | — | Tasks inside the dispatcher right now. The dispatcher places and runs immediately and has **no queue**, so this is the saturation signal. |
| `entangle_scheduler_workers` | gauge | — | Live workers in the scheduler pool. |
| `entangle_mesh_tailscale_state` | gauge | `state` (`active`, `stopped`, `uninstalled`, `unknown`) | One-hot: 1 for the tailnet state the liveness poller last confirmed (`unknown` until the first poll). **Absent unless `mesh.tailscale` is running.** |
| `entangle_build_info` | gauge | `version` | Always 1. |
| `entangle_daemon_uptime_seconds` | gauge | — | Seconds since the daemon started. |
| `entangle_telemetry_spans_dropped_total`, `..._spans_exported_total`, `..._export_failures_total` | counter | — | OTLP exporter health (§14b); present only with `[telemetry.otlp]` on. |
| `entangle_metrics_dropped_series_total` | counter | — | Appears only if a metric family hit its label-set cap (a bug indicator). |
| `entangle_aot_cache_hits_total`, `entangle_aot_cache_misses_total` | counter | — | Wasm component loads answered from the AOT cache, and loads that compiled (§23). |
| `entangle_aot_cache_rejections_total` | counter | `reason` (`permissions`, `header`, `version`, `mac`, `deserialize`, `io`) | AOT cache entries refused and deleted (`ENTANGLE-E0785`); the component was compiled instead. |
| `entangle_aot_cache_evictions_total` | counter | `reason` (`age`, `size`, `orphan`) | Entries removed by the maintenance loop's GC. |
| `entangle_aot_cache_bytes` | gauge | — | Bytes the AOT cache holds on disk (exact after each GC). |
| `entangle_plugin_restores_total` | counter | `outcome` (`restored`, `failed`, `disabled`) | Entries of the plugin-state file reloaded at daemon start (§22). |
| `entangle_plugin_reloads_total` | counter | `outcome` (`swapped`, `refused`, `migrate_failed`) | Hot reloads of a loaded plugin to another version (§24). |
| `entangle_plugin_idle_teardowns_total` | counter | `plugin` | Idle plugin instances dropped after their `idle-timeout-secs` (§24). |

#### Label cardinality

No label carries a peer id or free text. `capability` is the capability
*kind* (`compute.cpu`, `storage.share`, `custom`, ...), never a share or
custom name. `method` is normalised to the RPC methods the daemon implements
(everything else is `unknown`). `class`, `policy`, `tier`, `state` and
`outcome` (and `reason`) draw from the closed sets above, and `transport` from `local`,
`tailscale`, `iroh`, `none`. The one open-ended label is
`plugin`: each distinct plugin id gets its own series for the **first 64**
ids the daemon sees; later ids fold into `plugin="other"`. As a backstop every
family holds at most 512 label sets (excess samples are dropped and counted in
`entangle_metrics_dropped_series_total`). Counters for a plugin that has been
unloaded stay until the daemon restarts; its `plugin_uptime_seconds` series
disappears at once.

### 14b. Tracing (OTLP/HTTP)

```toml
[telemetry.otlp]
enabled = true
endpoint = "http://localhost:4318"   # spans go to <endpoint>/v1/traces
service_name = "entangled"
```

The daemon exports `tracing` spans as OTLP/HTTP **JSON** (`POST
<endpoint>/v1/traces`, `Content-Type: application/json`; `resourceSpans` →
`scopeSpans` → `spans`, hex `traceId`/`spanId`/`parentSpanId`, unix-nanosecond
timestamps as strings). Point it at a local OpenTelemetry Collector or agent
with the OTLP **HTTP** receiver (port 4318; port 4317 is gRPC, which is not
spoken). The exporter has no TLS client, so `https://` endpoints are refused
at startup (`ENTANGLE-E0651`): terminate TLS in the collector/agent.

A collector fragment:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318
```

Delivery: spans queue (2048) and ship in batches of up to 256 or every 5 s; a
full queue drops the new span and counts it (never blocks the daemon). Each
request has a 10 s timeout. `429`, `502`, `503`, `504` and connection
failures are retried with exponential backoff (250 ms doubling to 10 s,
`Retry-After` honoured, 3 retries); any other `4xx` or `5xx` is permanent and
the batch is dropped (the OTLP/HTTP retry rules). On shutdown
the queue is flushed, bounded: each remaining batch is sent once (no retries)
and the exporter gives up one request timeout (10 s) after the stop began,
counting what is still unsent as dropped, so an unreachable collector delays
the daemon's exit by at most about 11 s. Failures are visible as
`entangle_telemetry_*` metrics.

Spans (from `entangle*` targets, `INFO` and above, independent of
`RUST_LOG`): `rpc.request`, `task.dispatch`, `plugin.invoke` (one-shot calls
and streams alike, told apart by its `world` attribute: `plugin` or
`stream-plugin`),
`remote.dispatch` (client) and `remote.task.execute` (server); the last two
carry a `transport` attribute (`local`, `tailscale`, `iroh`, `none`). `WARN`/`ERROR`
events inside a span are attached to it; an `ERROR` marks the span failed.

**Across the mesh.** When a remote dispatch happens inside a recorded span,
the task frame carries a W3C `traceparent` (an optional trailing extension on
the scheduler wire v2 task frame), over whichever transport carries it. The worker's `remote.task.execute` span
joins that trace, so one trace shows the submitter's `remote.dispatch` and the
worker's execution (and its `plugin.invoke`) as parent and child. The worker
treats the value as untrusted: it only chooses which trace the span belongs
to; authorization is decided before and independently from the transport-
authenticated peer id, and a malformed value is ignored. With export off no
extension is sent, so frames are byte-identical to before. A peer built before
this extension answers it `MalformedRequest`; the dispatcher then resends the
same task without it, on the same transport, and stops attaching it for that
peer until restart.

### 14c. `entangle diag mesh`

```text
$ entangle diag mesh --probe
Mesh diagnostics for laptop (3f9c…)

Transports
  configured: local, iroh, tailscale
  running:    local, iroh
  ! tailscale is configured but not running (see the daemon log for why)

Local endpoints
  iroh        3f9c…@192.168.1.20:41641

Trusted peers (2)
  desk  7a21…  [trusted]
    mdns       192.168.1.31:7001   sighted 4s ago (1 address; unauthenticated, passive)  rtt 1.1 ms
    iroh       192.168.1.31:41641  address book ([scheduler] peers)  rtt 3.2 ms
    route: local -> iroh  (last used: local, 12s ago)
      skipped tailscale: not running on this node
  ghost  c0de…  [trusted]
    no path: no transport currently knows how to reach this peer
    hint: is the peer on the same LAN with mDNS allowed?; add its address under [scheduler] peers

Probe: 1 of 2 trusted peer(s) answered
```

`--json` prints the daemon's structured report (the `diag/mesh` RPC result).
The report lists configured vs running transports, this node's endpoint
addresses, the tailnet state (state, reason, time in state, candidate count)
when `mesh.tailscale` runs, and for every **trusted** (non-revoked) peer each
path a transport currently knows: an mDNS sighting, an iroh address-book entry
(`[scheduler] peers`), a tailscale candidate. Untrusted mDNS sightings are only
counted.

Each trusted peer also has a `route:` line: the transports remote dispatch
would try for it right now, in order (§20), the transports it would skip and
why (`tailscale: tailnet stopped (NeedsLogin)`, `iroh: not in the address
book ([scheduler] peers)`, `... [mesh.overrides]`), and the transport the
last successful dispatch or stream to it used (the peer record's chosen
transport). It is absent when this node dispatches nothing remotely.

`--probe` (with `--timeout-ms`, default 3000, at most 30000) measures a round
trip per path, through the daemon, concurrently, each over its own transport
regardless of the routing policy. Every probe is a scheduler control frame
about a task that does not exist: the peer authenticates us, checks its
allowlist and answers `unknown task` without running anything, so an answer
proves dial + handshake + authorization. A peer that answers `not authorized`
is shown as reached with that error: the network path is fine but *it* does
not trust this node. iroh paths are probed over the iroh endpoint, tailscale
paths over the tailnet session (`entangle/scheduler/1` selected on it), and an
mDNS sighting that advertises a key and mesh port over the LAN path when this
node runs the iroh endpoint; other sightings are passive and have no round
trip.

---

## 15. Shell wrappers: warning when an agent host runs outside Entanglement

Running `claude`, `codex` or `opencode` directly bypasses Entanglement (that is
by design, spec §8.3). The **wrapper** is an opt-in shell function that prints a
warning to stderr when you do that by accident, then runs the real binary with
the same arguments and exit status. It is a UX guardrail, **not a security
boundary**: `command claude` or `\claude` bypasses it.

```bash
entangle wrapper enable     # install into ~/.bashrc, ~/.zshrc, ~/.config/fish/conf.d/entangle.fish
entangle wrapper status     # per rc file: installed / outdated / no block / damaged / 2 blocks
entangle wrapper repair     # rewrite a damaged or duplicated block into exactly one
entangle wrapper disable    # remove the blocks and record [wrappers] install = false
```

What it does and does not touch:

- One block per file between `# >>> entangle wrapper >>>` and
  `# <<< entangle wrapper <<<`, defining one function for every host that
  `entangle agent run` supports (`entangle agent list` shows the binary names;
  today `claude`, `codex`, `opencode`). A host added in a later release shows as
  "outdated" in `status`; `enable` refreshes it.
- Nothing outside the markers is changed. Enable is idempotent; `disable` after
  `enable` restores the file byte-for-byte. LF and CRLF files keep their line
  endings (a mostly-LF file with a few pasted CRLF lines gets an LF block,
  since the shell would reject `claude() {` followed by `\r`), file permissions are kept, a symlinked rc file (dotfile managers) is
  edited through the link, and every write is atomic (temp file + rename).
- bash and zsh get POSIX-function syntax (so `sh` can source it too); fish gets
  a fish `function`. An `alias claude=...` defined earlier in the rc file is
  set aside while the function is defined and restored right after it (bash
  and zsh would otherwise expand it inside the definition, a syntax error that
  also skips the rest of the file), so `alias claude='claude --flag'` keeps
  working and still goes through the shim; an alias that points elsewhere
  (`alias claude=claude-beta`) bypasses it, and doctor reports that. `~/.zshrc` and the fish snippet are written even if you do
  not use those shells. `XDG_CONFIG_HOME` is honoured for the fish path, and
  `ZDOTDIR` (absolute) for the zsh one: the block then goes to
  `$ZDOTDIR/.zshrc`, the file zsh actually reads.
- **Login shells.** bash reads `~/.bashrc` only in interactive non-login shells;
  on macOS Terminal (login shells) add `source ~/.bashrc` to `~/.bash_profile`.
- `enable`/`disable` record `[wrappers] install` in `config.toml` with a
  format-preserving editor: comments, key order and sections the CLI does not
  model (`[mesh.tailscale]`, `[metrics]`, `[telemetry]`) are left as they were.
  Disabling is never silent: it prints what it did and the choice persists.
- Inside an Entanglement session (`ENTANGLE_SESSION_ID` set) the shim is silent.
- Setting `[wrappers] install = false` in `config.toml` by hand (spec §8.3
  item 2) silences the shim too, without touching the rc files: each function
  checks the key (one `awk` over `config.toml`) when an agent host is launched
  outside a session. `status` then shows the remaining blocks as inactive;
  `entangle wrapper disable` removes them.

### `entangle doctor` and the wrapper

The `wrapper` row is skipped unless you opted in (`[wrappers] install = true`).
When opted in:

- block missing from an rc file, damaged, duplicated or outdated: **warning**
  naming `entangle wrapper enable` / `repair`;
- the name resolves to something other than the shim: **failure** (exit 1),
  e.g. `'claude' is shadowed by /usr/local/bin/claude (PATH ahead of shell
  function). Run 'entangle wrapper repair' or 'unalias claude'.` Other shadow
  sources reported: an alias, or a different shell function (with the defining
  file when zsh says).

Shadowing is detected the way your shell sees it: doctor runs `$SHELL -i -c`
(bash or zsh) with an empty stdin, loads your rc files, and asks `type <bin>`
and `typeset -f <bin>`, under a timeout (8 s, `ENTANGLE_DOCTOR_PROBE_TIMEOUT_MS`
to change). Limits:

- only bash and zsh are probed; with another `$SHELL` (fish, sh, unset) the
  check is skipped and says so;
- the probe shell runs in its own session without a controlling terminal (so
  it cannot stop `entangle doctor &` run as a background job), so an rc file
  that behaves differently without a tty is probed in that mode, and one that
  blocks or reads stdin is cut off by the timeout (reported as a warning, not
  a pass); one that `exec`s or exits before the probe runs (`exec tmux`) is
  reported as "could not run" too;
- only what an *interactive* shell loads is seen; shadowing introduced only by a
  login profile (`~/.bash_profile`, `~/.zprofile`) that the interactive shell
  does not re-read is not;
- it checks the shell you run doctor from, not every shell on the machine;
- the "shell history shows recent unwrapped invocations" note from the spec is
  not implemented.

**Differences from the spec text (§8.3).** The wrapper is opt-in through
`entangle wrapper enable` only: there is no first-run wizard question and no
`entangle install --no-wrapper` flag (`entangle init` and `install` never
touch shell rc files, so there is nothing to opt out of), and doctor's
shell-history note (item 3) is not implemented. An absent `[wrappers] install`
key means "not enabled".

**Upgrade order.** `entangle wrapper enable` and the tier-ceiling workflow
write the `[wrappers]` and `[plugins]` sections. A daemon built before these
sections existed rejects unknown config keys and will not start on such a
file, so upgrade the daemon (`entangled`) together with, or before, the CLI;
after rolling a daemon back, remove those two sections from `config.toml`.

---

## 16. Changing the tier ceiling safely (`max_tier_allowed`)

`[security] max_tier_allowed` (1–5) caps the plugin tier the daemon will load
(§2). Raising it is a config edit. **Lowering it below the tier of a loaded
plugin is never silent**: the plugins that would stop are listed first.

```bash
entangle security set-max-tier 3                 # asks, at a terminal
entangle security set-max-tier 3 --force-unload  # non-interactive, loud
# or edit config.toml by hand, then:
entangle config reload                           # same prompt; cancel reverts your edit
entangle config validate                         # CI: exit 1 if the file would orphan plugins
```

At a terminal (stdin is a tty) you see:

```
Lowering [security] max_tier_allowed from 5 to 3 will affect 2 running plugins:

  - <fp>/agent-host@0.1.0   (tier 5, native subprocess, 1h17m uptime)
  - <fp>/cuda-runner@0.1.0  (tier 4, native subprocess, 22h uptime)

Choose action:
  [u] unload-and-disable  (default; plugins are stopped, marked disabled in config)
  [c] cancel              (config reload aborted; max_tier_allowed unchanged)

Decision [u/c]:
```

- **Unload-and-disable** (Enter or `u`): the daemon takes the delta set and
  sets the new ceiling in one step (a load still in flight is either in the
  delta set or refused with `ENTANGLE-E0043`), then drains each affected
  plugin — new invocations are refused, invocations already running complete
  (each within its own timeout) — and only then unloads it, releasing its
  broker grants, and audits it. An active stream (§17) of an affected plugin
  is drained the same way: the lowering waits until it ends (completes,
  reaches its stream timeout, or is cancelled by its submitter); new streams
  are refused. From the moment the ceiling is lowered, though, an affected
  plugin's capabilities stop as if revoked (§18): its `capability.fetch`
  calls are refused (`ENTANGLE-E0127`), new sockets and name lookups are
  refused, and an invocation or stream running on a `net.lan` / `net.wan`
  grant is stopped (`ENTANGLE-E0511`) rather than drained — no connection
  outlives the ceiling that forbids it. One without network keeps the
  directories it had open until it ends. Afterwards a load above the
  ceiling fails with `ENTANGLE-E0043`. The plugin ids are added to
  `[plugins] disabled` in `config.toml`.
- An answer at the prompt covers exactly the plugins listed. If another
  plugin above the new ceiling was loaded while the prompt waited, the daemon
  refuses with `ENTANGLE-E0758` and nothing changes; re-run to see the current
  list. (`--force-unload` consents in advance to whatever is above the ceiling
  when it is applied; each such plugin still gets its own `ENTANGLE-W0214`.)
- **Cancel** (`c`, or end of input): nothing is unloaded. For `config reload`
  your edit of `config.toml` is reverted to the daemon's ceiling; for
  `set-max-tier` the file was never changed. The command exits 1 so scripts
  cannot mistake it for success.
- **No terminal, no `--force-unload`**: refused with `ENTANGLE-E0753`, nothing
  changes.
- **`--force-unload`** (or, at a terminal only, `--yes`, which answers the
  prompt with its default; without a terminal `--yes` is refused like no flag):
  unloads and disables without asking, but the affected list goes to **stderr**
  and each plugin gets an `ENTANGLE-W0214` line. There is no flag that skips
  the audit trail.
- **Ordering.** The daemon is changed only once `config.toml` is known to take
  the edit (otherwise `ENTANGLE-E0754` and nothing changes); right after the
  daemon applied it the file is written, and the durable audit lines last, so
  a failure late in the command never leaves the daemon changed while the file
  still holds the old ceiling (which the next daemon start would restore).
- **Raising** (or lowering past every loaded plugin's tier) never unloads
  anything. Every change of the ceiling is audited: a raise as
  `ENTANGLE-I0217`, a lowering as `ENTANGLE-I0215` — also when the daemon is
  not running and only `config.toml` changes.
- The daemon is told over RPC (`security/plan-max-tier`, `security/apply-max-tier`,
  `security/cancel-max-tier`); only the ceiling is applied at runtime, every
  other config change needs a daemon restart. If the daemon is not running,
  nothing is loaded (the daemon does not persist its loaded set), so only
  `config.toml` changes and the CLI says so; the ceiling applies at next start.

**Audit trail.** Each outcome is written in two places: the daemon's in-memory
broker audit log (`ENTANGLE-W0214` per unloaded plugin, `ENTANGLE-I0215`
summary, `ENTANGLE-I0216` on cancel, `ENTANGLE-I0217` for a raise — the same log that records grants and
releases, also emitted to the `entangle::audit` tracing target with the code in
a `code` field — W-codes at WARN level, so `grep ENTANGLE-W0214` on the daemon
log finds them), and the durable
operator trail `~/.entangle/audit.log` (JSON lines, mode 0600), which survives
daemon restarts and exists even when the daemon is down.

**Disabled plugins.** `[plugins] disabled` is enforced: the kernel (the
daemon's and the `--allow-local` one) refuses to load a listed plugin id with
`ENTANGLE-E0759: plugin <id> is disabled ... run `entangle plugins enable <id>``,
before any signature work. A `SemanticEquivalent` metric package is a plugin
too: the daemon refuses to load a listed metric id (`ENTANGLE-E0310` wrapping
`ENTANGLE-E0759`) when a task names it with `--metric-dir`. The daemon
re-reads the list from `config.toml` before every `plugins load` and every
metric load, so the commands below take effect without a restart; an unreadable `config.toml` keeps the previous list (a broken edit
never re-enables a plugin).

```bash
entangle plugins disable <id>   # add to [plugins] disabled (a loaded copy keeps running until `plugins unload`)
entangle plugins enable  <id>   # remove it again
```

Both edit `config.toml` in place, keeping comments and other sections.
`enable` is refused with `ENTANGLE-E0760` when the plugin's tier (read from its
installed manifest under `~/.entangle/plugins/`, or from the tier recorded in
`audit.log` when the lowering disabled it) is above the current
`max_tier_allowed`; raise the ceiling first. A plugin whose tier cannot be
found on disk is enabled, and the load re-checks the ceiling
(`ENTANGLE-E0043`). The daemon does not load plugins at startup, so re-load an
enabled plugin explicitly.

The Wasm runtime is capped at tier 3, so in practice the plugins a lowering to
3 affects are native (tier 4–5) plugins; a lowering to 1 or 2 can also affect
Wasm plugins, stream plugins (§17) among them.

---

## 17. Streaming tasks (`entangle compute stream`)

Spec §7.1. A streaming task runs a `stream-plugin` component (export
`start-stream`, imports `yield-chunk` / `next-chunk`) on **one** executor and
sends its output back chunk by chunk as it is produced — an LLM's tokens, a
log tail. The submitter controls the pace: the executor may run at most
`credit_window` chunks ahead of what the submitter has consumed.

### Serving streams

A daemon with `"iroh"` in `[mesh] transports` serves streams on its
scheduler endpoint: the same `[scheduler] bind` port answers both
`entangle/scheduler/1` (one-shot tasks) and `entangle/stream/1`, so a peer's
one long address covers both. With `mesh.tailscale` running (§10) the
tailnet listener serves both as well, by the same stream server. The gate is the same peer store: only peers
paired with `entangle mesh trust` (and not revoked) may open a stream, and an
unpaired peer is refused before anything it sent is decoded. Load the stream
plugin like any other (`entangle plugins load <dir>`); a one-shot plugin
cannot be streamed, and a stream plugin cannot be `invoke`d. Its declared
capabilities are decided and realised exactly as for a one-shot wasm plugin
(§18): the same `/data`, `/shared` and `/shares/<n>` preopens, socket rules
and pinned `net.wan` names, and `entangle perms list` / `revoke` apply — a
revoked network capability stops a running stream (`ENTANGLE-E0511`).
Unloading a stream plugin, or lowering the tier ceiling below its tier
(§16), waits for its active streams to end before releasing its grants,
exactly as for one-shot invocations; a lowering stops a stream that is
running on a network grant at once, as a revocation would.

Every limit a submitter asks for is clamped by the executor (and reported
back in the `Accepted` frame): stream timeout ≤ 1 h, input ≤ 16 MiB, chunk ≤
4 MiB, total ≤ 256 MiB per direction, credit window ≤ 256, heartbeat between
1 s and 60 s, credit-exhaustion timeout between 1 s and 30 min, at most 64
streams at once.

### Running one

`compute stream` does not go through the daemon: it *is* the submitter. It
dials the executor itself with this node's identity (`~/.entangle/identity.key`,
so the executor's allowlist entry for this node covers it), grants credit as
stdout drains, and verifies every chunk's signature against the key the
transport authenticated for the executor (the QUIC handshake, or the
tailnet's signed key exchange).

It picks the transport exactly as the daemon's dispatcher does (§20), from
the same `config.toml`: `local`, then `tailscale`, then `iroh`, with
`[mesh] preferred` first and a `[mesh.overrides]` entry as the exact list
for that peer; a candidate that fails to connect falls back to the next, and
nothing is retried once the stream's `Open` frame may have reached the peer.
Being its own process, it starts only what that order can use for the peer:

* `local` (`"local"` in `[mesh] transports`): it listens on mDNS for up to
  1.5 s for the peer's LAN sighting (which the peer's daemon announces only
  when it runs both `"local"` and `"iroh"`);
* `tailscale` (`[mesh.tailscale] enabled` and `"tailscale"` listed): one
  `tailscale status` and one discovery round on `[mesh.tailscale] port`
  (at most 8 s: a node that has not answered by then — say one whose port
  accepts and never answers — is skipped, and the answers already in are
  kept), from a client-only tailnet transport whose listener is bound to
  loopback and serves nothing;
* `iroh`: when the peer has a long address — `--peer <key>@host:port` or its
  `[scheduler] peers` entry — whether or not `"iroh"` is listed, as before.

`--peer` may therefore be a bare peer id that only the tailnet or the LAN
knows. With `--json` the final status object names the `transport` that
carried the stream. When nothing can reach the peer the command fails with
the router's `ENTANGLE-E0430` / `E0431` (inside `ENTANGLE-E0363`), followed by
why a wanted transport did not start (e.g. `tailscale status` failed).

```bash
# On a paired peer, by long address or by peer id ([scheduler] peers gives the address):
entangle compute stream <publisher>/stream-lines@0.1.0 --input $'one\ntwo\n' \
  --peer <peer-id> --integrity trusted-executor --allow <peer-id>

# In this process (no network), e.g. to try a plugin:
entangle --allow-local compute stream <plugin-id> --input 'hello' --plugin-dir ./pkg

# One JSON object per chunk (seq, bytes, text/base64, signature status), then a status line:
entangle compute stream <plugin-id> --peer <peer-id> --json
```

`--integrity` accepts only `none` and `trusted-executor` (`--allow <peer-id>`,
repeatable; the executor must be one of them). `deterministic` and
`semantic-equivalent` are refused at submit time with `ENTANGLE-E0350`: there
is one executor and no second stream to compare against. `--partial keep`
(default) prints chunks as they arrive and, if the stream is interrupted,
keeps what arrived; `keep-signed` requires `--json` (the per-chunk signatures
are printed there; plain byte output carries none, so it is refused); `discard` holds all output back until the stream completes and
prints nothing if it does not. The exit status is non-zero for an
interrupted stream either way. Ctrl-C cancels the stream on the executor.

### What closes a stream

| Code | Reason | Meaning |
|---|---|---|
| `E0352` | `bad-chunk-signature` | A chunk did not verify against the executor's key, or arrived replayed / out of order. The stream aborts; the executor loses reputation. |
| `E0353` | `total-bytes-exceeded` | The stream reached `max_total_bytes`. The executor stops itself; a submitter facing one that does not tears the stream down. |
| `E0354` | `chunk-size-exceeded` | One chunk over `max_chunk_bytes`. |
| `E0371` | `total-bytes-exceeded` | More chunks than `max_total_bytes` allows: every chunk counts as at least 128 bytes (with a floor of 1024 chunks), however small it is. |
| `E0356` | `peer-lost` | Three heartbeats in a row went unanswered (15 s at the 5 s default). |
| `E0357` | `submitter-unresponsive` | The executor had no credit for twice the credit-exhaustion timeout. |
| `E0361` | (the peer's reason) | The other end closed the stream and said why. |

A consumer that stops reading stalls the executor: after the
credit-exhaustion timeout (30 min by default) the executor logs a
`StalledEvent` (`RUST_LOG=entangle::scheduler::stream=warn`; the event is
named `StalledEvent` in the log line) and waits as long again before giving
up. Reading again before then resumes the stream.

---

## 18. Plugin capability grants

A plugin's manifest *declares* capabilities; the daemon's capability broker
*grants* them, and only grants have any effect. When a plugin is loaded the
kernel asks the broker to decide every declared capability once (spec §4.5).
Each is granted unless the operator's policy refuses it:

- `[security] max_tier_allowed` below the plugin's tier refuses the whole
  plugin (`ENTANGLE-E0043`, before anything is verified or granted);
- `[security] deny_capabilities` refuses individual capabilities. **The
  plugin still loads, without them**: the denial is audited, counted
  (`entangle_capability_denials_total{reason="operator_policy"}`), logged as
  a warning, and shown by `entangle perms list`. Inside the plugin a denied
  capability behaves exactly like one it never had — no directory, no
  network, `capability.fetch` answers `not-granted` with `ENTANGLE-E0124`.
  This follows §4.5, where the deny decision is made per capability request,
  and lets an operator run a plugin with less than it asked for; plugins are
  expected to degrade gracefully. A native plugin's OS sandbox can only allow
  or forbid IP networking as a whole, so for a native plugin denying either
  `net.lan` or `net.wan` denies both — `deny_capabilities = ["net.wan"]`
  leaves a native plugin no network at all rather than a `net.lan` grant that
  would reach the WAN too.

These load-time grants are what both runtimes build the sandbox from: the
OS-sandbox profile for native plugins (§12), the WASI context for wasm
plugins (below) — one-shot and stream plugins (§17) alike: each stream's
instance is built from the plugin's grants as they stand when the stream
starts, exactly as each one-shot invocation's is. The manifest is never read directly for this. Each
`capability.fetch` a plugin makes at run time is a further broker decision,
audited and counted the same way.

### What a wasm plugin's grants realise

| Grant | In the guest |
|---|---|
| `storage.local { scope = "plugin" }` | `/data` → `~/.entangle/data/plugins/<publisher>/<name>/`, read-write or read-only per `mode` |
| `storage.local { scope = "shared" }` | `/shared` → `~/.entangle/data/shared/` |
| `storage.share.<n>` | `/shares/<n>` → `~/.entangle/data/shares/<n>/` (`rw-scoped`: its `<publisher>/<name>/` subdirectory) |
| `net.lan` | TCP/UDP to RFC 1918, link-local and unique-local IPv6 addresses (not the host's own, not cloud metadata endpoints); no name lookups |
| `net.wan { hosts }` | TCP/UDP to exactly the listed host:port pairs; lookups of the listed names only, answered from the pin |
| anything else (`compute.*`, `custom.*`, …) | nothing in WASI; `capability.fetch` returns a handle |
| no grant at all | no preopened directory, no TCP, no UDP, no DNS |

- **Where plugin data lives.** `~/.entangle/data/plugins/<publisher>/<name>/`,
  shared with native plugins (the same capability names the same directory in
  both runtimes) and keyed by publisher and name — not version, so an upgrade
  keeps its data. The daemon creates every directory `0700` without following
  symbolic links, and re-validates the publisher, name and share name as
  single path components (`ENTANGLE-E0510`). A grant whose directory is a
  symbolic link or not a directory fails the load (`ENTANGLE-E0509`), as does
  a storage grant on a kernel with no data directory (`ENTANGLE-E0508`).
  Inside the guest, wasmtime-wasi (cap-std) confines every path to its
  preopen: absolute paths elsewhere, `..` above it, and symbolic links that
  point out of it — whether the guest or anyone else created them — fail.
  Back up or delete a plugin's data by copying or removing its directory
  while it is not running.
- **Network rules.** The daemon's own host is reachable through no grant:
  neither loopback (`127.0.0.0/8`, `::1`) nor any address assigned to one of
  its interfaces (checked per connection by asking the kernel which source
  address it would use), so a plugin cannot reach the daemon or other local
  services even when they listen on every interface. Cloud instance-metadata
  endpoints — `169.254.169.254` (AWS, GCP, Azure, …), AWS's `169.254.169.253`,
  `169.254.169.123`, `169.254.170.2`, `169.254.170.23` and their
  `fd00:ec2::…` IPv6 forms — are excluded from `net.lan` although the rest of
  link-local space is LAN. Neither are CGNAT, multicast, broadcast,
  documentation or other special-purpose ranges. IPv4-mapped and NAT64 IPv6 forms are judged by the IPv4 address
  they carry. Plugins never listen, and a plugin's UDP socket receives
  only datagrams from addresses its grants let it send to (anything else
  writing to its port is dropped). `net.wan` host names are resolved by the
  daemon when an invocation starts — each distinct name once, all at the
  same time, bounded at 5 s and at half the invocation's timeout (a name
  that does not resolve in time is simply unreachable for that invocation,
  with a warning in the log, instead of the invocation timing out) — and the
  invocation may connect to exactly those addresses. This is
  done at instantiation rather than by checking the guest's own lookups at
  connect time because the socket check only ever sees an address, and the
  guest controls the name-to-address mapping it would present; pinning also
  makes DNS rebinding during an invocation useless. An allowlisted name that
  resolves to a LAN or loopback address is not reachable through `net.wan`.
  Wildcard `net.wan` entries are tier 4 and therefore never reach a wasm
  plugin (wasm is tier 1–3). The guest's own name lookups never reach the
  daemon's resolver: an allowlisted `net.wan` name resolves to exactly the
  addresses pinned for the invocation (so a round-robin or short-TTL name is
  still reachable), an IP literal to itself, and every other name — under
  any grant, `net.lan` included — does not resolve. A plugin therefore
  cannot use lookups of names like `<data>.attacker.example` to send data to
  outside name servers. Without a `net.*` grant nothing resolves.
- **Resource limits** (fuel/epoch deadline, memory) are unchanged by grants.

### Inspecting and revoking grants

```console
$ entangle perms list
aabbccddeeff00112233445566778899/fetcher@0.3.1 (tier 3)
  net.wan [hosts=api.example.com:443]              denied: operator policy (deny_capabilities = "net.wan")
  storage.local [scope=plugin mode=rw]             granted (grant 7)

$ entangle perms revoke aabbccddeeff00112233445566778899/fetcher@0.3.1 storage.local
storage.local revoked from aabbccddeeff00112233445566778899/fetcher@0.3.1; withdrew grant(s) 7
Not persistent: the plugin gets this capability back when it is unloaded and
loaded again or when the daemon restarts. To keep a capability away for good,
add it to [security] deny_capabilities.
```

`entangle perms list [<plugin>] --json` prints the `perms/list` RPC result:
per plugin, its effective tier and every declared capability with its
parameters, `state` (`granted` with the outstanding `grant_ids` — the load-time
grant plus any handle a running invocation holds; `denied` with the `reason`;
`revoked`; `not-granted`). Both commands need the daemon.

A revocation takes effect at once for `capability.fetch` (`revoked`,
`ENTANGLE-E0125`) and for a wasm plugin's network access: new sockets and
name lookups re-confirm that the grant behind them is still live, and an
invocation (or stream) running with a `net.lan` / `net.wan` grant that is
revoked is stopped (`ENTANGLE-E0511`, within about 50 ms), which closes every
connection it had open — an established connection never outlives the
grant. Storage is revoked from the next invocation (an invocation already
running keeps its open directory until it ends). A native plugin's OS-sandbox profile is fixed when
it loads, so a native plugin with a revoked capability is refused outright
(`ENTANGLE-E0125`) from its next invocation. Lowering `max_tier_allowed`
below a loaded plugin's tier (§16) has the same effect on all of its grants
at once while it drains — the per-grant tier check (`ENTANGLE-E0127`)
always reads the ceiling in force — and its unload then releases them. A
revocation is held in the daemon's memory: it lasts until the plugin is unloaded and loaded again or
the daemon restarts; to keep a capability away from every
plugin, use `deny_capabilities` instead.

Every grant, denial, release and revocation is recorded in the broker's
audit log with the plugin, the capability and its parameters, the reason and
the time.

---

## 19. Reproducible packages, release verification and governance checks

### 18.1 Building and verifying a reproducible package

`entangle plugins build <dir>` writes, next to `plugin.wasm`, `entangle.toml`,
`plugin.wasm.sig` and `provenance.json`, a deterministic archive
`<dir>/dist/<name>-<version>.tar.zst` and prints its SHA-256. Two builds of the same
source produce the same bytes: absolute paths are remapped out of the wasm
(`--remap-path-prefix` for the project, path dependencies, the cargo target directory,
`$CARGO_HOME`, `$RUSTUP_HOME`, the sysroot), the signature timestamp is `SOURCE_DATE_EPOCH` (default
2024-01-01T00:00:00Z), the tar is normalised and zstd uses fixed parameters.

* The project **must** have a committed `Cargo.lock`; otherwise the build stops with
  `ENTANGLE-E0830: Cargo.lock missing` before fetching or writing anything. `plugins new`
  generates one (skip with `--no-lockfile`). Builds run `cargo build --locked`.
* Flags from `CARGO_ENCODED_RUSTFLAGS` or `RUSTFLAGS` in the environment are kept and
  recorded; the build passes them, with the remap flags, as `CARGO_ENCODED_RUSTFLAGS`
  (so paths with spaces work), which replaces any `build.rustflags` in `.cargo/config.toml`.
* `entangle plugins verify --rebuild <package|dist-dir> [--source <dir>]` rebuilds in a
  scratch target dir, with the recorded `SOURCE_DATE_EPOCH`, and compares source digest,
  toolchain, flags, manifest, wasm and the signature bundle's hashes and `created_at`,
  then checks the publisher signature against the keyring (`--keyring`, default
  `~/.entangle/keyring.toml`; an untrusted publisher is a failure). It prints `PASS`
  (exit 0) or `FAIL: <first difference>` (non-zero). Without `--rebuild` it only checks
  the publisher signature.
* Cross-host reproducibility (macOS-14, Ubuntu-22.04, Ubuntu-24.04) is checked only in CI:
  `.github/workflows/reproducibility.yml` (signing with the public test key
  `tests/fixtures/repro-ci-key.pem`).

### 18.2 Verifying a release

```text
entangle release key add <release-public-key-hex> --name release-2026   # release keyring
entangle release verify entanglement-v1.0.0-<target>.tar.gz          # tag read from the file name
entangle release verify download.tar.gz --tag v1.0.0               # or given explicitly
```

Needs `<artifact>.ed25519` (from `entangle release sign`) and the cosign bundle
`<artifact>.sigstore`, and verifies both; either failing fails the command. The release
keyring is `~/.entangle/release-keyring.toml`, separate from the publisher keyring
(`--release-key <hex>` trusts a single key instead). `cosign` must be on `PATH` (or
`--cosign <path>`); if it is missing the command fails with `ENTANGLE-E0845`.
The cosign certificate identity is pinned to **one release**: the release workflow of this
repository run on exactly `refs/tags/<tag>`, with `<tag>` from `--tag vX.Y.Z` or, when
omitted, from an `entanglement-<tag>-<target>.tar.gz` file name. If neither is available the
command refuses (`ENTANGLE-E0847`); a `--tag` that is not a `vX.Y.Z[-pre]` tag is refused
the same way, and one that contradicts a release-style file name is refused
(`ENTANGLE-E0848`). This is what stops a rollback: an older release (valid signatures and
all) renamed to a newer version was minted by the older tag's run and fails the newer
tag's identity (`ENTANGLE-E0846`). The identity is anchored and the tag's dots escaped, so
no other tag, branch, pull-request or dispatch run, workflow or repository matches.
`--certificate-identity-regexp` replaces the pinning outright (for forks with their own
release workflow; it excludes `--tag`), and `--certificate-oidc-issuer` defaults to GitHub
Actions. `.github/workflows/release.yml` signs only tag runs. The key ceremony (2-of-3 Shamir split with
`entangle release key split|combine`) is in `docs/governance/key-ceremony.md`.

### 18.3 Governance checks

`cargo xtask bus-factor` fails when any role in `docs/maintainers/roles.toml` has fewer than
two active holders (a merge authored in the last 60 days); the weekly workflow runs it and
opens the P0 issue. `cargo xtask rotation-note-check` fails when the newest
`## YYYY-MM-DD` note in `docs/governance/rotations.md` is older than 35 days; the release
workflow runs it first (`rotation_note_fresh`).

---

## 20. Transport selection (`local`, `tailscale`, `iroh`)

Spec §6.1. A daemon can reach a peer over up to three transports at once,
and picks one **per request** (and per stream) from what it currently knows
about that peer.

### Where the candidates come from

| Transport | Running when | Candidate for a peer when |
|---|---|---|
| `local` | `"local"` **and** `"iroh"` in `[mesh] transports` | its mDNS sighting advertises its key and mesh port (a daemon advertises them only when it runs both `"local"` and `"iroh"`; with `"iroh"` alone it does not announce on the LAN, so it is never a `local` candidate) and it is trusted in `peers.toml`. Dialled over the iroh endpoint to the LAN addresses only. |
| `tailscale` | §10 (`[mesh.tailscale] enabled = true` and `"tailscale"` in `transports`) | the last discovery round found it on the tailnet **and** the tailnet is `active`. |
| `iroh` | `"iroh"` in `transports` | its long address is in `[scheduler] peers` and it is trusted. |

Every connection authenticates the peer's `PeerId` and pins it to the key
the candidate names (the QUIC handshake, or the tailnet's signed key
exchange), so a stale or spoofed address can only fail to connect, never
reach someone else.

### The order

1. A peer with a `[mesh.overrides]` entry: exactly the transports listed
   there, in that order. One transport forces it; nothing outside the list
   is ever tried for that peer.
2. Otherwise `local`, then `tailscale`, then `iroh` (cheapest first), with
   `[mesh] preferred` moved to the front if set.

```toml
[mesh]
transports = ["local", "tailscale", "iroh"]
preferred = "tailscale"            # first for every peer without an override

[mesh.overrides]                   # keys: the peer id (`entangle mesh peers`)
"7a21c0de7a21c0de7a21c0de7a21c0de" = "iroh"                  # only iroh
"0b5e55ed0b5e55ed0b5e55ed0b5e55ed" = ["tailscale", "iroh"]   # these, in order
```

Both keys are validated when the file is loaded: an unknown transport name
is `ENTANGLE-E0434`, a bad peer id, an empty list or a repeated transport
`ENTANGLE-E0435`, and the daemon does not start. Naming a transport that is
not running is accepted (it may be enabled later) and logged at startup;
until then it simply has no candidates.

### Fallback, and what is never retried

The router tries the candidates in order. It moves on to the next one only
when **connecting** fails: dial refused or timed out, handshake or identity
failure, the peer's ACL refusing us on the tailnet, or the peer not serving
the protocol. Nothing was delivered in those cases.

A candidate with a fallback after it must connect within 5 s, or within an
even share of what is left of the request's budget when that is shorter
(e.g. a 2 s task with the 10 s overhead and three candidates: 4 s for the
first). A dial that has not connected by then — a LAN sighting left behind
when the peer moved, a spoofed one, a blackholed port — is abandoned
(nothing was sent) and the next candidate tried, so it cannot use up the
budget before the later transports get a turn. If those fail too, a
candidate it cut short (slow, not refused — e.g. a relayed iroh dial) is
tried once more without a deadline. The last candidate is bound only by its
transport's own timeouts and the request's budget. The deadline covers
connection setup only: a request already sent runs to its end.

A transport that failed to connect to a peer (refused, unreachable, or out
of its deadline) is then tried **after** that peer's other candidates for
30 s, so a dead route is not waited on by every request; `entangle diag
mesh` shows it at the end of the `route:` order meanwhile. It is demoted,
not dropped: it is still tried when the others fail, and the first success
over it restores its place. `--probe` attempts neither demote a transport
nor skip a demoted one.

Everything after the connection is up is final:

* an answer from the peer — success, or a refusal such as `not-authorized`
  or `plugin-not-loaded` — is the result, never resent elsewhere;
* a transport failure once the request may have reached the peer (a reset
  mid-response, a response timeout, an over-cap frame) fails the dispatch
  with `ENTANGLE-E0432` / `E0433` rather than risking a second execution.

When no candidate exists the dispatch fails at once with `ENTANGLE-E0430`
(naming, per transport, why it had none); when every candidate failed to
connect, with `ENTANGLE-E0431` (naming each attempt). Both arrive inside
`ENTANGLE-E0402` (`compute/dispatch`) or `ENTANGLE-E0363` (streams).

`entangle compute stream` builds its router with the same code from the
same settings (§17), so a stream it opens follows these rules too.

The transport that carried the last successful request or stream to a peer
is recorded (in memory, per peer), logged at info when it changes
(`mesh: transport chosen for peer`), shown in `entangle diag mesh` (§14c) and
used as the `transport` label of `entangle_remote_dispatch_total` and
`entangle_remote_stream_opens_total` (§14a).

### Serving

Inbound, both transports serve the same thing — one task server and one
stream server behind `peers.toml` — so a peer may reach this node over
whichever transport it picks. The serving side's `transport` label is the
transport that carried the frame (`iroh` covers LAN dialling).

During a rolling upgrade, a node from before protocol selection that probes
the tailnet path (`entangle diag mesh --probe` sends a plain ping) gets a
fixed answer and still reports the path reachable; nothing it sends reaches
the task or stream server.

### Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `ENTANGLE-E0430 ... tailscale: tailnet stopped (NeedsLogin)` | The tailnet is down and the peer is known only there. `tailscale up`, or give it a `[scheduler] peers` address. |
| `... tailscale: not a tailnet discovery candidate` | The peer is not online in the tailnet, does not run `entangled` with `mesh.tailscale`, or uses another `[mesh.tailscale] port`. Discovery runs every 60 s; `entangle diag mesh` shows the candidate count. |
| `... local: no mDNS sighting with a dialable address` | The peer is not on the LAN, mDNS is blocked, or it runs without `"iroh"` (nothing to dial). |
| `... iroh: not in the address book ([scheduler] peers)` | Add the peer's long address under `[scheduler] peers` (it must also be trusted). |
| `ENTANGLE-E0431 ... tailscale: ... rejected us (we are not in its allowlist)` | The peer runs `entangle-on-top` and has not trusted this node: pair the two (`entangle pair`) or `entangle mesh trust` this node on the peer. |
| `... does not serve entangle/scheduler/1 over mesh.tailscale` | The peer's tailnet listener predates this release (it answered without protocol selection). Upgrade it; until then the router falls back to the next transport. |
| Traffic uses a slower transport than expected | Check the `route:` line in `entangle diag mesh` (order, skips, last used) and `[mesh] preferred` / `[mesh.overrides]`. A connect failure on the first candidate (e.g. a stale tailnet address) silently falls back; `RUST_LOG=entangle_scheduler=debug` logs each failed attempt. |
| `ENTANGLE-E0432` | The connection broke after the request was sent; the task may or may not have run on the peer, so it was not retried. Re-submit if the task is idempotent. |

---

## 21. Fault isolation and restarts

A bug in the daemon's own code must not leave a half-working daemon behind
(spec §2.1). `entangled` therefore turns every **core fault** into a clean
process exit with a distinct status, and lets the service manager restart it:

| Exit status | Meaning |
|---|---|
| `0` | Clean stop (SIGTERM / SIGINT). Not restarted by `Restart=on-failure` or the launchd plist. |
| `1` | Startup error: bad `config.toml`, unreadable keyring or identity, the multi-node peer check (§5), an unusable `[metrics]` section. Restarted, and fails again until fixed. |
| `70` | **Core fault** (`EX_SOFTWARE`): a panic outside a contained plugin call, or a supervised core task that ended while the daemon was running. Restarted. |

Before exiting with 70 the daemon writes **one** structured error line at
target `entangle::telemetry` with `code = "ENTANGLE-E0787"`, `exit_code`,
and either the panic's `location`, `thread` and message (`panic`), or the
`task` that ended:

```json
{"level":"ERROR","target":"entangle::telemetry","fields":{"code":"ENTANGLE-E0787","contained":false,"exit_code":70,"location":"crates/entangle-bin/src/maintenance.rs:113:9","thread":"tokio-rt-worker","panic":"...","message":"ENTANGLE-E0787: panic in core code; exiting so the service manager restarts the daemon"}}
```

**Which paths exit and which contain.**

| Where the panic happens | Outcome |
|---|---|
| RPC server (accept loop, request handling), maintenance loop, scheduler task and stream servers (`mesh.iroh`, `mesh.tailscale`), mDNS discovery, metrics endpoint, plugin load / unload / reload, any other daemon thread | Exit 70 (`ENTANGLE-E0787`). |
| Capability broker: granting or releasing a capability (`Broker::grant`, `grant_by_key`, `release`), even when reached from a plugin's `capability.fetch` inside a plugin call | Exit 70. These are critical sections: unwinding halfway could leave the grant table inconsistent, so they are never contained. |
| Host code reached from inside one plugin call — a wasm one-shot `run` or `start-stream` (instantiation, guest code, the host imports it calls on the polling thread), or a native plugin's supervised invocation — started through `Kernel::invoke` / `invoke_stream` (`plugins/invoke`, `compute/dispatch`, `compute stream`, work served to mesh peers) | **Contained**: logged once at `entangle::telemetry` with `code = "ENTANGLE-E0788"`, `contained = true`; that call fails with `ENTANGLE-E0788`; its store and instance are discarded; the plugin stays loaded; the daemon keeps serving. |
| Host work a plugin call hands to another thread (WASI filesystem operations run on tokio's blocking pool) or spawns as its own task | Exit 70: the containment marker is per thread and per poll. |
| Metric components run by the submitter's verifier (`SemanticEquivalent`) | Exit 70 (not a `Kernel::invoke` call). |
| Wasm traps, timeouts, resource-limit hits, a plugin returning an error | Not panics: the call returns its error as before. |

**Supervised core tasks.** The RPC server, the maintenance loop and the
`mesh.iroh` task and stream servers run under a supervisor: if one returns
(for example, the RPC socket cannot be bound) while the daemon is running, the
daemon logs `ENTANGLE-E0787` with the task's name and exits 70. The
`mesh.tailscale` accept loops are covered by the panic hook only.

**The tradeoff (spec §2.1).** A core fault restarts the whole daemon: calls
and streams in flight on this node are lost (their callers see the
connection close and may retry), mesh peers see this node disappear and
re-appear, and plugins come back as described in §22. State on disk —
identity, keyring, peers, plugin data, the AOT cache — is untouched. The
daemon is one process by design; this is the price of that simplicity.

**Fault injection (debug builds only).** Tests arm named fault points with
`ENTANGLE_FAULT_INJECT=<point>[,<point>…]`: `maintenance` (panic in the
maintenance loop), `maintenance-return` (it returns early), `rpc` (panic
handling a request), `broker` (panic in `grant_by_key`), `host-call` (panic in
the `host-info` import). The hook exists only when `debug_assertions` are on;
in a release build the variable has no effect.

---

## 23. AOT compilation cache

Compiling a wasm component with Cranelift is the slow part of loading a
plugin. The daemon keeps each compiled component in `~/.entangle/aot`
(`[runtime] aot_cache = true`, the default), so loading the same package
again — after an unload, a hot reload back, or a daemon restart — skips
compilation.

**Key.** An entry is keyed by BLAKE3 of the component bytes, the Wasmtime
version, Wasmtime's engine compatibility hash (target triple, compiler flags,
tunables, enabled wasm features — everything about the engine configuration
that affects code generation) and the host architecture/OS. A new daemon
build with another Wasmtime version or engine configuration simply misses and
recompiles; GC removes the old entries later.

**Trust.** Loading a compiled artifact skips Wasmtime's validation, so the
daemon only loads entries it wrote itself:

- the directory must be owned by the daemon's user with mode `0700`, and the
  per-node key `cache.key` (32 random bytes) must be a `0600` regular file;
  otherwise the cache is not used at all and the daemon logs
  `ENTANGLE-E0786` and compiles everything (fix with `chmod 700
  ~/.entangle/aot && chmod 600 ~/.entangle/aot/cache.key`, or delete the
  directory);
- every entry has a sidecar `<key>.meta` with a keyed BLAKE3 MAC over its
  header and the artifact bytes under `cache.key`; the artifact is read into
  memory, checked, and only then handed to Wasmtime;
- an entry that is a symbolic link, has group/other bits or another owner, a
  malformed sidecar, another Wasmtime version, a MAC that does not verify, or
  that Wasmtime refuses is **deleted**, logged (`ENTANGLE-E0785`, with the
  reason), counted in `entangle_aot_cache_rejections_total{reason}` and the
  component compiled as if there were no cache. A bad entry never fails a
  load.

**GC.** The maintenance loop (at startup and every hour) removes entries not
used for `aot_cache_max_unused_days` (default 30; a hit refreshes an entry's
last use), then the least recently used entries until the cache is under
`aot_cache_max_mb` (default 512 MiB), and partial writes older than an hour.
Deleting `~/.entangle/aot` while the daemon is stopped is always safe; the
next start creates a new key and cache.

Metrics: `entangle_aot_cache_hits_total`, `..._misses_total`,
`..._rejections_total{reason}`, `..._evictions_total{reason}`,
`entangle_aot_cache_bytes` (§14a).

