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

[security]
max_tier_allowed = 5       # default: 5 (Tier::Native — most permissive)
```

| Section | Key | Type | Default | Meaning |
|---|---|---|---|---|
| `[runtime]` | `bus_capacity` | usize | `1024` | Buffered-envelope capacity of the daemon's lifecycle event bus. Daemon-only tuning knob; not written by the CLI. |
| `[mesh]` | `transports` | array of strings | `[]` | Active mesh transport backends. Phase 1 supports only `"local"` (mDNS on `_entangle._udp.local`). Listing `"iroh"`/`"tailscale"` here does not activate them — those crates are Phase-2 scaffolds. |
| `[mesh]` | `multi_node` | bool | `false` | When `true`, the daemon requires at least one trusted peer in `peers.toml` **before it will start**. See §5 for the exact failure. |
| `[security]` | `max_tier_allowed` | integer 1–5 | `5` | Ceiling on the plugin tier the daemon will load (`Tier::Native` = 5 down to `Tier::Pure` = 1). A load above the ceiling is refused with `ENTANGLE-E0043`. Out-of-range values (`0` or `>5`) fail to parse. |

Notes:

- The `[mesh]` and `[security]` sections are **field-for-field shared** with
  the CLI's own config schema (`crates/entangle-cli/src/config.rs`), which is
  what actually writes the file (via `entangle init` or `entangle mesh
  trust`/`untrust`). A round-trip test in `entangle-bin` pins this
  compatibility so the two schemas cannot silently drift.
  - One asymmetry to know about: the CLI stores `max_tier_allowed` as a bare
    `u8` (default `5`), while the daemon deserializes it into the `Tier` enum,
    which gets range validation for free — the wire representation (an
    integer 1–5) is identical either way.
- `[runtime]` is daemon-only; the CLI never writes it. Two keys that *used to*
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

`entangle doctor` (see §4) is the fastest way to audit all of the above at
once — its `identity-perms` and `dir-perms` checks specifically flag mode
deviations and suggest the `chmod` to fix them.

---

## 4. Checking health

Two independent tools answer "is it working," at different levels:

### `entangle doctor` — structured pre-flight / ongoing diagnostics

Runs 13 checks and prints one `[ok] / [warn] / [fail] / [skip]` line each,
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
11. `OS sandbox` — availability of Seatbelt/Landlock/Bubblewrap for tier-5 plugin isolation (probe only in Phase 1 — no enforcement yet).
12. `disk-space` — warns below 1 GiB free on the filesystem hosting `~/.entangle` (or `/tmp` if that dir doesn't exist yet).
13. `clock-skew` — compares the daemon's clock to the local clock via a `time` RPC; `warn` above 2s drift, **`fail`** above 30s (biscuit-auth tokens have only ±60s allowance, so severe drift breaks cross-node auth and pairing TOFU).

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
| E0200–E0201 | Manifest / plugin id validation |
| E0300–E0301 | Task execution (output-size limit, timeout) |
| E0302–E0305 | Integrity policy enforcement (`entangle-runtime`) |
| E0500–E0506 | Wasm host errors (`entangle-host`) |
| E0600–E0699 | Agent-host adapter (`entangle-agent-host`) |
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
| `ENTANGLE-E0420`–`E0424` | Bridge (cross-node relay) biscuit attenuation violations — missing fact, TTL/rate/byte-cap ceiling exceeded, or destination-pin mismatch. |
| `ENTANGLE-E0620`, `E0630`, `E0640`, `E0650` | `NotImplemented` stubs for the MCP gateway, `mesh.iroh`, `mesh.tailscale`, and OpenTelemetry export respectively — all Phase 2+. |

If you hit a code not listed above, the fastest way to find its exact meaning
and the crate that owns it is:

```bash
grep -rn "ENTANGLE-E<code>" crates/*/src/
```

---

## 7. Backup / restore of `identity.key`

`identity.key` is the node's Ed25519 private key. **The daemon's `peer_id` —
and every existing pairing — is derived from its public key.** There is no
recovery path for a lost key:

> **WARNING:** losing `identity.key` (or overwriting it without a backup)
> permanently breaks every existing pairing. Every peer that trusted this
> node's old public key will reject the new one; you must re-pair from
> scratch on every peer with `entangle pair`.

### Backup

There is no dedicated `entangle backup` command in Phase 1 — back it up like
any other secret file:

```bash
cp ~/.entangle/identity.key /secure/offline/location/identity.key.bak
chmod 600 /secure/offline/location/identity.key.bak
```

After backing it up, touch the sentinel the built-in maintenance loop checks
for, so it stops nagging in the logs:

```bash
touch ~/.entangle/.identity_backed_up
```

(`crates/entangle-bin/src/maintenance.rs`'s `warn_backup` check emits a
`maintenance: identity has no backup sentinel …` warning on every tick while
that sentinel file is absent. It does not track *how stale* your backup is —
only whether one was ever acknowledged — so re-touch it after any deliberate
key rotation, but there's no automated re-check on a schedule.)

The maintenance loop also warns (does not fail) once the key is older than
`key_rotation_warn_days` (default 365 days), as a rotation reminder.

### Restore

Stop the daemon, place the backed-up PEM at `~/.entangle/identity.key` with
mode `0600`, and restart:

```bash
systemctl stop entangled          # or: docker stop entangled
cp /secure/offline/location/identity.key.bak ~/.entangle/identity.key
chmod 600 ~/.entangle/identity.key
systemctl start entangled         # or: docker start entangled
```

`entangle init` also supports importing a PEM interactively (option `i` in
the wizard, or non-interactively by pre-placing the file): if an identity
already exists and differs from the one being imported, it requires explicit
confirmation, takes an automatic `identity.key.bak-<unix_ts>` copy (mode
`0600`) of the *old* key before overwriting, and offers to clear
`peers.toml` (since the old pairings are now stale against the new key).
Importing a byte-identical key is a no-op.

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
| `entangle`/`entangled` fail identity checks with "PEM parse failed" / corrupt key | `identity.key` truncated, corrupted, or edited by hand | Restore from backup (§7); if none exists, `entangle init` can generate a fresh identity — but every existing pairing must be redone via `entangle pair`. |
| `entangle doctor`'s `identity-perms` or `dir-perms` check warns | File/dir permissions loosened outside the tool (e.g. by a backup/restore process, or an `umask` override) | `chmod 600 ~/.entangle/identity.key` / `chmod 700 ~/.entangle` as suggested in the check's own output. |
| `entangled status` fails / hangs | Daemon not running, socket path mismatch, or daemon wedged | Check `systemctl status entangled` / `docker ps`; confirm the socket path matches (`--socket` override vs. default `$HOME/.entangle/sock`); check logs for the last activity before it stopped responding. |
| Plugin load refused with `ENTANGLE-E0043` | Plugin's declared tier exceeds `[security] max_tier_allowed` in `config.toml` | Either raise `max_tier_allowed` (understand the tier's capability implications first — see spec §4.2) or use a lower-tier plugin build. |
| Cross-node capability grant refused with `ENTANGLE-E0100`/`E0101` | Biscuit signature doesn't verify, or the publisher/peer key isn't in the trust roots | Re-check the peer is actually paired (`entangle mesh peers`) and its key matches what's in `peers.toml`/`keyring.toml`. |
| `clock-skew` check in `entangle doctor` reports `fail` | Local and daemon-host clocks have drifted >30s | Sync via NTP/chrony. Biscuit-auth tokens only tolerate ±60s, so severe drift breaks pairing TOFU and cross-node auth outright. |
| mDNS peer discovery doesn't work under Docker on macOS | Docker Desktop's `network_mode: host` is scoped to its internal Linux VM, not the Mac's real network | Use a Linux host/VM for mDNS-dependent testing, or run `entangled` natively on macOS for local dev. See [`../docker/README.md`](../docker/README.md). |
