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
error. The runtime validates the same file for daemon and local execution.

```toml
[runtime]
bus_capacity = 1024        # default 1024

[mesh]
transports = ["local", "iroh"]  # written by entangle init
multi_node = false         # default: false

[security]
max_tier_allowed = 5       # default: 5 (Tier::Native — most permissive)
```

| Section | Key | Type | Default | Meaning |
|---|---|---|---|---|
| `[runtime]` | `metrics_bind` | socket address | disabled | Local Prometheus HTTP endpoint, for example `127.0.0.1:9898`. Requires a loopback IP. |
| `[runtime]` | `bus_capacity` | usize | `1024` | Buffered-envelope capacity of the daemon's lifecycle event bus. Daemon-only tuning knob; not written by the CLI. |
| `[runtime]` | `plugins` | array of strings | `[]` | Absolute paths to signed plugin package directories to load at startup. |
| `[mesh]` | `transports` | array of strings | `[]` | `local` enables LAN mDNS, `iroh` enables configured QUIC routes, and `tailscale` enables routes discovered through the local Tailscale client. Select both `local` and `iroh` for automatic routes to paired LAN workers. |
| `[scheduler]` | `bind` | socket address | `0.0.0.0:0` | Scheduler UDP listener. LAN discovery advertises the assigned port, including when `:0` selects it. Static and tailnet routes require a known worker port. |
| `[scheduler]` | `peers` | array of strings | `[]` | Static Iroh worker addresses in `<public-key-hex>@<ip>:<port>` form. Paired workers discovered on the LAN can use an empty list. |
| `[scheduler]` | `tailnet_peers` | array of tables | `[]` | Stable Tailscale node ID, Entanglement public key and scheduler port for each worker. |
| `[scheduler]` | `relay` | bool | `true` | Allow Iroh relay fallback when the `iroh` transport is enabled. |
| `[mesh]` | `multi_node` | bool | `false` | When `true`, the daemon requires at least one trusted peer in `peers.toml` **before it will start**. See §5 for the exact failure. |
| `[security]` | `max_tier_allowed` | integer 1–5 | `5` | Ceiling on the plugin tier the daemon will load (`Tier::Native` = 5 down to `Tier::Pure` = 1). A load above the ceiling is refused with `ENTANGLE-E0043`. Out-of-range values (`0` or `>5`) fail to parse. |

The daemon and CLI read the same configuration schema. Both validate `max_tier_allowed` as an integer from 1 through 5. Installing a plugin checks the tier ceiling before building or trusting the publisher. The temporary worker used by `--allow-local` also applies the ceiling when loading a signed package. Build-only installations (`--no-load`) can prepare components for a different device.

`entangle init` enables LAN discovery and QUIC scheduling, with `[scheduler] relay = false` for this LAN configuration. It preserves existing configuration files. Set `multi_node` under `[mesh]` and `max_tier_allowed` under `[security]`. Older configurations that place these keys under `[runtime]` produce a configuration error. [Configuration schema](../crates/entangle-runtime/src/config.rs)

The daemon reads `~/.entangle/config.toml` and requires a resolvable home directory. Section 3 describes path resolution for the config and socket.

---

### Running a worker on the LAN

Pair the Entanglement identities on the two hosts with `entangle pair` and verify their fingerprints. Merge these settings into `~/.entangle/config.toml` on both hosts, then restart both daemons.

```toml
[mesh]
transports = ["local", "iroh"]
multi_node = true

[scheduler]
bind = "0.0.0.0:0"
relay = false
```

The daemons advertise their assigned UDP ports over multicast DNS. Both hosts need multicast DNS on the same link and must be able to reach each other's scheduler UDP ports. If the firewall requires a fixed port, set `bind` to an address such as `0.0.0.0:7443` and allow that port. On an IPv6 LAN, `[::]:7443` supports global and unique-local addresses.

Load a signed plugin on the worker. On the coordinator, `entangle mesh peers` shows sightings. Within a polling cycle, the coordinator checks a paired worker's identity over QUIC and retrieves its hardware and loaded plugin versions. To run the JSON Pointer plugin on a specific worker, use its paired ID and the publisher shown by `entangle plugins list` on that worker.

```sh
entangle compute dispatch '<publisher>/json-pointer@0.1.0' \
  --input '{"pointer":"/job/id","data":{"job":{"id":42}}}' \
  --cpu-cores 0.25 --integrity trusted-executor --allow '<worker-entanglement-peer-id>'
```

The result includes the chosen worker's peer ID. LAN routes follow mDNS changes and expire with the service record. Static Iroh routes and tailnet mappings keep their own lifetimes.

From a source checkout on a Linux host with multicast enabled, run the two-daemon check to verify this setup, including signed plugin execution and live revocation.

```sh
cargo test --locked -p entangle-bin --test daemon_compute -- --ignored --exact discovers_and_runs_work_without_a_configured_peer_address
```

### Monitoring work

Run `entangle metrics` as the daemon user to read Prometheus text over the control socket. For an HTTP scraper, set `metrics_bind = "127.0.0.1:9898"` under `[runtime]`, restart the daemon and scrape `GET /metrics`. The listener is accessible to other processes on the same host. Leave it disabled on a shared host when only the daemon owner should read metrics.

| Series | Meaning |
|---|---|
| `entangle_daemon_up` | The responding daemon is serving requests. |
| `entangle_plugins_loaded` | Components currently loaded on this worker. |
| `entangle_wasm_invocation_seconds` | Histogram of completed invocations on this worker, labeled `ok` or `error`. Includes jobs received from peers. |
| `entangle_compute_dispatch_seconds` | Histogram of requests submitted to this daemon's scheduler, labeled `local`, `remote` or `error`. Parameter validation occurs before timing begins. |

For a binary result such as a resized image, use `entangle compute dispatch <plugin-id> --input-file request.bin --output-file result.png`. Use `--raw` to pipe the result bytes to another program. Both modes print the selected worker to standard error.

Histogram counts and sums start at daemon startup. The first observation creates each labeled series.

### Restoring plugins on a worker

Keep each signed package in a stable directory readable by the daemon user. Add
its publisher's public key to that user's keyring, then list the absolute
package directory in `~/.entangle/config.toml`.

```toml
[runtime]
plugins = ["/var/lib/entangle/plugins/json-pointer"]
```

On restart, the daemon verifies and loads these packages before serving requests
or advertising plugin availability. An invalid package or duplicate plugin ID
fails startup with the package path and error. The default empty list leaves
plugin loading to `entangle plugins load` or `entangle plugins install`.
Remove an entry to keep its package unloaded on future restarts.

### Running a worker on a tailnet

1. Connect both hosts to your tailnet using the host Tailscale client. Each daemon needs a local tailnet interface and permission to run `tailscale status --json`. Allow the worker's scheduler UDP port in your tailnet policy.
2. Pair the Entanglement identities and verify their fingerprints using `entangle pair`. On the coordinator, `entangle mesh tailnet --json` lists visible Tailscale nodes with their stable `node_id`. Find the worker's paired Entanglement `public_key_hex` in `~/.entangle/peers.toml`. These two identifiers come from independent systems.
3. On **both** hosts, add the following settings to `~/.entangle/config.toml`. Merge them with any existing sections. A Tailscale-only scheduler resolves the wildcard to the host's tailnet interface and disables Iroh relays.

```toml
[mesh]
transports = ["tailscale"]

[scheduler]
bind = "0.0.0.0:7443"
```

4. On the **coordinator**, add one mapping for each worker. Replace both placeholders with the identifiers from step 2. Add the reverse mapping if the worker should also send jobs back.

```toml
[[scheduler.tailnet_peers]]
node_id = "<worker-stable-tailscale-node-id>"
public_key = "<worker-64-digit-entanglement-public-key>"
port = 7443
```

5. Configure the worker's signed plugin package as shown above and restart both Entanglement daemons. Check `entangle mesh status` for `tailscale` on each and allow a capability polling cycle. On the coordinator, the following command restricts execution to the paired worker and prints the chosen peer and result.

```sh
entangle compute dispatch '<publisher>/json-pointer@0.1.0' \
  --input '{"pointer":"/job/id","data":{"job":{"id":42}}}' \
  --cpu-cores 0.25 --integrity trusted-executor --allow '<worker-entanglement-peer-id>'
```

The daemon refreshes tailnet address hints every 30 seconds and polls configured workers for hardware and loaded plugin versions every 15 seconds. Each scheduler connection authenticates the worker's Entanglement key. Both sides consult the persisted trust store when authorizing work. A mapping can remain in the configuration after revocation.

The default address family is IPv4. Use `[::]:7443` on hosts using Tailscale IPv6. If Tailscale was offline when a Tailscale-only daemon started, or its local bound IP changed, restart Entanglement after the interface is ready. In mixed `["iroh", "tailscale"]` mode the ordinary Iroh listener and relay policy apply. Linux and macOS host deployments can use this mode with a working Tailscale interface. Userspace-only SOCKS deployments and MagicDNS service publication are outside this implementation.

Run the two-device acceptance check to verify the selected peer and plugin output over a live tailnet. [Tailnet compute test](testing/tailnet-compute.md)

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

### Reproduce the catalog and cross-node smoke test

From a checkout with Rust 1.91, Python 3.11+, and OpenSSL installed:

```bash
rustup target add wasm32-wasip2
cargo build --locked -p entangle-cli -p entangle-bin
python3 -m venv target/catalog-smoke-python
target/catalog-smoke-python/bin/pip install Pillow==12.2.0 zxing-cpp==2.3.0
target/catalog-smoke-python/bin/python plugins/smoke_test.py \
  target/debug/entangle target/debug/entangled --two-node
```

The test builds and signs all seven plugins in temporary profiles, verifies
their output on a local daemon, then repeats the workloads through an empty
coordinator and a trusted worker over loopback QUIC. Omit `--two-node` to run
only the local phase.

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
| E0500–E0507 | Wasm host errors (`entangle-host`) |
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
| `ENTANGLE-E0400` | Strict remote placement selected a remote worker without a configured transport. |
| `ENTANGLE-E0401` | Task input exceeds the dispatcher's configured `max_input_bytes`. |
| `ENTANGLE-E0410`–`E0413` | Biscuit-auth parse / mint / verify / malformed-claim failures. |
| `ENTANGLE-E0420`–`E0424` | Bridge (cross-node relay) biscuit attenuation violations — missing fact, TTL/rate/byte-cap ceiling exceeded, or destination-pin mismatch. |
| `ENTANGLE-E0641` | The configured Tailscale executable is unavailable. Check the daemon's PATH. |
| `ENTANGLE-E0620`, `E0650` | MCP gateway and OpenTelemetry export stubs. |

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
