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
| `[runtime.inference]` | `endpoint`, `model`, `token_env` | optional table | disabled | Opt in to signed streams from a local OpenAI-compatible model server. |
| `[mesh]` | `transports` | array of strings | `[]` | `local` enables LAN mDNS, `iroh` enables configured QUIC routes, and `tailscale` enables routes discovered through the local Tailscale client. Select both `local` and `iroh` for automatic routes to paired LAN workers. |
| `[scheduler]` | `bind` | socket address | `0.0.0.0:0` | Scheduler UDP listener. LAN discovery advertises the assigned port, including when `:0` selects it. Static and tailnet routes require a known worker port. |
| `[scheduler]` | `peers` | array of strings | `[]` | Static Iroh worker addresses in `<public-key-hex>@<ip>:<port>` form. Paired workers discovered on the LAN can use an empty list. |
| `[scheduler]` | `tailnet_peers` | array of tables | `[]` | Stable Tailscale node ID, Entanglement public key and scheduler port for each worker. |
| `[scheduler]` | `relay` | bool | `true` | Allow Iroh relay fallback when the `iroh` transport is enabled. |
| `[mesh]` | `multi_node` | bool | `false` | When `true`, the daemon requires at least one trusted peer in `peers.toml` **before it will start**. See §5 for the exact failure. |
| `[security]` | `max_tier_allowed` | integer 1–5 | `5` | Ceiling on the plugin tier the daemon will load (`Tier::Native` = 5 down to `Tier::Pure` = 1). A load above the ceiling is refused with `ENTANGLE-E0043`. Out-of-range values (`0` or `>5`) fail to parse. |
| `[wrappers]` | `install` | bool | unset | Explicit opt-in or opt-out for shell warnings; an unset preference may be prompted for on an interactive install. |

The daemon and CLI read the same configuration schema. Both validate `max_tier_allowed` as an integer from 1 through 5. Installing a plugin checks the tier ceiling before building or trusting the publisher. The temporary worker used by `--allow-local` also applies the ceiling when loading a signed package. Build-only installations (`--no-load`) can prepare components for a different device.

`entangle init` enables LAN discovery and QUIC scheduling, with `[scheduler] relay = false` for this LAN configuration. It preserves existing configuration files. Set `multi_node` under `[mesh]` and `max_tier_allowed` under `[security]`. Older configurations that place these keys under `[runtime]` produce a configuration error. [Configuration schema](../crates/entangle-runtime/src/config.rs)

The daemon reads `~/.entangle/config.toml` and requires a resolvable home directory. Section 3 describes path resolution for the config and socket.

---

### Adjusting the tier ceiling

Run `entangle config validate` after editing `[security] max_tier_allowed`. It checks the proposed ceiling against the live plugin inventory and exits unsuccessfully if approval is needed. `entangle config reload` applies the tier policy to the running daemon. When the change affects loaded plugins, the terminal lists each ID and tier. Press Enter or `u` to drain and disable them, or `c` to restore the previous ceiling in the file.

Plugin unload and tier policy operations wait up to five seconds for registry reservations and active work to drain. If a stream is waiting for receiver credit or a tier-5 inference call keeps its lease longer, the command returns an error before saving or unloading. Finish or cancel the active request, then retry. An already edited config file still holds your proposed value until you apply or cancel it.

For automation, `entangle security set-max-tier 2 --force-unload` prints the affected plugins to stderr and records an `ENTANGLE-W0214` audit event for each plugin. Successful changes record `ENTANGLE-I0215`, and cancellation records `ENTANGLE-I0216`. If the file or inventory changes between review and approval, repeat the command to review the new state.

The daemon preserves disabled IDs under `[runtime] disabled_plugins`, including across restarts and later ceiling increases. To re-enable a plugin, raise the ceiling if necessary, remove its ID from that list, run `entangle config reload` and load the signed package. Other daemon startup settings take effect at restart.

The Linux acceptance check exercises this workflow with two signed tier-3 WebAssembly components. The current package loader supports WebAssembly. A native tier-5 agent-host needs a signed native supervisor with an enforced OS sandbox and working gateway.

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

### Comparing outputs from three workers

Load the same signed compute package on three distinct paired workers and load a signed comparator package on the submitting daemon. The comparator manifest declares tier 2 and the build world `entangle:integrity/comparator@0.1.0`. Its component exports `entangle:integrity/metric@0.1.0` with `compare(a: list<u8>, b: list<u8>) -> f64`. The local publisher keyring must contain its exact signing key at submission.

```sh
entangle plugins load /path/to/signed-comparator
entangle compute dispatch '<job-publisher>/<job>@1.0.0' \
  --input-file image.bin --integrity semantic-equivalent \
  --metric '<metric-publisher>/<metric>@1.0.0' --threshold 0.25 \
  --max-output-bytes 1048576 --timeout-ms 30000
```

Every selected worker must negotiate signed semantic replicas before the coordinator sends job bytes. The coordinator signs one work unit identifying the task, limits, comparator content digest, publisher and threshold. Each worker runs one copy of the job and returns its observed policy hash and raw output. The coordinator enforces the byte limit before invoking the local comparator on the three output pairs. At least two distances must be below the threshold. The result names the executor whose output has the most supporting comparisons. A worker with an older protocol causes this policy to fail closed. Unrelated one-shot tasks continue to use the original v1 protocol.

### Monitoring work

The scheduler's QUIC listener admits up to 64 live connections, including incomplete handshakes, and reads up to eight opening request frames at once. The default handshake deadline is 15 seconds. Idle connections and incomplete opening frames expire after 30 seconds. Once a request enters its handler, its own execution, credit and heartbeat deadlines apply.

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

### Streaming inference from a worker

Run your OpenAI-compatible model server on the paired worker. For example, an operator with a local GGUF model can run `llama-server --host 127.0.0.1 --port 8080 --model /path/to/model.gguf --alias desktop-model`. Merge the following into the worker's config and restart `entangled`.

```toml
[runtime.inference]
endpoint = "http://127.0.0.1:8080/v1/chat/completions"
model = "desktop-model"
# token_env = "ENTANGLE_INFERENCE_TOKEN"
```

Use a literal loopback address and either `/v1/chat/completions` or `/v1/completions`. If the backend requires a bearer token, set `token_env` to the name of a variable available to the daemon service. The model must appear in the backend's `/v1/models` response. The daemon checks that response when reporting its capabilities and each time it starts inference. The configured adapter ID appears in the worker startup log. It uses the worker's 32-digit identity fingerprint and the name `openai-inference@0.1.0`.

On the paired coordinator, allow a capability polling cycle and submit a stream using the adapter ID and the worker's full peer ID.

```sh
entangle compute stream '<worker-fingerprint>/openai-inference@0.1.0' \
  --allow '<worker-entanglement-peer-id>' --credit-window 32 \
  --input '{"prompt":"Summarize the benefits of local inference.","max_tokens":128,"temperature":0.5}'
```

The adapter accepts one request at a time on the worker, with at most 64 KiB of input, 4096 requested tokens and a five-minute active execution limit by default. Backend I/O counts toward this limit. Waiting for credit to deliver a yielded chunk pauses it. One credit timeout reports a stall and a second interval without credit cancels the stream. Each interval defaults to 30 minutes. Output uses the task's byte and credit limits. The coordinator verifies each signed chunk before writing it to stdout. Job input can set the prompt, `max_tokens`, and optional `temperature`. The worker operator owns the endpoint, model and credentials.

This is a daemon service using a model server you operate separately. It requires tier 5 and advertises a streaming-only capability. Lowering the live tier drains any active bounded inference request and disables new requests. If the server is offline, the model disappears, or the backend lacks the supported API, signed Wasm plugin streaming remains available to trusted peers. To run the transport check with local chat and completion SSE fixtures, use `cargo test --locked -p entangle-bin --test daemon_compute inference::configured_inference_streams_incremental_signed_chunks -- --exact`.

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

5. Configure the worker's signed plugin package as shown above and restart both Entanglement daemons. Check `entangle mesh status` for `tailscale` on each. On the coordinator, the following command restricts execution to the paired worker and prints the chosen peer and result. If the worker has a trusted route, this command can refresh its inventory before the next scheduled poll.

```sh
entangle compute dispatch '<publisher>/json-pointer@0.1.0' \
  --input '{"pointer":"/job/id","data":{"job":{"id":42}}}' \
  --cpu-cores 0.25 --integrity trusted-executor --allow '<worker-entanglement-peer-id>'
```

The daemon refreshes tailnet address hints every 30 seconds and polls configured workers for hardware and loaded plugin versions every 15 seconds. Each scheduler connection authenticates the worker's Entanglement key. Both sides consult the persisted trust store when authorizing work. A mapping can remain in the configuration after revocation.

With an active scheduler listener, an ordinary one-shot dispatch that selects an already paired, explicitly mapped worker can request a fresh local Tailscale status snapshot if no route is known. Concurrent misses share one snapshot. Demand status commands start at least one second apart and have a 750 ms deadline. Each caller waits up to one second within its existing transfer budget. The daemon rechecks the worker's pairing before using a recovered route and sends the invocation at most once. Manage the local Tailscale service separately.

The default address family is IPv4. Use `[::]:7443` on hosts using Tailscale IPv6. A Tailscale-only daemon can start before the local Tailscale service. Local commands remain available while the scheduler waits for a verified tailnet address. During that wait, `entangle mesh status` shows no active scheduler transport and the daemon leaves the scheduler port unbound.

After a successful initial bind, a Tailscale-only daemon can recover from a later `tailscaled` restart. When it detects loss of the listener or local address, it withdraws its routes. It retries the bind at intervals of 1 to 15 seconds using the same Entanglement identity and UDP port. A configured wildcard can select a new local tailnet address in the same IP family. An explicitly configured address must return before the listener can recover. Check `entangle mesh status` on both devices, then submit a fresh job and verify the selected peer. Interrupted jobs may have executed before the connection failed. Check the job's effects before submitting it again.

The daemon polls worker inventory at startup and every 15 seconds. After a placement miss, an ordinary local `compute dispatch` can request an earlier authenticated report from explicitly configured peers with current trusted routes. A trusted-executor request queries only its allowed peers. The daemon waits up to 2.5 seconds, within the original task timeout. When a usable report arrives, it selects once more before execution and subtracts the wait from the task's timeout. A failed selection returns to the caller. An invocation that has already started, including a request whose connection failed before returning output, is never replayed by this refresh.

Demand inventory refreshes share route checks and queries by peer. The daemon keeps up to eight pending peers and probes up to eight concurrently with a two-second deadline per demand query. Extra waves start at least two seconds apart. The ordinary polling lane retains its limit of eight queries, for a combined maximum of 16 during overlap. A usable cached worker report avoids demand inventory refresh. LAN-only discovery, streaming, and replicated operations keep their existing behavior.

Tailnet policy controls network reachability. Applying a narrower ACL can leave an established UDP flow usable for a time. To withdraw a peer's permission to submit jobs, run `entangle mesh revoke <peer-id>` on the worker. The worker enforces its current trust store when the link returns.

In mixed `["iroh", "tailscale"]` mode the ordinary Iroh listener and relay policy apply. Linux and macOS host deployments can use this mode with a working Tailscale interface. Userspace-only SOCKS deployments and MagicDNS service publication are outside this implementation.

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

The test builds and signs all eight plugins in temporary profiles, verifies
their output on a local daemon, then repeats the workloads through an empty
coordinator and a trusted worker over loopback QUIC. Omit `--two-node` to run
only the local phase.

### Process a directory of camera RAW files

Install the LibRaw tools on the submitting machine. Debian supplies
`dcraw_emu` and `raw-identify` in `libraw-bin`. Homebrew supplies them in
`libraw`. The Linux checks used LibRaw 0.21.4. Workers need the Entanglement
daemon and the signed tier-1 `image-dehaze` component.

Build and sign the package once on the publishing machine. Give each worker
the same signed directory and the publisher’s public key through your normal
distribution channel. Each worker must trust that publisher, pair with the
submitter, and load the package. Use the full plugin ID from the manifest
and the paired worker IDs in the command below. [Build, trust and load a plugin](plugin-authoring.md#4-build-and-sign)

```sh
entangle plugins build plugins/image-dehaze
# On each worker, after adding the publisher's public key:
entangle plugins load /path/to/signed/image-dehaze

# On the submitting machine, with its daemon running:
entangle image dehaze --recursive ./raw --output-dir ./developed \
  --plugin "$PUBLISHER/image-dehaze@0.1.0" \
  --allow "$DESKTOP_ONE" --allow "$DESKTOP_TWO" --jobs 3 --json
```

LibRaw develops each source at full resolution with linear transfer, sRGB
primaries, and automatic brightening disabled. It requests the camera’s
as-shot white balance and uses LibRaw’s fallback when unavailable. The
submitter estimates atmospheric light once per image. It sends bounded
16-bit PNG tiles with a seven-pixel overlap around each core to authorized
workers over the existing compute route. Workers process the pixels inside
their Wasm sandbox. The submitter discards the overlaps, assembles the
lossless linear RGB16 PNG, and records which peer rendered each tile.
The local RAW file, its pathname and its camera metadata stay on the
submitting machine. Each selected worker receives photographic pixel data.

A source such as `raw/trip/001.NEF` produces
`developed/trip/001.NEF.dehazed.png`. Keep the output directory outside the
input directory. Use `--resume` to verify previous results before skipping
them. The CLI processes one source at a time, with up to `--jobs` concurrent
tile dispatches. The native decoder accepts a regular file up to 128 MiB,
32 million developed pixels and 32,768 pixels per side. Camera model
coverage depends on the installed LibRaw version. Output uses a linear
transfer function and carries explicit PNG color tags for color-managed
viewers. The operation discards source metadata. [Plugin and wire format](../plugins/image-dehaze/README.md)

`--timeout-ms` sets the deadline for each worker invocation. The default
Iroh transport also limits a complete request to 30 seconds. Use smaller
`--tile-edge` values on routes that take longer to transfer a tile.

For one-shot inputs of at least 256 KiB, the scheduler also considers how
quickly each worker acknowledged recent uploads from this submitter. It
measures ordinary QUIC requests after connecting and retains a sample only
when the request succeeds and its observed path stays the same through the
acknowledgement. A response that arrives first proceeds immediately. The
placement explanation distinguishes measured upload speed from advertised
bandwidth. Samples expire after 60 seconds. A route change between jobs can
temporarily leave an older estimate in use. Download speeds and rendering
times can differ from this upload measurement.

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

## 7. Encrypted node backup and recovery

The Ed25519 key at `~/.entangle/identity.key` determines the node's peer ID. To move a node while retaining existing pairings, stop its daemon and pause CLI changes to trust, config and plugin data. Keep the original node offline after starting its replacement.

```bash
systemctl --user stop entangled
entangle backup --to /secure/offline/location/node.entbak
```

Choose a strong, unique passphrase at the hidden prompt. Keep it separately from the encrypted backup. A password manager can pipe one passphrase line to `--passphrase-stdin`. When using a daemon started with a custom `--socket`, pass the same socket path to `entangle backup`. Backup takes the daemon socket lock and requires a new output filename outside the node directory.

The snapshot includes `identity.key`, `keyring.toml`, `peers.toml`, `config.toml`, and the complete managed `plugins/` and `data/` directories. Place any startup packages under `~/.entangle/plugins/` and list their absolute paths in `[runtime].plugins`. On restore, those paths are updated for the replacement home. External storage and per-agent credentials need their own recovery procedures. For bridge or relay-receiver nodes, put the existing ledger under `~/.entangle/data/` and point `[mesh.bridge].ledger` at that absolute file. Backup takes the ledger's writer lock, retains its exact counters and relocates its path on restore. A ledger outside the managed data tree must be moved while the node is stopped. Never initialize a replacement for an existing ledger. Runtime sockets, logs and the bridge ledger lock are excluded.

Version 1 encrypts and authenticates a bounded ustar archive with XChaCha20-Poly1305, a random 24-byte nonce and Argon2id v1.3 (64 MiB, three passes, four lanes, fresh 16-byte salt). It accepts up to 128 MiB of archive data and 16,384 entries. Symbolic links, hard-linked regular files, devices, and paths beyond the supported archive limits fail the backup.

The archive restores trust as of the snapshot time. Record subsequent peer revocations and publisher removals so you can reapply them before reconnecting the replacement node. Bridge spending after the snapshot also needs reconciliation. Use the latest authoritative ledger, or keep the bridge/receiver offline until all previously issued grants expire before accepting new grants.

On the new device, install compatible binaries. Use a fresh home owned by your account that has no `~/.entangle`. Restore before starting the service or running `entangle init`.

```bash
entangle restore --from /secure/offline/location/node.entbak
systemctl --user start entangled
entangle mesh status --json
entangle plugins list
```

Restore authenticates the full ciphertext before extracting it into a private staging directory. It checks the identity, publisher keyring, peer store, configuration, and startup-package paths before atomically publishing the directory. An existing destination is preserved, including a concurrently created one. A process kill or power interruption before publication can leave a private `.entangle-restore-*` staging directory containing decrypted state. Once all restores have stopped, inspect the directory under the destination account and remove the interrupted staging copy. Compare the restored peer ID with the original ID, then dispatch a job from an existing paired node to verify connectivity and publisher trust. Update scheduler bindings or routes if the replacement machine has different interfaces or addresses.

If power is lost while restoring, the destination may still be absent and an owner-only
`.entangle-restore-*` directory can remain next to it. This staging directory can contain
decrypted identity and plugin state. With all restore processes stopped, inspect the
directory and remove the abandoned staging copy before retrying from the encrypted backup.

After verifying a recovery copy, `touch ~/.entangle/.identity_backed_up` acknowledges the built-in maintenance reminder. The reminder tracks the presence of the sentinel. Create a fresh backup after identity, trust, plugin, or configuration changes.

The disposable Linux/macOS acceptance harness runs signed work before and after restoration, checks error paths and verifies that revocation still denies the original peer. Run it against the built binaries with `python3 scripts/tests/recovery.py --bin-dir target/debug`.

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

## 10. Optional agent shell warnings

Shell warnings are an opt-in convenience, not a sandbox or a security boundary.
Run `entangle wrapper enable --shell bash` (or `zsh` / `fish`) to add functions
for `claude-code`, `codex`, and `aider`; start a new shell afterward. Each warns
on stderr outside an Entanglement session and forwards the original arguments
and exit status. `entangle wrapper status` shows the saved preference and files;
`entangle wrapper repair --shell bash` restores an unmodified managed block.
`entangle wrapper disable` removes managed blocks and records
`[wrappers] install = false` without replacing unrelated TOML content. Existing
modified blocks or symlinked startup files are refused for manual review.

A first successful `entangle install` asks only on an interactive terminal when
no preference exists. Scripts never prompt; `--wrapper` opts in explicitly and
`--no-wrapper` records an opt-out. In a configured shell, `entangle doctor` checks how that
shell currently resolves `claude-code`. The diagnostic reports a shadowed
wrapper if a later alias, function, or executable takes precedence. The
integration preserves existing aliases and functions named `entangle`.
Invoking the CLI by absolute path or with `command entangle doctor` bypasses
the shell check and can only report the information available to a child process.
Run `entangle wrapper repair --shell bash` (or `zsh` / `fish`) and start a fresh
shell to upgrade an older managed block. Direct `command claude-code`
bypasses the warning.
