# Writing an Entanglement plugin

End-to-end guide for third-party authors: scaffold a project, write `run`, pick
a tier and capabilities, build and sign, trust your key, load, invoke.

You need the `entangle` CLI and a Rust toolchain. You do **not** need a checkout
of the Entanglement repository.

```sh
rustup target add wasm32-wasip2   # once per machine
entangle init                     # once per machine — creates your publisher key
```

`entangle init --non-interactive` skips the wizard and takes the defaults.

---

## 1. Scaffold

```sh
entangle plugins new my-plugin
cd my-plugin
```

That writes a project which builds and loads with **no boilerplate editing**:

```text
my-plugin/
  Cargo.toml     crate-type = ["cdylib"], wasm-sized release profile, SDK dep
  entangle.toml  manifest: plugin id, tier, capabilities, build target
  src/lib.rs     a working `run`, wired up by entangle_plugin!
  README.md      the build/sign/load/invoke commands for this plugin
  .gitignore     target/, dist/
```

Useful flags (`entangle plugins new --help`):

| Flag | Meaning |
|------|---------|
| `--path <DIR>` | create in `<DIR>` instead of `./<name>` |
| `--tier <1..3>` | declared tier ceiling (default `1`) |
| `--description <TEXT>` | manifest description |
| `--sdk <SPEC>` | where to get `entangle-sdk` from (see below) |
| `--force` | overwrite existing files |

The name must match `^[a-z][a-z0-9-]{0,62}$` — the same rule the kernel applies
to plugin ids. It is also the cargo crate name.

### Choosing an SDK source

`--sdk` accepts:

| Spec | Renders into `Cargo.toml` | When to use it |
|------|---------------------------|----------------|
| `auto` *(default)* | a path dep if a checkout is detected, else the git dep | just works |
| `crates-io[:<req>]` | `entangle-sdk = "0.1"` | **once `entangle-sdk` is published** |
| `git[:<url>[#<rev>]]` | `entangle-sdk = { git = "…", rev = "…" }` | works today; add a `rev` for reproducible builds |
| `path:<DIR>` | `entangle-sdk = { path = "<DIR>" }` | hacking on the SDK next to your plugin |

`auto` looks at `$ENTANGLE_SDK_PATH` first, then walks up from the current
directory looking for `crates/entangle-sdk`, and otherwise emits the git
dependency.

> **Honest status:** `entangle-sdk` is **not on crates.io yet**, so
> `--sdk crates-io` produces a project that cannot resolve its dependency until
> it is published. `git` is the supported form for external authors today.
> The generated `Cargo.toml` carries all three forms as comments, so switching
> later is a one-line edit. See the publishing note at the top of
> `crates/entangle-sdk/Cargo.toml` for what still blocks publication.

---

## 2. Write `run`

`src/lib.rs` starts as a complete plugin:

```rust,ignore
use entangle_sdk::{entangle_plugin, log, PluginError};

fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
    let name = std::str::from_utf8(&input)
        .map_err(|e| PluginError::InvalidInput(e.to_string()))?;
    let name = if name.is_empty() { "world" } else { name };

    log::info(&format!("my-plugin received: {name}"));

    Ok(format!("Hello, {name}! — from my-plugin").into_bytes())
}

entangle_plugin!(run);
```

The contract is small:

- `entangle_plugin!(run)` exports your function as the component's `run` export.
  The name is yours to choose; `entangle_plugin!(handle)` works just as well.
- The signature is fixed: `fn(Vec<u8>) -> Result<Vec<u8>, PluginError>`.
- `input` is whatever the caller passed to `entangle plugins invoke`; the
  returned bytes go straight back to the caller.
- `log::{debug,info,warn,error}` reach the host at every tier — logging is a
  host-provided convenience, not a capability you have to declare.

Do not change `crate-type = ["cdylib"]` or the `[profile.release]` block:
a component plugin must be a cdylib, and `entangle plugins build` refuses to
package anything else.

---

## 3. Choose a tier and capabilities

`entangle.toml` declares a **tier ceiling** and a set of **capabilities**.

```toml
[plugin]
id = "PUBLISHER_PLACEHOLDER/my-plugin@0.1.0"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "my-plugin — an Entanglement plugin"

[capabilities]

[build]
wit_world = "entangle:plugin@0.1.0/plugin"
target = "wasm32-wasip2"
```

### The tiers

| Tier | Name | What it means | Runtime |
|------|------|---------------|---------|
| 1 | pure | pure computation, no I/O at all | `wasm` |
| 2 | sandboxed | scoped local storage | `wasm` |
| 3 | networked | outbound connections to declared hosts | `wasm` |
| 4 | privileged | shared volumes, inter-plugin messaging | `native` |
| 5 | native | full host access, incl. the Docker socket | `native` |

`runtime = "wasm"` is only valid for tiers 1–3, and `runtime = "native"` only
for tiers 4–5. `entangle plugins new` generates wasm plugins (`--tier` 1–3)
unless you pass `--native` (`--tier` 4–5) — see
[Native plugins](#native-tier-45-plugins) below.

### The tier ↔ capability rule

Every capability carries a **minimum tier**:

| Capability key | Min tier |
|----------------|----------|
| `"storage.local" = { scope = "plugin" }` | 1 |
| `"custom.*"` | 1 |
| `"compute.cpu" = {}` | 2 |
| `"storage.local" = { scope = "shared" }` | 2 |
| `"agent.invoke" = {}` | 2 |
| `"compute.gpu" = {}` | 3 |
| `"compute.npu" = {}` | 3 |
| `"net.lan" = {}` | 3 |
| `"net.wan" = { hosts = ["api.example.com:443"] }` | 3 |
| `"net.wan" = {}` (any host) or a wildcard entry (`"*"`, `"*.example.com"`) | 4 |
| `"storage.share.<name>" = { mode = "ro" \| "rw" \| "rw-scoped" }` | 4 |
| `"mesh.peer" = {}` | 4 |
| `"host.docker-socket" = {}` | 5 |

`<name>` in `storage.share.<name>` is one path component matching
`[a-z0-9][a-z0-9_-]*` (at most 63 characters); anything else, such as `/`,
`..` or `a/b`, fails validation.

The *implied tier* is the maximum minimum-tier across everything you declare.
The rule is:

- **Declaring a capability below its implied tier fails validation with
  `ENTANGLE-E0042`.** For example `tier = 1` together with
  `"net.wan" = { hosts = ["api.example.com:443"] }` is rejected, because
  `net.wan` implies tier 3 — and a tier-3 plugin with an unrestricted
  `"net.wan" = {}` is rejected too, because WAN egress wildcards are a
  tier-4 authority (spec §4.2); the error tells you to list the hosts.
- Declaring a tier *above* what your capabilities need is allowed. The
  **effective tier** is `max(declared, implied)`, so over-declaring costs you
  privilege headroom you didn't need — grant the least privilege you can.

`entangle plugins build` runs this validation *before* it compiles anything, so
a tier mistake fails in about a second:

```text
error: the rendered entangle.toml is not a valid plugin manifest
  caused by: ENTANGLE-E0042: declared tier Pure below implied tier Networked from capability 'net.wan'
```

### Capability parameters

Each capability is a table; every key in it is checked. A key a capability
does not take is refused (`ENTANGLE-E0203`), so a typo such as `host = …`
for `hosts = …` can never silently drop a restriction; a malformed value is
`ENTANGLE-E0202`. Every capability also accepts `rationale = "…"`, a string
shown to the operator.

| Capability | Parameters |
|---|---|
| `storage.local` | `scope` = `"plugin"` (default; `"$plugin_data"` is an alias) or `"shared"`; `mode` = `"rw"` (default) or `"ro"` |
| `storage.share.<name>` | `mode` = `"ro"` (default), `"rw"` or `"rw-scoped"` |
| `net.wan` | `hosts` = non-empty list of `"host[:port]"`: a DNS name, an IPv4 address, or a bracketed IPv6 address (`"[2001:db8::1]:443"`). No port = every port of that host. `"*"` and `"*.domain"` are wildcards (tier 4). Omitting `hosts` means any host (tier 4). |
| everything else | none |

```toml
[capabilities]
"storage.local" = { mode = "rw", rationale = "cache downloaded models" }
"net.wan" = { hosts = ["api.example.com:443", "cdn.example.com"] }
```

### Using capabilities at run time

Declaring a capability is necessary but not sufficient: when the plugin is
loaded the daemon's capability broker decides each one (spec §4.5). It grants
it unless the operator's policy refuses it — `[security] deny_capabilities`
in the daemon config, or a `max_tier_allowed` below your tier. A denied
capability does **not** stop your plugin from loading; it simply does not
work, and `entangle perms list` shows why. An operator can also revoke a
capability from a running plugin (`entangle perms revoke`). Write plugins
that degrade gracefully when a capability is missing.

What a wasm plugin can reach is derived from the broker's grants alone —
nothing else is ambient:

**Storage.** `storage.local` (plugin scope) appears in the guest as the
directory **`/data`**: your plugin's private directory on the host, kept
across invocations and upgrades (it is keyed by publisher and name, not
version). Use ordinary `std::fs` with absolute paths under `/data`; there is
no working directory, so relative paths fail. With `mode = "ro"` the
directory is readable and every write, create, rename or delete fails with
`PermissionDenied`. `scope = "shared"` appears as **`/shared`**, a directory
every shared-scope plugin sees; `storage.share.<name>` (tier 4, native only
today) would appear as `/shares/<name>`. Nothing else on the host filesystem
exists for the guest: absolute paths outside these directories, `..` above
them and symbolic links pointing out of them all fail, whoever created the
link.

```rust
std::fs::write("/data/state.json", &bytes)?;          // needs storage.local (rw)
let cached = std::fs::read("/data/state.json").ok();  // works with ro too
```

**Network.** Use `std::net::TcpStream` / `UdpSocket` (wasi:sockets). Without
a `net.*` grant there is no TCP, no UDP and no DNS at all.

- `net.lan` — connect (TCP) or send (UDP) to LAN addresses only: RFC 1918
  (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`,
  `fe80::/10`) and unique-local IPv6 (`fc00::/7`). **The daemon's own host
  is never reachable** — neither loopback (`127.0.0.0/8` / `::1`) nor any
  address assigned to one of the host's interfaces, through any grant — and
  neither are cloud instance-metadata endpoints (`169.254.169.254`,
  `fd00:ec2::254` and their AWS siblings).
- `net.wan` — connect to exactly the listed `host[:port]` entries. Host
  names are resolved **by the daemon when each invocation starts**, and the
  invocation may connect to exactly the addresses they resolved to (on the
  listed port, if any). The guest's own DNS answers cannot widen that: an
  allowlisted name that resolves somewhere else mid-invocation (DNS
  rebinding) is still refused, as is any allowlisted name that resolves to a
  LAN, loopback or other non-public address (use `net.lan` for LAN hosts).
- Either grant enables DNS lookups (`ToSocketAddrs`) for the guest.
- Plugins are clients: listening (`TcpListener::bind`) is always refused; a
  UDP socket may bind only an ephemeral port on the unspecified address.

A refused address fails with `PermissionDenied`, before any packet is sent.

**`capability.fetch`.** `entangle_sdk::capability::fetch(kind, name)` asks
the broker for a handle to a capability (`name` is the share name for
`storage-share`, the suffix for `custom`, and `None` otherwise):

```rust
use entangle_sdk::capability::{fetch, release, FetchError, Kind};

match fetch(Kind::NetWan, None) {
    Ok(handle) => { /* granted: go online */ release(handle); }
    Err(FetchError::NotGranted(why)) => { /* not declared or denied: `why` carries the ENTANGLE code */ }
    Err(FetchError::Revoked) => { /* the operator revoked it */ }
    Err(FetchError::InvalidKind) => { /* malformed name, e.g. `storage-share` without one */ }
}
```

It returns a handle only for a capability your manifest declares **and** the
broker grants; otherwise `not-granted` with the reason (`ENTANGLE-E0120` not
declared, `E0124` operator policy, `E0127` tier ceiling), or `revoked`
(`E0125`) after `entangle perms revoke`. Every decision is audited and counted
(`entangle_capability_grants_total` / `entangle_capability_denials_total`).
Storage and network work without fetching — they are realised from the
standing grants — so today a handle is mainly a reliable "do I have this?"
check, and the token future host interfaces (GPU, mesh, agent invocation)
will take. Handles belong to one invocation: `release` is idempotent, and
any handle still held when the invocation ends is released for you. An
invocation may hold at most 256 handles and make at most 1024 fetches.

### The plugin id

The `id` field must be the fully-qualified three-part form:

```text
<publisher_fingerprint>/<name>@<version>
```

An id missing `@<version>` is rejected by the kernel with `ENTANGLE-E0201`.

You never write the publisher yourself — you can't know your own fingerprint
until `entangle init` has run. Leave `PUBLISHER_PLACEHOLDER` in place;
`entangle plugins build` replaces it with the fingerprint of the key that signs
the artifact, and forces `@<version>` to match the `version` field. If you bump
`version`, the id follows automatically.

---

## 4. Build and sign

```sh
entangle plugins build .
```

This:

1. reads your identity key (`~/.entangle/identity.key`, or `--key <PEM>`);
2. renders and **validates** `dist/entangle.toml` with the real publisher id;
3. runs `cargo build --release --target wasm32-wasip2`;
4. copies the component to `dist/plugin.wasm`;
5. signs *both* the wasm and the manifest bytes into `dist/plugin.wasm.sig`.

```text
dist/
  plugin.wasm       compiled component
  entangle.toml     manifest with the real publisher in the id
  plugin.wasm.sig   detached Ed25519 signature bundle
```

Because the signature covers the manifest as well as the wasm, editing
`dist/entangle.toml` after signing (raising the tier, adding a capability)
invalidates the bundle and the load fails.

Flags (`entangle plugins build --help`):

| Flag | Meaning |
|------|---------|
| `<DIR>` | project directory (default `.`) |
| `--key <PEM>` | signing key (default `~/.entangle/identity.key`) |
| `--out <DIR>` | output directory (default `<DIR>/dist`) |
| `--wasm <FILE>` | package a pre-built artifact instead of running cargo |
| `--target <TRIPLE>` | build target (default `wasm32-wasip2`) |

The command prints your publisher fingerprint, the fully-qualified plugin id,
the effective tier, and then the exact next commands to run.

### Building from inside this repository

Contributors can use the xtask aliases, which delegate to the same
implementation:

```sh
cargo xtask plugin build <DIR>       # any directory
cargo xtask hello-world build        # alias for examples/hello-world
cargo xtask hash-it build            # alias for examples/hash-it
```

---

## 5. Trust your publisher key

Signing is mandatory, and the kernel only loads artifacts signed by a key in
your keyring. Add your own:

```sh
entangle keyring add <PUBLIC_KEY_HEX> --name self
entangle keyring list
```

`<PUBLIC_KEY_HEX>` is the 64-hex-char *public key* (not the 32-char
fingerprint) — `entangle plugins build` prints the exact `keyring add` line to
copy. To distribute your plugin to someone else, give them that same public key
hex; they run the same `keyring add` before loading.

Remove a key by fingerprint:

```sh
entangle keyring remove <FINGERPRINT_HEX>
```

---

## 6. Load and invoke

Loaded plugins live in the daemon, so start it in another terminal:

```sh
entangled run
```

Then:

```sh
entangle plugins load ./dist
entangle plugins list
entangle plugins invoke <publisher>/my-plugin@0.1.0 --input 'world'
entangle plugins unload <publisher>/my-plugin@0.1.0
```

`invoke` also takes `--input-file <PATH>` for binary payloads and
`--timeout-ms <N>` (default 30000). Non-UTF-8 output is printed base64-encoded.

Without a daemon, `--allow-local` runs a short-lived in-process kernel. It keeps
no state between commands, so it is only useful for a single operation such as
checking that a package loads:

```sh
entangle --allow-local plugins load ./dist
```

If something goes wrong, `entangle doctor` checks your identity, config,
keyring, and daemon reachability.

---

## 7. Publish to an OCI registry

Any OCI Distribution v1.1 registry (GHCR, Harbor, a self-hosted `registry:2`,
a mirror) can host your plugin. The registry is only a place to keep bytes:
consumers trust **your publisher key**, never the registry (spec §3.6, ATC-MIR-1).

```sh
entangle plugins build .                       # produces dist/ (section 4)
entangle plugins publish dist oci://ghcr.io/you/hello:0.1.0
```

`publish` accepts the build directory (or an already packed package file),
packs it, uploads the blobs (monolithic upload; chunked for packages larger
than 4 MiB) and pushes the manifest. Credentials come from
`ENTANGLE_OCI_TOKEN`, or `ENTANGLE_OCI_USERNAME` + `ENTANGLE_OCI_PASSWORD`,
together with `ENTANGLE_OCI_REGISTRY=<host[:port]>` naming the one registry
they are for, or from `~/.entangle/oci-auth.toml` (see `docs/operations.md`
section 12). Consumers run:

```sh
entangle keyring add <YOUR_PUBLIC_KEY_HEX> --name you   # once
entangle plugins install oci://ghcr.io/you/hello:0.1.0
```

Pin by digest (`oci://ghcr.io/you/hello@sha256:<hex>`) for reproducible installs;
tags are mutable.

### Artifact format

| Item | Value |
|------|-------|
| Manifest media type | `application/vnd.oci.image.manifest.v1+json` |
| `artifactType` | `application/vnd.entangle.plugin.v1` |
| Config | the OCI empty descriptor (`application/vnd.oci.empty.v1+json`, `{}`) |
| Layer (exactly one) | `application/vnd.entangle.plugin.layer.v1.tar+zstd` |

The layer is a zstd-compressed ustar archive of exactly three regular files,
the same ones the loader reads from `dist/`: `entangle.toml`, `plugin.wasm`,
`plugin.wasm.sig` (links, directories, extra or duplicate entries are
rejected). The archive is deterministic (fixed order, zero timestamps).
Registries that predate `artifactType` are handled via the config media type
as OCI 1.1 prescribes. An image index is accepted if it has exactly one child
manifest with this `artifactType`. Manifest annotations are informational and
never influence trust.

Pulled bytes are verified exactly like a local `dist/`: the signature must be
by a key in **your** keyring, bound to the publisher in the manifest id. The
installer then applies `security.max_tier_allowed`, manifest validation and the
kernel's own load-time checks.

### Mirror listings

A mirror operator can publish a signed listing of a repository's tags at the
well-known tag `_entangle-listing` (artifact type
`application/vnd.entangle.mirror-listing.v1`: a JSON layer
`...mirror-listing.v1+json` with `repository`, `tags` -> digests,
`generated_at`, `expires_at` in unix seconds, and a detached Ed25519 signature
layer `...mirror-listing.sig.v1+json` over the exact listing bytes). Listings
are signed with a dedicated **mirror key**, which is never a publisher key:

```sh
entangle plugins mirror-sign oci://mirror.example/you/hello --key mirror.pem --ttl-days 7
entangle plugins tags oci://mirror.example/you/hello
```

A listing says which tags existed; it cannot make an artifact trusted.

## Native (tier 4–5) plugins

Some workloads cannot be wasm (a Node.js agent, a GPU driver). A native
plugin is an ordinary **executable** that the daemon runs inside the host's
OS sandbox — Landlock + seccomp + namespaces on Linux, Seatbelt on macOS —
derived from the capabilities it declares.

```sh
entangle plugins new my-native --native     # tier 5 by default; --tier 4 also valid
entangle plugins build my-native            # cargo build --release for THIS host + sign
```

`dist/` then holds `plugin.bin`, `entangle.toml` and `plugin.bin.sig`; trust,
load and invoke exactly as above. A pre-built executable can be packaged with
`--bin <FILE>`. `examples/native-echo/` is a complete example.

**Protocol.** The generated `src/main.rs` implements it; there is no SDK
dependency. Each invocation starts a fresh process, writes one request to its
stdin and closes it, and reads one response from its stdout:

```text
request  (stdin):  u32 big-endian length | input bytes
response (stdout): u32 big-endian length | tag | body
                   tag 0 = ok (body = output), tag 1 = err (body = UTF-8 message)
```

The response length includes the tag byte. stderr goes to the daemon log. The
process is killed (with everything it forked) at the invocation deadline, and
a response larger than the configured cap is refused from its header.

**What the plugin can touch** is exactly what its granted capabilities map
to (`docs/operations.md` §12): with no capabilities, only its own binary and
the system libraries, no network, no Unix sockets, an empty environment apart
from `ENTANGLE_PLUGIN_ID`. `storage.local { scope = "plugin" }` adds a private
directory at `$ENTANGLE_DATA_DIR` — the same host directory a wasm plugin sees
as `/data`, read-write or read-only per `mode`. For native plugins `net.lan`
and `net.wan` currently grant IP networking as a whole; the per-address rules
above apply to wasm plugins. For the same reason an operator who denies either
one (`[security] deny_capabilities`) denies a native plugin both.

Native plugins are refused on hosts with no sandbox primitive, and operators
can disable them entirely with `[security] max_tier_allowed = 3` (or tier 5
alone with `= 4`).

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `ENTANGLE-E0042: declared tier … below implied tier …` | raise `tier`, or drop the capability |
| `ENTANGLE-E0042 … a wildcard or unrestricted WAN allowlist is a tier-4 authority` | list the hosts: `"net.wan" = { hosts = ["api.example.com:443"] }` |
| `ENTANGLE-E0202: malformed capability args` / `ENTANGLE-E0203: … does not take parameter` | fix the capability table; see [Capability parameters](#capability-parameters) |
| `fetch` → `not-granted: ENTANGLE-E0124 … by operator policy`, or `/data` missing | the operator denies that capability (`entangle perms list` shows it); the plugin runs without it |
| `fetch` → `revoked` | the operator ran `entangle perms revoke`; reload the plugin to get it back |
| `ENTANGLE-E0508` / `E0509` when loading | a storage grant has no data directory, or the plugin's directory is a symbolic link / not a directory (see `docs/operations.md` §15) |
| `PermissionDenied` on connect | the address is not covered by your `net.*` grant (loopback never is) |
| `ENTANGLE-E0201: plugin id format invalid` | the id is not `<publisher>/<name>@<version>`; rebuild with `entangle plugins build` rather than hand-editing `dist/` |
| `ENTANGLE-E0101: publisher fingerprint not in keyring` | run `entangle keyring add <PUBLIC_KEY_HEX> --name …` |
| `ENTANGLE-E0104: manifest hash mismatch` | `dist/entangle.toml` was edited after signing; rebuild |
| `[signature] publisher = … does not match the signing key` | an optional `[signature]` section pins a different signer; drop it or sign with that key via `--key` |
| `the wasm32-wasip2 target is not installed` | `rustup target add wasm32-wasip2` |
| `… does not declare crate-type = ["cdylib"]` | restore the `[lib]` block in `Cargo.toml` |
| `identity key not found at ~/.entangle/identity.key` | `entangle init` |
| `ENTANGLE-E0814: package verification failed` on `install oci://` | the signer is not in your keyring (`ENTANGLE-E0101`) or the package was altered; the registry is irrelevant |
| `ENTANGLE-E0507: runtime kind mismatch` | the artifact is not what `runtime` says (an executable shipped as wasm, or the reverse); rebuild with `entangle plugins build` |
| `ENTANGLE-E0700` / `E0701` when loading a native plugin | the host has no OS sandbox (or cannot take the network away); see `entangle doctor` and `docs/operations.md` §12 |

## Reference

- `crates/entangle-sdk/README.md` — the SDK surface and dependency forms.
- `docs/architecture.md` §4.2 (tiers), §4.3 (tier ↔ capability binding),
  §4.4 (manifest), §4.5–4.6 (capability resolution, grants and revocation),
  §3.6 (artifact signing).
- `crates/entangle-host/fixtures-src/caps-probe/` — a test plugin that
  exercises storage, sockets, DNS and `capability.fetch`.
- `docs/tutorial.md` — a narrated walkthrough using the bundled examples.
- `examples/hello-world/`, `examples/hash-it/` — working plugins in-tree.
- `examples/native-echo/` — a working native (tier 5) plugin.
