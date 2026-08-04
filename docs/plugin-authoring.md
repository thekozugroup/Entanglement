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
for tiers 4–5. `entangle plugins new` generates wasm plugins, so `--tier` is
limited to 1–3.

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
| `"net.wan" = {}` | 3 |
| `"storage.share.<name>" = { mode = "ro" \| "rw" \| "rw-scoped" }` | 4 |
| `"mesh.peer" = {}` | 4 |
| `"host.docker-socket" = {}` | 5 |

The *implied tier* is the maximum minimum-tier across everything you declare.
The rule is:

- **Declaring a capability below its implied tier fails validation with
  `ENTANGLE-E0042`.** For example `tier = 1` together with `"net.wan" = {}`
  is rejected, because `net.wan` implies tier 3.
- Declaring a tier *above* what your capabilities need is allowed. The
  **effective tier** is `max(declared, implied)`, so over-declaring costs you
  privilege headroom you didn't need — grant the least privilege you can.

`entangle plugins build` runs this validation *before* it compiles anything, so
a tier mistake fails in about a second:

```text
error: the rendered entangle.toml is not a valid plugin manifest
  caused by: ENTANGLE-E0042: declared tier Pure below implied tier Networked from capability 'net.wan'
```

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

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `ENTANGLE-E0042: declared tier … below implied tier …` | raise `tier`, or drop the capability |
| `ENTANGLE-E0201: plugin id format invalid` | the id is not `<publisher>/<name>@<version>`; rebuild with `entangle plugins build` rather than hand-editing `dist/` |
| `ENTANGLE-E0101: publisher fingerprint not in keyring` | run `entangle keyring add <PUBLIC_KEY_HEX> --name …` |
| `ENTANGLE-E0104: manifest hash mismatch` | `dist/entangle.toml` was edited after signing; rebuild |
| `[signature] publisher = … does not match the signing key` | an optional `[signature]` section pins a different signer; drop it or sign with that key via `--key` |
| `the wasm32-wasip2 target is not installed` | `rustup target add wasm32-wasip2` |
| `… does not declare crate-type = ["cdylib"]` | restore the `[lib]` block in `Cargo.toml` |
| `identity key not found at ~/.entangle/identity.key` | `entangle init` |

## Reference

- `crates/entangle-sdk/README.md` — the SDK surface and dependency forms.
- `docs/architecture.md` §4.2 (tiers), §4.3 (tier ↔ capability binding),
  §4.4 (manifest), §3.6 (artifact signing).
- `docs/tutorial.md` — a narrated walkthrough using the bundled examples.
- `examples/hello-world/`, `examples/hash-it/` — working plugins in-tree.
