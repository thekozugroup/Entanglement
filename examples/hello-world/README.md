# Hello-World Plugin — spec §9.3 walkthrough

The simplest possible Entanglement plugin: accepts a name as `Vec<u8>`, returns
`"Hello, <name>!"` as `Vec<u8>`, and logs one INFO message through the host
logging interface.

## Prerequisites

1. **Rust toolchain** (1.85+) with the WASM component target:

   ```sh
   rustup target add wasm32-wasip2
   ```

2. **An Entanglement identity key** — run the daemon init command once:

   ```sh
   entangle init
   # writes ~/.entangle/identity.key (Ed25519 PEM)
   ```

## Build

From the workspace root:

```sh
cargo xtask hello-world build
# optionally: cargo xtask hello-world build --key /path/to/identity.key
```

This command:

1. Compiles `examples/hello-world` for `wasm32-wasip2`.
2. Copies the artifact to `examples/hello-world/dist/plugin.wasm`.
3. Signs the artifact with your identity key → `dist/plugin.wasm.sig`.
4. Writes `dist/entangle.toml` with `[plugin] id = "<fingerprint>/hello-world"`.

## Trust your own key

Add your publisher fingerprint to the local keyring (printed by the build step):

```sh
entangle keyring add <fingerprint_hex> --name "self"
```

## Load the plugin

```sh
entangle plugins load examples/hello-world/dist/
```

The daemon validates the manifest, verifies the signature, registers the plugin,
and instantiates it — emitting four lifecycle events on the bus:

1. `ManifestValidated`
2. `SignatureVerified`
3. `Registered`
4. `Loaded`

## Verify it loaded

```sh
entangle plugins list
# should show: <fingerprint>/hello-world  v0.1.0  tier=1  wasm
```

## Run the e2e integration test

The workspace integration test exercises the full pipeline in-process
(no daemon required). It is marked `#[ignore]` because it runs an
out-of-process `cargo build`:

```sh
cargo test -p entangle-runtime --test hello_world_e2e -- --ignored
```

Expected output: four `ManifestValidated → SignatureVerified → Registered → Loaded`
events followed by `Unloaded` after the kernel unloads the plugin.

## Invoke the plugin

Once the plugin is loaded you can call its `run` export through the kernel:

```sh
entangle plugins load examples/hello-world/dist/
# ✓ loaded <id>

entangle plugins invoke <id> --input "world"
# output: Hello, world!
```

Additional flags:

```sh
# Read input from a file instead of an inline string
entangle plugins invoke <id> --input-file /path/to/input.bin

# Override the default 30 s timeout (value is in milliseconds)
entangle plugins invoke <id> --input "world" --timeout-ms 5000
```

The invoke command:

1. Emits `Activated` on the lifecycle bus.
2. Calls the plugin's `run` export with the input bytes.
3. Emits `Idled` on the lifecycle bus.
4. Prints the output as UTF-8 text (or base64 if the bytes are not printable).

**Note**: the actual byte-level roundtrip (`Hello, world!` output) requires
WIT-generated host-side bindings that are completed in a later iteration. The
`Activated` / `Idled` lifecycle events and the `invoke` CLI plumbing are
available now.
