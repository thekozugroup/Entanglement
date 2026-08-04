# entangle-sdk

Guest-side SDK for authoring [Entanglement](https://github.com/thekozugroup/Entanglement)
plugins: signed WebAssembly components that a host kernel loads, sandboxes by
capability tier, and invokes.

This is the only crate a plugin needs to depend on.

```rust,ignore
use entangle_sdk::{entangle_plugin, log, PluginError};

fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
    let name = std::str::from_utf8(&input)
        .map_err(|e| PluginError::InvalidInput(e.to_string()))?;
    log::info("greeting a caller");
    Ok(format!("Hello, {name}!").into_bytes())
}

entangle_plugin!(run);
```

## Getting a project

Don't hand-write the boilerplate — the `entangle` CLI generates a project that
builds and loads as-is:

```sh
entangle plugins new my-plugin
cd my-plugin
entangle plugins build .
```

See [`docs/plugin-authoring.md`](../../docs/plugin-authoring.md) for the full
walkthrough: tiers, capabilities, signing, keyrings, loading, and invoking.

## Requirements

- The `wasm32-wasip2` target: `rustup target add wasm32-wasip2`.
- `crate-type = ["cdylib"]` in the plugin crate.

`wit-bindgen` only generates component-model bindings for `wasm32`, so on a
native target this crate compiles to little more than the `entangle_plugin!`
macro and a version smoke test. That is expected; build your plugin for
`wasm32-wasip2`.

## Depending on this crate

`entangle plugins new` writes one of three dependency forms (`--sdk <SPEC>`):

| Spec | Renders | Notes |
|------|---------|-------|
| `crates-io[:<req>]` | `entangle-sdk = "0.1"` | requires this crate to be published — see the publishing note in `Cargo.toml` |
| `git[:<url>[#<rev>]]` | `entangle-sdk = { git = "…" }` | works today; pin a `rev` for reproducible builds |
| `path:<DIR>` | `entangle-sdk = { path = "…" }` | local development against a checkout |

`auto` (the default) picks a local checkout when it can detect one — via
`ENTANGLE_SDK_PATH` or by walking up from the current directory — and otherwise
falls back to `git`.

## License

Apache-2.0.
