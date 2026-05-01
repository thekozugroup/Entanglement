# hash-it

A minimal pure-compute Entanglement plugin: returns the BLAKE3 hex hash of its input bytes.

Tier 2, zero declared capabilities. Pairs with the [hello-world](../hello-world/) example to show
how tier and capability interact in `entangle.toml`.

## Build

```bash
cargo xtask hash-it build
entangle plugins load examples/hash-it/dist/
entangle plugins invoke <fingerprint>/hash-it@0.1.0 --input "hello"
# → 9d54... (BLAKE3 of "hello")
```

## Files

- `src/lib.rs` — 6 lines of plugin logic
- `entangle.toml` — tier-2 manifest, zero capabilities
- `dist/` — produced by `cargo xtask hash-it build` (gitignored when empty)
