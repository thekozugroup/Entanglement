# Pre-built metric components

Used by `tests/integrity_atc.rs` (spec §16 ATC-INT-1/-3/-5) so that the
`SemanticEquivalent` tests run the **real** stdlib metrics rather than a
stand-in, without requiring the `wasm32-wasip2` target at test time.

| File | Source | Interface |
|---|---|---|
| `metric-bleu-4.wasm` | `plugins/metric-bleu-4/` | `entangle:integrity/metric@0.1.0` |
| `metric-numerical-l2-relative.wasm` | `plugins/metric-numerical-l2-relative/` | `entangle:integrity/metric@0.1.0` |

**Rebuild**: `bash build.sh` (from this directory or anywhere).

The source of truth is the plugin directory; these blobs are reproducible from
it with the script above. They are unsigned: each test signs them with a
throwaway publisher key, exactly like the `hello-pong.wasm` host fixture.
