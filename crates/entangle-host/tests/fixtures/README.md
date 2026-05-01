# Pre-built WASM test fixtures

## hello-pong.wasm

**Purpose**: Stable binary artifact used by `fixture_invoke.rs` integration tests.  
Pre-built so CI does not require the `wasm32-wasip2` target at test time.

**Source**: `crates/entangle-host/fixtures-src/hello-pong/`

**Rebuild**:
```bash
bash ../../fixtures-src/hello-pong/build.sh
```
Run from within `crates/entangle-host/tests/fixtures/`, or adjust the relative path.

**Size**: intentionally kept under 500 KB (typical ~50–150 KB with `opt-level = "s"` + LTO + strip).  
Do not add dependencies that bloat the binary beyond this limit.

**Binary blob policy**: Committed `.wasm` files are binary blobs — this is intentional.  
The source of truth is the `fixtures-src/` directory; the blob is reproducible via the build script above.
