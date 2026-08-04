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

## stress.wasm

**Purpose**: Stable binary artifact used by `limits_and_timeout.rs` integration tests.  
Input-selected behavior: `grow` (unbounded allocation until the host limiter trips),
`spin:<ms>` (busy-loop for `<ms>` wall-clock milliseconds), anything else echoes.

**Source**: `crates/entangle-host/fixtures-src/stress/`

**Rebuild**:
```bash
bash ../../fixtures-src/stress/build.sh
```
Run from within `crates/entangle-host/tests/fixtures/`, or adjust the relative path.

**Binary blob policy**: Committed `.wasm` files are binary blobs — this is intentional.  
The source of truth is the `fixtures-src/` directory; the blob is reproducible via the build script above.
