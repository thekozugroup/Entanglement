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

## caps-probe.wasm

**Purpose**: Stable binary artifact used by `capabilities.rs` (and by
`entangle-runtime/tests/wasm_capabilities.rs`, `entangle-bin/tests/perms_rpc.rs`)
to check what capability grants let a plugin do. The input is a script, one
command per line (`write`, `read`, `mkdir`, `ls`, `symlink`, `connect`,
`listen`, `udp`, `udprecv`, `resolve`, `fetch`, `release`, `info`); the output has one
`ok[:detail]` or `err:<kind>:<message>` line per command. See the table at
the top of its `src/lib.rs`.

**Source**: `crates/entangle-host/fixtures-src/caps-probe/`

**Rebuild**:
```bash
bash ../../fixtures-src/caps-probe/build.sh
```
The build is reproducible: rebuilding from the committed source yields a
byte-identical file.

## stream-caps-probe.wasm

**Purpose**: The `stream-plugin`-world twin of `caps-probe.wasm`, used by
`capabilities.rs` and `entangle-runtime/tests/wasm_capabilities.rs` to check
that a streaming invocation gets exactly the capability grants a one-shot
invocation gets (same preopens, socket rules, pinned names, `capability.fetch`
decisions) and that live revocation stops a stream. `start-stream` runs its
input as a script with the `caps-probe` commands (`write`, `read`, `ls`,
`connect`, `listen`, `resolve`, `fetch`, `release`, plus `hold` / `again` to
keep a connection open across chunks) and yields **one chunk per command**;
each inbound chunk is run as a further script until the input ends. See the
table at the top of its `src/lib.rs`.

**Source**: `crates/entangle-host/fixtures-src/stream-caps-probe/` (uses
`wit-bindgen` directly: the SDK binds only the `plugin` world).

**Rebuild**:
```bash
bash ../../fixtures-src/stream-caps-probe/build.sh
```

## lifecycle-probe.wasm

**Purpose**: Stable binary artifact used by `entangle-runtime/tests/hot_reload.rs`
for hot reload and the optional `migrate` hook. A `migratable-plugin`-world
component (the `plugin` world plus `migrate`): `run` answers `id` with the
plugin id it runs as, `spin:<ms>` after busy-waiting, `read <path>` with a
file's contents, anything else with `<plugin-id>|<input>`; `migrate(from)`
fails in a version whose pre-release tag contains `fail` and otherwise writes
`<from>-><to>` to `/data/migrated` (when it has storage). See the table at
the top of its `src/lib.rs`.

**Source**: `crates/entangle-host/fixtures-src/lifecycle-probe/` (uses
`wit-bindgen` directly: the SDK binds only the `plugin` world).

**Rebuild**:
```bash
bash ../../fixtures-src/lifecycle-probe/build.sh
```

**Binary blob policy**: Committed `.wasm` files are binary blobs — this is intentional.  
The source of truth is the `fixtures-src/` directory; the blob is reproducible via the build script above.
