# Linux WASI filesystem conformance

This evidence runs a newly built and locally signed, tier-1 WASI component through the frozen candidate's optimized `entangle` CLI and `entangled` daemon in a disposable profile. The guest queries `wasi:filesystem/preopens.get-directories` and makes only read-only filesystem calls against the path of a synthetic host fixture: directory and file metadata, directory listing, file read, symlink metadata and readlink, and directory metadata with a trailing slash. The host compares fixture names, modes, content digest and symlink target before and after execution. The fixture contains no credentials.

`result.json` records exact source, binary, component, guest source, lockfile and runner digests, timestamps, observations and exit status. The component and source are archived here; the installation path signs it with a fresh local identity and the daemon verifies it before invocation. `run.log` is the runner output; `build.log` is the local offline component build. `relocation.json` records successful locked metadata in an alternate checkout with identical tracked SDK files and lockfile. `deny-receipt.json` records the full all-features dependency-policy check: advisory, bans, licenses and sources passed; the retained initial failure was corrected by adding the probe license declaration. The guest reported zero preopens and none of the seven read-only calls succeeded; the fixture state matched afterward.

This is not a permissions test inside a granted directory. No rename, write, path traversal or other bypass is attempted. It covers Linux x86_64 only, not macOS or other OS hosts, and does not establish all WASI filesystem cases.

Rebuild from the repository root with the existing workspace toolchain and cached dependencies:

```sh
export CARGO_HOME=/workspace/.entanglement-dev/cargo
export RUSTUP_HOME=/workspace/.entanglement-dev/rustup
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR=/tmp/entangle-fs-probe-target
cargo build --locked --release --target wasm32-wasip2 --manifest-path docs/testing/production-review/evidence/candidate-864ae27b/wasi-fs-conformance/fs-probe/Cargo.toml
python3 docs/testing/production-review/evidence/candidate-864ae27b/wasi-fs-conformance/run.py
```
