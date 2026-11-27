# WASI package reproducibility

The reproducibility workflow packages the pinned hello-world plugin twice in
series, checks the archive bytes, signs one copy, and verifies a rebuild using a
second Git checkout. The cross-host matrix compares SHA-256 from Ubuntu 22.04,
Ubuntu 24.04, and macOS 14 before the reproducibility job passes.

1. Confirm the serial and cross-host jobs pass for the release commit.
2. Confirm the package's committed `Cargo.lock` and exact `rust-toolchain.toml`
   are present. External WIT imports use exact versions.
3. Package and sign with the same publisher identity. The default compression
   uses one Zstandard thread at level 19. If multiple threads are requested,
   compare archives made with the same thread count.
4. Distribute the `.tar.zst` and its `.tar.zst.sig` together. Keep the source
   commit accessible at the package's recorded HTTPS Git URL.
5. Verify a copy with `cargo entangle verify --rebuild` using the published
   public key in the verifier's keyring. Record the result and SHA-256.

For a local preflight on the pinned toolchain, install the `wasm32-wasip2`
target and run the same fixture tests as CI.

```sh
cargo test --locked -p cargo-entangle --test package
cargo test --locked -p cargo-entangle --test verify_rebuild -- --ignored
```

The archive stores four regular files in alphabetical order. Header modes and
timestamps are normalized. The source epoch, Git commit, publisher identity,
lockfile, toolchain, and Zstandard settings must agree for byte-identical
packages. Treat a digest difference across the required hosts as a release
blocker.
