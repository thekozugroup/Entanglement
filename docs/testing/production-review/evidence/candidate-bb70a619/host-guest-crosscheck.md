# Repeating the native host/guest cross-check

The supplemental test links the production CLI raster module and the standalone native image-dehaze guest to the same Rust test binary. It compares every 16-bit channel of a 1033 × 1035 deterministic scene and the assembled files for tile core widths 512 and 1024. Tiles complete in reverse ordinal order. The repository also contains the host and guest suites and an independent photograph and whole-raster SciPy check. [Test and release receipts](image-unit-conformance.json) · [Photograph fixture guide](../../../../../docs/testing/raw-image-fixtures.md)

From this evidence directory, the following commands recreate its supplemental test crate in a fresh temporary directory. The recorded source and manifest refer to the qualification checkout at `/workspace/Entanglement`. Adjust the two absolute paths if using another checkout.

```sh
check_dir=$(mktemp -d)
mkdir "$check_dir/src"
cp host-guest-crosscheck.rs "$check_dir/src/lib.rs"
cp host-guest-crosscheck-manifest.txt "$check_dir/Cargo.toml"
cp host-guest-crosscheck-lock.txt "$check_dir/Cargo.lock"
cargo +1.91.1 test --offline --locked --release --manifest-path "$check_dir/Cargo.toml" -- --nocapture
```

The package lock SHA-256 is `c01c3dc130409fed8bec4ab1add2e24df39b40c1432adcffdb67200f6b07ac45`. Offline execution uses previously cached Cargo registry dependencies.
