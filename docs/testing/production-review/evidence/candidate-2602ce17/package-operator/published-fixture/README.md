# Test-only signed hello-world package

These artifacts use a disposable test publisher. The public key and dedicated keyring are provided for this rebuild. `source.json` records the exact Git commit, source URL, SHA-256 digests and toolchain metadata.

Run the verifier with the archive and its adjacent detached signature in the same directory.

```sh
cargo entangle verify --rebuild hello-world-0.1.0.tar.zst --keyring test-publisher-keyring.toml
```
