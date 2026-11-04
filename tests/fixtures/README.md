# Test fixtures

`repro-ci-key.pem` is a **public, test-only** Ed25519 key. It exists so the
reproducibility workflow (`.github/workflows/reproducibility.yml`) and the
`atc_pkg_*` tests sign hello-world as the same publisher on every host. It
is not trusted anywhere and must never be added to a keyring or used for a
real plugin or release.
