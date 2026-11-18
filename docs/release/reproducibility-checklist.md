# Reproducibility checklist

Spec: `docs/architecture.md` §9.3 ("A regression that breaks reproducibility is
a P0 release-blocker, documented in `docs/release/reproducibility-checklist.md`").
This is the list a release engineer works through before cutting a release tag.
It describes what the code enforces today; where the spec text goes further,
the gap is marked **(spec, not enforced)**.

A plugin package (`*.tar.zst`) built by `entangle plugins build` must be
**byte-identical** for the same source, toolchain and signing key, on the same
host twice, and across hosts. A release whose packages are not reproducible is
not releasable: see "Regression rule" at the end.

## 1. What makes the output deterministic

Read these once; the checklist below verifies them.

| Input | How it is pinned | Where |
|---|---|---|
| Absolute build paths in the wasm | rustc runs with `--remap-path-prefix` for the project dir, every path dependency, the cargo target dir, `$CARGO_HOME`, `$RUSTUP_HOME` and the sysroot | `crates/entangle-cli/src/cmd/repro.rs` (`remap_flags`) |
| Timestamps | The only timestamp is `created_at` in the signature bundle; it is `SOURCE_DATE_EPOCH` when set, else the fixed `REPRODUCIBLE_EPOCH` (2024-01-01T00:00:00Z) | `repro.rs` (`signing_epoch`) |
| Dependency resolution | `cargo build --locked` against a committed `Cargo.lock`; packaging refuses without one (`ENTANGLE-E0830`, ATC-PKG-3) | `repro.rs` (`require_lockfile`) |
| Archive layout, mtimes, owners, modes, zstd parameters | Fixed in the packer | `crates/entangle-oci` (`pack`) |
| Manifest serialisation | `toml::to_string_pretty` over an ordered table | `package.rs` |
| Signature | Ed25519 is deterministic: with a fixed `created_at` the bundle is a function of (artifact, manifest, key) | `entangle-signing` |
| Rust toolchain | `rust-toolchain.toml` pins `channel = "1.91"`; CI uses the same version | repo root, `.github/workflows/*.yml` |
| Locale and time zone | The cargo build is run with `LC_ALL=C` and `TZ=UTC` | `package.rs` |
| Archive contents | `entangle.toml`, `plugin.wasm`, `plugin.wasm.sig`, `provenance.json`, alphabetical | `entangle-oci` |

`provenance.json` records the source-tree SHA-256 (ignoring `.git`, and
`target/` and `dist/` directly under the project root), the git commit when
available, the toolchain and the build flags. It is **not** covered by the
publisher signature; `plugins verify --rebuild` is what validates it.

## 2. Before tagging

Tick every box on the commit that will be tagged.

- [ ] `Cargo.lock` is committed and current (`cargo metadata --locked` succeeds).
      Every plugin that ships has its own committed `Cargo.lock`
      (`plugins build` fails with `ENTANGLE-E0830` otherwise).
- [ ] `rust-toolchain.toml` pins an exact version, and the CI workflows use the
      same version. Do not bump one without the other.
- [ ] Working tree is clean (`git status`): a dirty tree changes the source digest.
- [ ] No release step sets `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS` differently
      from the documented build; the reproducible build replaces
      `build.rustflags` from `.cargo/config.toml`.
- [ ] `SOURCE_DATE_EPOCH` is either unset (fixed epoch) or set to the same value
      in every release job. Record the value in the release notes.
- [ ] The signing key used by the reproducibility jobs is the public test key
      `tests/fixtures/repro-ci-key.pem`. It must never sign a release package.

## 3. Local verification (any host)

```
cargo build --release --locked -p entangle-cli
# two builds from separate copies, in different directories, so a dropped
# path remap changes the digest:
for n in 1 2; do
  mkdir -p /tmp/repro$n && cp -r examples/hello-world /tmp/repro$n/
  rm -rf /tmp/repro$n/hello-world/target
  # point the SDK path dependency at this checkout
  sed -i "s|../../crates/entangle-sdk|$PWD/crates/entangle-sdk|" /tmp/repro$n/hello-world/Cargo.toml
  target/release/entangle plugins build /tmp/repro$n/hello-world \
      --key tests/fixtures/repro-ci-key.pem --out /tmp/repro$n/out
done
sha256sum /tmp/repro1/out/hello-world-*.tar.zst /tmp/repro2/out/hello-world-*.tar.zst   # must match
```

- [ ] The two SHA-256 digests are identical.
- [ ] `entangle plugins verify <package.tar.zst> --rebuild --source <source dir>`
      prints `PASS`. On `FAIL: <first difference>` the difference names the
      layer (source digest, toolchain, flags, manifest, wasm, signature): fix
      that layer, do not re-run until it passes.
- [ ] `cargo test --workspace --test reproducible` passes (ATC-PKG-1, -3, -4 and
      the structure check for ATC-PKG-2 in `crates/entangle-cli/tests/reproducible.rs`).

## 4. CI verification (must be green on the release commit)

`.github/workflows/reproducibility.yml` (ATC-PKG-1, ATC-PKG-2):

- [ ] `serial_double_build`: two builds on ubuntu-24.04 from different
      directories produce the same SHA-256.
- [ ] `cross_host_matrix`: hello-world is built on macos-14, ubuntu-22.04 and
      ubuntu-24.04, each uploading its digest.
- [ ] `compare`: exactly three digests were found and all are equal.
      The comparison runs **only** in CI; the local ATC-PKG-2 test checks the
      workflow's shape, not the result.

The workflow runs on pushes to `main`, on pull requests touching
`entangle-cli`, `entangle-oci`, `entangle-signing`, `entangle-sdk`,
`examples/hello-world`, the fixture key or the workflow itself, and by manual
dispatch. For a release, run it by dispatch on the release commit even if no
such path changed.

## 5. After publishing

- [ ] Rebuild a published package independently (a machine that did not build
      it) with `entangle plugins verify <package> --rebuild --source <checkout of the tagged commit>`;
      the result is `PASS`.
- [ ] `entangle release verify` passes for the release artifacts (Ed25519 and
      cosign), with the cosign identity pinned to the tag.
- [ ] Attach the digests from section 3 and the CI run URL to the release notes.

## 6. Known limits (do not treat as regressions, do not claim more)

- `plugins verify --rebuild --source` takes a local directory; it does not
  re-clone at the recorded commit. A git-commit mismatch is reported but does
  not fail when the source digest matches (spec §9.3 says "re-clone"; **spec,
  not implemented**).
- The packager does not validate that `rust-toolchain.toml` is pinned to an
  exact version nor that WIT imports carry exact `@x.y.z` versions; items 2 above
  are manual until it does (**spec, not enforced**).
- The spec's `--threads=N` zstd option does not exist; zstd runs single-threaded.
- Only wasm plugins get an archive; native plugins (`plugin.bin`) do not yet.
- The spec's example names (`cargo entangle package`, `cargo entangle verify`)
  are `entangle plugins build` and `entangle plugins verify` in the shipped CLI.

## 7. Regression rule (P0)

A change that makes any of the following fail is a **P0 release-blocker**:
the serial double build, the cross-host digest comparison, `verify --rebuild`
on the hello-world fixture, or the `Cargo.lock` requirement.

1. Open an issue labelled `P0` and `release-blocker` naming the failing job and
   the first differing layer (section 3).
2. Freeze tagging: no `v*.*.*` tag, no `release.yml` dispatch, until the check is
   green on `main` again.
3. Fix forward or revert the offending commit. Do not weaken the workflow,
   loosen the comparison, drop a host from the matrix, or skip a test to turn it
   green; a legitimately intentional change to the digest (a new toolchain, a
   new archive field) is a reviewed change to the pinned inputs in section 1 and
   must update this file in the same change.
4. After the fix, re-run section 3 and 4 in full and record the green run in
   the issue before closing it.
