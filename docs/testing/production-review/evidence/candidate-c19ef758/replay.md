# Repeating the Linux release checks

Start at the root of a checkout of the review branch that contains this evidence. The source commit being tested is `c19ef7587a2215ef9434b642413bebd0473caf20`. The evidence commit comes after it. The local archive label `v0.1.0` is test input. These commands require no GitHub Actions, Git tag or release publication.

## Run the two production-entry-point regression suites

On Linux with Python 3.12, `b3sum` and standard POSIX tools on `PATH`, the following exercises the actual packager and POSIX installer using temporary file fixtures. The scans inside the tests include positive installation, checksum validation, rollback, non-regular inputs and file collisions.

```bash
python3 -B scripts/tests/test_install_transaction.py -v
python3 -B scripts/tests/test_package_native_release.py -v
```

To build and package the candidate binaries, use Rust 1.91.1 and the checked-out source rather than resolving a tag. Start in the full review checkout, and use a new output directory for each packaging attempt. The repository's production workflow invokes this same Python packager. The ELF bytes depend on the compiler inputs and environment. [Packaging format](../../../../testing/native-release-packaging.md)

```bash
review=$(git rev-parse --show-toplevel)
proof="$review/docs/testing/production-review/evidence/candidate-c19ef758"
scratch=$(mktemp -d)
source_revision=c19ef7587a2215ef9434b642413bebd0473caf20
git clone --no-local --no-checkout "$review" "$scratch/source"
git -C "$scratch/source" checkout --detach "$source_revision"
epoch=$(git -C "$scratch/source" show -s --format=%ct HEAD)
(
  cd "$scratch/source"
  cargo build --release --locked -p entangle-cli -p entangle-bin -p cargo-entangle -p xtask
  python3 scripts/package-native-release.py --version v0.1.0 \
    --target x86_64-unknown-linux-gnu --source-date-epoch "$epoch" \
    --bin-dir target/release --output-dir "$scratch/packed"
)
(
  cd "$scratch/packed"
  sha256sum -c ./*.sha256
  b3sum -c ./*.b3
)
```

## Replay the actual incompatible upgrade

This x86-64 Linux exercise requires the two **specific** unsigned archives and their `.sha256` and `.b3` sidecars. Both archives have the same basename. The canonical archive requires glibc 2.39, and the supplemental archive requires glibc 2.34. The review branch retains the manifests and recorded observations. The archive files are separate local artifacts. Supply the directory containing each three-file set through `NATIVE_ARCHIVE_DIR` and `PORTABLE_ARCHIVE_DIR`. [Canonical manifest](linux-archive.json) · [Portable manifest](glibc-compat/linux-archive.json) · [Ubuntu build provenance](glibc-compat/build-inputs.json)

Use the `review`, `proof` and detached `scratch/source` checkout from above. The original harness needs a writable `/workspace` visible to rootless Docker bind mounts, `readelf`, `b3sum`, and the `ubuntu:22.04` and `ubuntu:24.04` Linux x86-64 images present in that daemon. It checks the old script at commit `a0926c6ef3471aad01cedd256028437b249ef747`, so the repository must contain that ancestor. It deliberately creates a new trace beside its driver. Copy the three files to a fresh directory to preserve the recorded evidence. [Exact image digests and observed cases](transactional-installer/installer-qualification.json) · [Fresh-checkout replay](transactional-installer/fresh-checkout.json)

```bash
asset=entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
mkdir "$scratch/installer-run"
cp "$proof/transactional-installer/"{verify.py,curl-fixture.sh,mv-fixture.sh} "$scratch/installer-run/"
python3 -B "$scratch/installer-run/verify.py" --repo "$scratch/source" \
  --source-id sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644 \
  --canonical "${NATIVE_ARCHIVE_DIR:?}/$asset" --canonical-receipt "$proof/linux-archive.json" \
  --portable "${PORTABLE_ARCHIVE_DIR:?}/$asset" --portable-receipt "$proof/glibc-compat/linux-archive.json" \
  --b3sum "$(command -v b3sum)" --prereg "$proof/qualification-plan.md"
```

The earlier failure comparison used the old installer at `5c4ead3` and the two archives from `a0926c6e`. Its stdout contains both installer hashes and both archive hashes. The pre-integration packager is identified as `b0ca308` in its original receipt. Its implementation can be recovered from `412c32b` in the review branch history. The historic drivers contain the original machine's scratch paths. [Failure before staging and rollback](transactional-installer/before-fix/comparison.json) · [Original packager investigation](reproducible-package-engineering/summary.json)

## Workload timings

The seven-route experiment ran the actual `bb70a6193f8879b1feb3e6d3ceb8f2980413ce58` and `c19ef7587a2215ef9434b642413bebd0473caf20` daemons. The performance guide lists the greeting command, JPEG source, Pillow version and image benchmark invocation. Use the ordering, workload sizes and acceptance margins recorded before this test. [Reproduction commands](../../../../performance.md) · [Fixed protocol](performance-plan.md) · [Measurements](performance.md)

The photo harness uses the two specified Git LFS sensor files, LibRaw 0.21.4 utilities, a release `image-dehaze` component, the native CLI/daemon, and Python with the imaging dependencies listed in the photo guide. Place the two hash-verified files together and pass that directory through `--fixture-dir`. Run the harness in the evidence checkout so its repository-relative imports resolve. Select a new output path with `--report`. [Fixture acquisition, hashes and dependencies](../../../../testing/raw-image-fixtures.md) · [Photo timing driver](raw-batch/loopback-harness.py) · [Measured CLI arguments](raw-clock.json)
