# Signed libtest integration on Linux

The functional run uses the checked-in sharder, a disposable coordinator, two current workers and one c19ef758 worker. Each scenario selects its listed workers explicitly. The coordinator and workers exchange actual one-shot calls over authenticated loopback Iroh. A local Unix-socket observer records sharder requests and replies and times ordinary operator commands. It forwards each request unchanged. The evidence includes disposable public peer IDs and signed package digests.

The scheduling comparison uses the same two running current workers for both scripts, each pinned to one different logical CPU. It alternates the checked-out sharder and the script obtained from commit a837e6da48b67361b9d2841b6a37e892d7cbf2e3. Each guest case checks a fixed arithmetic result and prints its execution interval. Both workers have the same signed package. One short warm-up per worker is excluded.

## Reproduction

Use Linux, Python 3.11 or later, OpenSSL, taskset, rustc 1.91.1 (ed61e7d7e), its wasm32-wasip2 target, the exact repository checkout, the Linux tarball named by its linux-archive.json, and the entangle and entangled executables extracted from the c19ef758 archive for the legacy controls. The driver verifies the tarball, executable digests and candidate source IDs before dispatch. It uses a fresh private temporary directory for each cluster.

From the root of that checkout, set the variables below. Source file paths can affect Rust's embedded panic locations. The original builds used the displayed absolute temporary paths.

```sh
revision=296b427a3bb2d60615ea3c56b9779f97039c6e24
source_id=sha256:b65a7bd226264bd85b84fca929676a8cb5be88dd6ee188e3b2e30d9f2cb9ab4b
evidence=docs/testing/production-review/evidence/candidate-296b427a/rust-sharder-integration
fixtures=/tmp/entangle-integrated-sharder-qa
seeded_source=/tmp/entangle-sharder-qa
mkdir -p "$fixtures" "$seeded_source"
cp "$evidence/guarded.rs" "$fixtures/guarded.rs"
cp "$evidence/seeded.rs" "$seeded_source/seeded.rs"
cp "$evidence/seeded.rs" "$fixtures/seeded.rs"
rustc --edition=2021 --target wasm32-wasip2 --test -O --cfg build_a "$fixtures/guarded.rs" -o "$fixtures/a.wasm"
rustc --edition=2021 --target wasm32-wasip2 --test -O --cfg build_b "$fixtures/guarded.rs" -o "$fixtures/b.wasm"
rustc --edition=2021 --target wasm32-wasip2 --test -O "$seeded_source/seeded.rs" -o "$fixtures/seeded.wasm"
python3 -B "$evidence/qualify.py" identity --repo "$PWD" --revision "$revision" --source "$source_id" --fixture-dir "$fixtures" --old-bin-dir /path/to/extracted-c19ef758 --out /tmp/identity-reproduction.json
python3 -B "$evidence/qualify.py" perf --repo "$PWD" --revision "$revision" --source "$source_id" --fixture-dir "$fixtures" --out /tmp/timing-reproduction.json
```

The drivers refuse to overwrite prior output. The comparison measures a controlled mixed-duration suite on one machine. The deliberate first assertion failure exercises retry classification independently of naturally occurring language-test flakes.
