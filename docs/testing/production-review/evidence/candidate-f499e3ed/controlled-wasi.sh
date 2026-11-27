#!/usr/bin/env bash
set -euo pipefail

commit=${1:?candidate commit required}
expected=${2:?candidate source hash required}
archive=${3:?candidate archive required}
evidence=${4:?candidate evidence directory required}
artifact_dir=$(dirname "$archive")
label=${archive##*/}
label=${label%.tar.gz}
guest_cache=/tmp/entangle-wasip2-libtest-target
scratch=$(mktemp -d /tmp/entangle-successor-libtest.XXXXXX)
trap 'rm -rf "$scratch"' EXIT

before=$(python3 scripts/production_score.py --source-id)
printf 'UTC start %s\nsource before %s\ncommit %s\n' "$(date -u +%FT%TZ)" "$before" "$(git rev-parse HEAD)"
test "$before" = "$expected"
test "$(git rev-parse HEAD)" = "$commit"
archive_sha=$(sha256sum "$archive" | cut -d ' ' -f1)
test "$archive_sha" = "$(jq -r .sha256 "$artifact_dir/verification.json")"
rustc --version
uname -smr
printf 'command tar -xzf %q -C %q\n' "$archive" "$scratch"
tar -xzf "$archive" -C "$scratch"
binaries="$scratch/$label"
for name in entangle entangled; do
    sha256sum "$binaries/$name"
    test "$(sha256sum "$binaries/$name" | cut -d ' ' -f1)" = "$(jq -r --arg name "$name" '.files_sha256[$name]' "$artifact_dir/verification.json")"
done
printf 'command cargo test --offline --locked --target wasm32-wasip2 --target-dir %q --no-run --test atc_spec -p entangle-types -p entangle-manifest --message-format=json\n' "$guest_cache"
cargo test --offline --locked --target wasm32-wasip2 --target-dir "$guest_cache" --no-run --test atc_spec \
    -p entangle-types -p entangle-manifest --message-format=json > "$scratch/wasi-test-artifacts.json"
types=$(jq -er 'select(.reason == "compiler-artifact" and .profile.test and .target.name == "atc_spec" and (.manifest_path | endswith("/entangle-types/Cargo.toml"))) | .executable' "$scratch/wasi-test-artifacts.json")
manifest=$(jq -er 'select(.reason == "compiler-artifact" and .profile.test and .target.name == "atc_spec" and (.manifest_path | endswith("/entangle-manifest/Cargo.toml"))) | .executable' "$scratch/wasi-test-artifacts.json")
printf 'command rustc --target wasm32-wasip2 --test scripts/tests/fixtures/libtest_retry.rs -o %q\n' "$scratch/libtest_retry.wasm"
rustc --target wasm32-wasip2 --test scripts/tests/fixtures/libtest_retry.rs -o "$scratch/libtest_retry.wasm"
sha256sum "$types" "$manifest" "$scratch/libtest_retry.wasm"
printf 'command python3 scripts/tests/distributed-rust-tests.py --bin-dir %q --types-wasm %q --manifest-wasm %q --retry-wasm %q\n' "$binaries" "$types" "$manifest" "$scratch/libtest_retry.wasm"
status=0
python3 scripts/tests/distributed-rust-tests.py --bin-dir "$binaries" --types-wasm "$types" \
    --manifest-wasm "$manifest" --retry-wasm "$scratch/libtest_retry.wasm" > "$scratch/report.json" || status=$?
after=$(python3 scripts/production_score.py --source-id)
printf 'exit %s\nsource after %s\nUTC finish %s\n' "$status" "$after" "$(date -u +%FT%TZ)"
test "$after" = "$before"
test "$(git rev-parse HEAD)" = "$commit"
if [ "$status" -eq 0 ]; then
    jq --arg sid "$before" --arg after "$after" --arg commit "$commit" \
       --arg archive_sha "$archive_sha" '{
        source_id:$sid, source_before:$sid, source_after:$after, source_commit:$commit, archive_sha256:$archive_sha,
        platform:"two independent Linux workers on one host over authenticated Iroh QUIC",
        exit:0, reports:.
    }' "$scratch/report.json" > "$evidence/distributed-rust-release.json"
    jq 'map_values({counts,filtered,elapsed_ms})' "$scratch/report.json"
elif [ -s "$scratch/report.json" ]; then
    cp "$scratch/report.json" "$evidence/distributed-rust-release-incomplete.txt"
fi
exit "$status"
