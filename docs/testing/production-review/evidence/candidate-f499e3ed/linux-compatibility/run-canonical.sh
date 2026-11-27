#!/bin/sh
set -eu
cd /workspace/Entanglement
root=docs/testing/production-review/evidence/candidate-f499e3ed
evidence="$root/linux-compatibility"
mkdir "$evidence/linux-userspaces"
python3 -B "$evidence/userspaces.py" --repo . --out "$evidence/linux-userspaces" \
    --commit f499e3edf84e20f550312d05df51b9ea4e7cc699 \
    --source-id sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa \
    --archive target/release-candidate/f499e3edf84e/entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz \
    --archive-receipt "$root/linux-archive.json" \
    --wasm target/catalog-smoke/wasm32-wasip2/release/entangle_json_pointer.wasm \
    --b3sum /tmp/entangle-release-followup/tools/b3sum
