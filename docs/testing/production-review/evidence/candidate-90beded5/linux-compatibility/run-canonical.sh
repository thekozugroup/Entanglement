#!/bin/sh
set -eu
cd /workspace/Entanglement
root=docs/testing/production-review/evidence/candidate-90beded5
evidence="$root/linux-compatibility"
mkdir "$evidence/linux-userspaces"
python3 -B "$evidence/userspaces.py" --repo . --out "$evidence/linux-userspaces" \
    --commit 90beded509f93909507c78f2986dea0e085e4f1e \
    --source-id sha256:f55d4a44e7f128f7e059ecd7c93625be91e7f56484c49f93b7920e9266cf6cbb \
    --archive target/release-candidate/90beded509f9/entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz \
    --archive-receipt "$root/linux-archive.json" \
    --wasm target/catalog-smoke/wasm32-wasip2/release/entangle_json_pointer.wasm \
    --b3sum /tmp/entangle-release-followup/tools/b3sum
