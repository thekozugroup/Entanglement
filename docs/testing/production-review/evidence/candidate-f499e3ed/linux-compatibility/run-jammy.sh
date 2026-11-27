#!/bin/sh
set -eu
candidate=f499e3edf84e20f550312d05df51b9ea4e7cc699
source_id=sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa
cd /workspace/Entanglement
proof=docs/testing/production-review/evidence/candidate-f499e3ed/linux-compatibility
work="$proof/jammy-build"
python3 -B "$work/check-jammy.py" --commit "$candidate" --source-id "$source_id" --out "$work/jammy-build-feasibility.json"
python3 -B "$work/probe-jammy-tmpfs.py" --commit "$candidate" --source-id "$source_id" --out "$work"
python3 -B "$work/stage-jammy.py" --commit "$candidate" --source-id "$source_id" --out "$work"
python3 -B "$work/stage-jammy-archive-tools.py" --out "$work"
python3 -B "$work/portable-jammy.py" --repo . --out "$work" --commit "$candidate" --source-id "$source_id" \
    --b3sum /tmp/entangle-release-followup/tools/b3sum
mkdir "$proof/jammy-userspaces"
python3 -B "$proof/portable-smoke.py" --out "$proof/jammy-userspaces"
