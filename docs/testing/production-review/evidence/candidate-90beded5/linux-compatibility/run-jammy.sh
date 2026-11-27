#!/bin/sh
set -eu
candidate=90beded509f93909507c78f2986dea0e085e4f1e
source_id=sha256:f55d4a44e7f128f7e059ecd7c93625be91e7f56484c49f93b7920e9266cf6cbb
cd /workspace/Entanglement
proof=docs/testing/production-review/evidence/candidate-90beded5/linux-compatibility
work="$proof/jammy-build"
python3 -B "$work/check-jammy.py" --commit "$candidate" --source-id "$source_id" --out "$work/jammy-build-feasibility.json"
python3 -B "$work/probe-jammy-tmpfs.py" --commit "$candidate" --source-id "$source_id" --out "$work"
python3 -B "$work/stage-jammy.py" --commit "$candidate" --source-id "$source_id" --out "$work"
python3 -B "$work/stage-jammy-archive-tools.py" --out "$work"
python3 -B "$work/portable-jammy.py" --repo . --out "$work" --commit "$candidate" --source-id "$source_id" \
    --b3sum /tmp/entangle-release-followup/tools/b3sum
mkdir "$proof/jammy-userspaces"
python3 -B "$proof/portable-smoke.py" --out "$proof/jammy-userspaces"
