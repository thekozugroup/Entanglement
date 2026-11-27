#!/usr/bin/env python3
"""Replay the signed-package incident exercise with final archive binaries."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path("/workspace/Entanglement")
TEMPLATE = ROOT / ("docs/testing/production-review/evidence/candidate-864ae27b/"
                   "publisher-rotation-rehearsal.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    archive = args.archive.resolve(strict=True)
    label = archive.name.removesuffix(".tar.gz")
    receipt = json.loads(archive.with_name("verification.json").read_text())
    assert receipt["source_id"] == receipt["source_after"] == args.source_id
    assert receipt["name"] == archive.name
    with archive.open("rb") as data:
        assert hashlib.file_digest(data, "sha256").hexdigest() == receipt["sha256"]
    with tempfile.TemporaryDirectory(prefix="ent-successor-incident-", dir="/tmp") as tmp:
        stage = Path(tmp)
        subprocess.run(["tar", "-xzf", archive, "-C", stage], cwd=ROOT, check=True)
        binaries = stage / label
        for name in ("entangle", "entangled"):
            with (binaries / name).open("rb") as data:
                assert hashlib.file_digest(data, "sha256").hexdigest() == receipt["files_sha256"][name]
        driver = TEMPLATE.read_text()
        anchor = "        cli(primary,'plugins','unload',old_id)"
        assert driver.count(anchor) == 1
        driver = driver.replace(anchor, """        assert old_id in cli(primary,'plugins','list','--json')
        signed_hash = hashlib.sha256((old/'plugin.wasm').read_bytes()).hexdigest()
        cli(primary,'plugins','unload',old_id)
        assert old_id not in cli(primary,'plugins','list','--json')
        cli(primary,'plugins','invoke',old_id,'--input','after-unload',error='not loaded')
        assert hashlib.sha256((old/'plugin.wasm').read_bytes()).hexdigest() == signed_hash
        record('Unload blocks invocation; signed bytes are retained', retained_component_sha256=signed_hash)""")
        namespace = {"__name__": "incident_template", "__file__": str(TEMPLATE)}
        exec(compile(driver, str(TEMPLATE), "exec"), namespace)
        namespace["BIN"] = binaries
        namespace["SOURCE"] = args.source_id
        assert namespace["source_id"]() == args.source_id
        sessions = stage / "profiles"
        sessions.mkdir()
        steps = namespace["exercise"](sessions)
        assert namespace["source_id"]() == args.source_id
        print(json.dumps({"source_id": args.source_id, "source_after": args.source_id,
                          "release_archive_sha256": receipt["sha256"],
                          "binary_sha256": {key: receipt["files_sha256"][key] for key in ("entangle", "entangled")},
                          "template_sha256": hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
                          "scope": "same-host Linux publisher containment rehearsal, disposable identities, no external messages",
                          "actions": steps}, indent=2))


if __name__ == "__main__":
    main()
