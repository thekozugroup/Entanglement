"""Stage checksum-pinned WASI fixtures for the official release catalog test."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["ENTANGLE_PORTABLE_CATALOG_SOURCE"])
lock = json.loads(Path(os.environ["ENTANGLE_PORTABLE_CATALOG_FIXTURES"]).read_text())
args = sys.argv[1:]
assert len(args) == 9
assert args[:6] == ["build", "--locked", "--release", "--target", "wasm32-wasip2", "--manifest-path"]
assert args[7:] == ["--target-dir", str(root / "target/catalog-smoke")]
project = Path(args[6]).parent
name = project.name
assert Path(args[6]) == root / "plugins" / name / "Cargo.toml"
row = lock[name]
assert hashlib.sha256(Path(args[6]).read_bytes()).hexdigest() == row["manifest_sha256"]
assert hashlib.sha256((project / "Cargo.lock").read_bytes()).hexdigest() == row["lock_sha256"]
component = Path(row["input"])
data = component.read_bytes()
assert data[:8] == b"\0asm\x0d\0\x01\0"
assert len(data) == row["archive_bytes"]
assert hashlib.sha256(data).hexdigest() == row["wasm_sha256"]
staged = root / "target/catalog-smoke/wasm32-wasip2/release" / component.name
staged.parent.mkdir(parents=True, exist_ok=True)
with staged.open("xb") as output:
    output.write(data)
with Path(os.environ["ENTANGLE_PORTABLE_CATALOG_STAGING_LOG"]).open("a") as log:
    print(json.dumps({
        "utc": datetime.now(timezone.utc).isoformat(), "plugin": name,
        "fixture_sha256": row["wasm_sha256"], "fixture_bytes": len(data),
        "argv": args, "staged": str(staged), "used_existing_component": True,
    }), file=log)
