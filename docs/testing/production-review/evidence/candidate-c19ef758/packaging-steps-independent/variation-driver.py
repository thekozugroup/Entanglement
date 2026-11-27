#!/usr/bin/env python3
"""Prepare one controlled metadata variation and run the real packager."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zlib

variant, origin_arg, stage_arg, epoch = sys.argv[1:]
origin, stage = Path(origin_arg), Path(stage_arg)
original = (
    "LICENSE", "README.md", "docs/architecture.md",
    "bin/entangle", "bin/entangled", "docs/tutorial.md",
)
recipe = {
    "a": (original, 1795762259, 0o644, 0o755),
    "b": (original[::-1], 1450000000, 0o600, 0o700),
    "c": (original[3:] + original[:3], 1700000123, 0o640, 0o751),
}
order, mtime, doc_mode, bin_mode = recipe[variant]
(stage / "scripts").mkdir(parents=True)
(stage / "docs").mkdir()
(stage / "bin").mkdir()
helper = stage / "scripts/package-native-release.py"
shutil.copyfile(origin / "scripts/package-native-release.py", helper)
manifest = json.loads((origin / "verification.json").read_text())
files = {}
started = datetime.now(timezone.utc).isoformat()
for index, name in enumerate(order):
    path = stage / name
    shutil.copyfile(origin / name, path)
    path.chmod(bin_mode if name.startswith("bin/") else doc_mode)
    os.utime(path, (mtime + index, mtime + index))
    info = path.stat()
    with path.open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
    assert digest == manifest["files_sha256"][path.name]
    files[name] = {"path": str(path), "uid": info.st_uid, "gid": info.st_gid,
                   "mode": oct(info.st_mode & 0o7777), "mtime_ns": info.st_mtime_ns,
                   "size": info.st_size, "sha256": digest}

output = stage / "out"
command = [sys.executable, "-B", str(helper), "--version", "v0.1.0", "--target",
           "x86_64-unknown-linux-gnu", "--source-date-epoch", epoch,
           "--bin-dir", str(stage / "bin"), "--output-dir", str(output)]
done = subprocess.run(command, check=True, text=True, capture_output=True)
umask = os.umask(0)
os.umask(umask)
print(json.dumps({"variant": variant, "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
                  "source_date_epoch": int(epoch), "command": command, "exit_code": done.returncode,
                  "base_name": done.stdout.strip(), "copy_order": order, "inputs": files,
                  "directory_order": {name: os.listdir(stage / name) for name in ("docs", "bin")},
                  "process_uid": os.getuid(), "process_gid": os.getgid(), "umask": oct(umask),
                  "timezone": os.environ.get("TZ"), "python": sys.version,
                  "zlib": zlib.ZLIB_RUNTIME_VERSION}, indent=2))
