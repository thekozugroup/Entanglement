"""Run a local RPC through the installed Linux archive pair."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shlex
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[5]
EVIDENCE = Path(__file__).resolve().parent
FIXTURE = EVIDENCE / "installer-fixture.py"
COMMIT = "1a772db2e69b03e51dc1c03db6feeba28dd234ae"
SOURCE = "sha256:f2bf0e3c6eabe047696aee6c833420333ad951300e82f5f3b0f95281707b19be"
ARCHIVE = ROOT / "target/release-candidate/1a772db2e69b/entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stamp():
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source = subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"],
                                     cwd=ROOT, text=True).strip()
    assert (commit, source) == (COMMIT, SOURCE), (commit, source)
    return source


def exercise():
    manifest = json.loads(ARCHIVE.with_name("verification.json").read_text())
    assert manifest["source_id"] == manifest["source_after"] == SOURCE and manifest["source_commit"] == COMMIT
    assert manifest["name"] == ARCHIVE.name and manifest["sha256"] == sha(ARCHIVE)
    assert sha(FIXTURE) == "9c8a73a97d4af293359a4bbf41fe664cc9316e57728b76af9de769f7f3777395"
    print(f"verified archive SHA-256 {manifest['sha256']}, POSIX installer fixture SHA-256 {sha(FIXTURE)}")
    installer = runpy.run_path(FIXTURE)
    with tempfile.TemporaryDirectory(prefix="ent-install-uds-", dir="/tmp") as td:
        path = Path(td) / "native"
        installer["case"](path, ROOT / "scripts/install.sh", "linux", "x86_64",
                          "x86_64-unknown-linux-gnu", "sha256sum", "v0.1.0", "positive", ARCHIVE)
        profile = path / "home"
        installed = profile / "install/bin"
        env = {**os.environ, "HOME": str(profile), "TOKIO_WORKER_THREADS": "2", "RAYON_NUM_THREADS": "2"}
        env.pop("ENTANGLE_ALLOW_LOCAL", None)
        for binary in ("entangle", "entangled"):
            assert sha(installed / binary) == manifest["files_sha256"][binary]

        def cli(*args):
            cmd = [str(installed / "entangle"), *args]
            print(shlex.join(cmd), flush=True)
            result = subprocess.run(cmd, env=env, cwd=ROOT, timeout=10, check=True, capture_output=True, text=True)
            print(f"exit {result.returncode}")
            return result.stdout

        cli("init", "--non-interactive")
        state = profile / ".entangle"
        (state / "config.toml").write_text("[mesh]\ntransports = []\n")
        cmd = [str(installed / "entangled"), "run"]
        print(shlex.join(cmd), flush=True)
        with (path / "daemon.log").open("w+") as daemon_log:
            daemon = subprocess.Popen(cmd, env=env, cwd=ROOT, stdout=daemon_log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while not (state / "sock").is_socket():
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.03)
                assert sha(Path(f"/proc/{daemon.pid}/exe")) == manifest["files_sha256"]["entangled"]
                response = json.loads(cli("mesh", "status", "--json"))
                assert re.fullmatch(r"[0-9a-f]{32}", response["local_peer_id"])
                assert response["transports_active"] == []
                assert response["seen_peer_count"] == response["trusted_peer_count"] == 0
                print("Installed binary UDS mesh/status", json.dumps(response))
            finally:
                daemon.terminate()
                try:
                    daemon.wait(10)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()
                    raise
            assert daemon.returncode == 0, daemon_log.read_text()
            print(f"installed daemon shutdown exit {daemon.returncode}")


if __name__ == "__main__":
    expected = stamp()
    print(f"UTC start {now()}, source {expected}")
    exercise()
    print(f"UTC finish {now()}, source {stamp()}")
