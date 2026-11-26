#!/usr/bin/env python3
"""Exercise publisher trust changes against the production CLI and running daemon."""

import argparse
import os
import subprocess
import tempfile
import time
import tomllib
from pathlib import Path


def exercise(bin_dir, home):
    repo = Path(__file__).resolve().parents[2]
    env = {**os.environ, "HOME": str(home), "TOKIO_WORKER_THREADS": "2"}
    env.pop("ENTANGLE_ALLOW_LOCAL", None)

    def cli(*args, expected_error=None):
        result = subprocess.run(
            [bin_dir / "entangle", *args], env=env, capture_output=True, text=True, timeout=20
        )
        if expected_error is None:
            if result.returncode:
                raise RuntimeError(f"entangle {args[0]} failed: {result.stderr}")
        elif result.returncode == 0 or expected_error not in result.stderr:
            raise RuntimeError(f"expected {expected_error}: exit {result.returncode}, {result.stderr}")
        return result.stdout

    cli("init", "--non-interactive")
    state = home / ".entangle"
    (state / "config.toml").write_text("[mesh]\ntransports = []\n")
    daemon = subprocess.Popen([bin_dir / "entangled", "run"], env=env)
    try:
        deadline = time.monotonic() + 10
        while not (state / "sock").is_socket():
            if daemon.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("daemon did not start")
            time.sleep(0.05)
        cli("plugins", "install", "hello-world", "--catalog", repo / "examples",
            "--wasm", repo / "crates/entangle-host/tests/fixtures/hello-pong.wasm")
        package = state / "plugins/hello-world"
        plugin_id = tomllib.loads((package / "entangle.toml").read_text())["plugin"]["id"]
        if "Hello, publisher!" not in cli("plugins", "invoke", plugin_id, "--input", "publisher"):
            raise RuntimeError("unexpected output from newly trusted plugin")
        cli("plugins", "unload", plugin_id)
        cli("keyring", "remove", plugin_id.split("/")[0])
        cli("plugins", "load", package, expected_error="ENTANGLE-E0101")
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bin_dir", type=Path, help="directory containing entangle and entangled")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir="/tmp") as temp:
        exercise(args.bin_dir.resolve(), Path(temp))
    print("Running daemon accepted the newly trusted publisher and refused a load after removal.")
