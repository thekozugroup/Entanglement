#!/usr/bin/env python3
"""Recover a stopped worker into a fresh home, then dispatch over its existing paired route."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import tomllib

REPO = Path(__file__).resolve().parents[2]


def check(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=REPO / "target/debug")
    bins = parser.parse_args().bin_dir.resolve()
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="ent-recover-") as work:
        base = Path(work)
        old, peer, new = (base / x for x in ("source", "peer", "fresh"))
        for home in (old, peer, new):
            home.mkdir(mode=0o700)
        archive = base / "node.enc"
        passphrase = secrets.token_urlsafe(32).encode() + b"\n"

        def env(home):
            return {**os.environ, "HOME": str(home), "TOKIO_WORKER_THREADS": "2", "RAYON_NUM_THREADS": "2", "ENTANGLE_ALLOW_LOCAL": "0"}

        def cli(home, *args, secret=None, success=True):
            res = subprocess.run([bins / "entangle", *args], input=secret if secret is not None else b"",
                                 env=env(home), capture_output=True, timeout=60)
            if success is not None:
                check((res.returncode == 0) == success, f"{args}: {res.stderr.decode()}")
            return res

        @contextlib.contextmanager
        def daemon(home):
            with (home / "daemon.log").open("ab") as log:
                proc = subprocess.Popen([bins / "entangled", "run"], env=env(home), stdout=log, stderr=log)
            try:
                until = time.monotonic() + 15
                while time.monotonic() < until:
                    check(proc.poll() is None, "daemon exited: " + (home / "daemon.log").read_text()[-1000:])
                    status = cli(home, "mesh", "status", "--json", success=None)
                    if status.returncode == 0:
                        check(json.loads(status.stdout)["transports_active"] == ["iroh"], "missing iroh")
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError("daemon startup timed out")
                yield json.loads(status.stdout)["local_peer_id"]
            finally:
                if proc.poll() is None:
                    proc.terminate()
                proc.wait(timeout=10)

        pubs, ids = {}, {}
        for home in (old, peer):
            cli(home, "init", "--non-interactive")
            state = home / ".entangle"
            pubs[home] = subprocess.check_output(["openssl", "pkey", "-in", state / "identity.key",
                                                  "-pubout", "-outform", "DER"], timeout=10)[-32:].hex()
            cli(home, "keyring", "add", pubs[home], "--name", "recovery test publisher")
            ids[home] = tomllib.loads((state / "keyring.toml").read_text())["entries"][0]["fingerprint"]
        for home, other in ((old, peer), (peer, old)):
            cli(home, "mesh", "trust", ids[other], "--public-key-hex", pubs[other], "--display-name", "paired node")

        state = old / ".entangle"
        package = state / "plugins/hello"
        package.parent.mkdir()
        cli(old, "plugins", "build", str(REPO / "examples/hello-world"),
            "--wasm", str(REPO / "crates/entangle-host/tests/fixtures/hello-pong.wasm"), "--out", str(package))
        plugin = tomllib.loads((package / "entangle.toml").read_text())["plugin"]["id"]
        sentinel = secrets.token_bytes(32)
        (state / "data").mkdir()
        (state / "data/sentinel").write_bytes(sentinel)
        ledger = state / "data/bridge.toml"
        cli(old, "mesh", "bridge", "init", str(ledger))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            addr = f"127.0.0.1:{sock.getsockname()[1]}"
        mesh = '[mesh]\ntransports=["iroh"]\nmulti_node=true\n[scheduler]\nrelay=false\n'
        alias = base / "source-home-alias"
        alias.symlink_to(old, target_is_directory=True)
        configured_package = alias / ".entangle/plugins/hello"
        (state / "config.toml").write_text(mesh + f'bind="{addr}"\n[runtime]\nplugins={json.dumps([str(configured_package)])}\n[mesh.bridge]\nreceive=true\nledger={json.dumps(str(ledger))}\n')
        (peer / ".entangle/config.toml").write_text(mesh + f'bind="127.0.0.1:0"\npeers=["{pubs[old]}@{addr}"]\n')

        def dispatch():
            nonce = secrets.token_hex(16)
            out = base / nonce
            deadline = time.monotonic() + 45
            while True:
                res = cli(peer, "compute", "dispatch", plugin, "--cpu-cores", "0.01", "--input", nonce,
                          "--output-file", str(out), success=None)
                if res.returncode == 0:
                    check(ids[old].encode() in res.stdout + res.stderr, "unexpected executor")
                    check(out.read_text() == f"Hello, {nonce}!", "wrong signed plugin output")
                    break
                check(time.monotonic() < deadline, res.stderr.decode())
                time.sleep(.2)

        with daemon(peer):
            with daemon(old) as before:
                check(before == ids[old], "original worker identity")
                dispatch()
                blocked = cli(old, "backup", "--to", str(archive), "--passphrase-stdin", secret=passphrase, success=False)
                check(b"stop the daemon" in blocked.stderr and not archive.exists(), "live backup was permitted")

            cli(old, "backup", "--to", str(archive), "--passphrase-stdin", secret=passphrase)
            alias.unlink()
            check(archive.stat().st_mode & 0o777 == 0o600, "backup file was not private")
            check(sentinel not in archive.read_bytes() and b"BEGIN PRIVATE KEY" not in archive.read_bytes(), "plaintext in backup")
            cli(old, "backup", "--to", str(archive), "--passphrase-stdin", secret=passphrase, success=False)
            tampered = base / "damaged.enc"
            data = bytearray(archive.read_bytes())
            data[-20] ^= 0x80
            tampered.write_bytes(data)
            for source, secret in ((archive, b"wrong\n"), (tampered, passphrase)):
                rejected = cli(new, "restore", "--from", str(source), "--passphrase-stdin", secret=secret, success=False)
                check(b"authentication failed" in rejected.stderr and not list(new.iterdir()), "failed restore published state")
            cli(new, "restore", "--from", str(archive), "--passphrase-stdin", secret=passphrase)
            recovered = new / ".entangle"
            check(recovered.stat().st_mode & 0o777 == 0o700, "recovered home permissions")
            for name in ("identity.key", "keyring.toml", "peers.toml", "plugins/hello/plugin.wasm.sig"):
                check((recovered / name).read_bytes() == (state / name).read_bytes(), f"lost {name}")
                check((recovered / name).stat().st_mode & 0o777 == 0o600, f"permissions of {name}")
            check((recovered / "data/sentinel").read_bytes() == sentinel, "lost plugin state")
            restored_ledger = Path(tomllib.loads((recovered / "config.toml").read_text())["mesh"]["bridge"]["ledger"])
            check(restored_ledger == recovered.resolve() / "data/bridge.toml" and restored_ledger.read_bytes() == ledger.read_bytes(), "relay ledger lost or linked to old node")
            check(not (recovered / "sock.lock").exists(), "runtime lock was copied")
            cli(new, "restore", "--from", str(archive), "--passphrase-stdin", secret=passphrase, success=False)
            with daemon(new) as after:
                check(after == before, "restored peer identity changed")
                dispatch()
                cli(new, "mesh", "revoke", ids[peer])
                denied = cli(peer, "compute", "dispatch", plugin, "--cpu-cores", ".01", "--input", "denied", success=False)
                check(b"not-authorized" in denied.stderr, "restored worker did not enforce pairing revocation")
        print(f"Recovered peer {before}. Signed plugin ran before and after relocation. Existing peer revocation enforced.")


if __name__ == "__main__":
    main()
