#!/usr/bin/env python3
"""Exercise interactive, scripted and stale tier decisions against a running daemon."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import socket
import subprocess
import tempfile
import time
import tomllib

REPO = Path(__file__).resolve().parents[2]


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin-dir", type=Path, default=REPO / "target/debug")
    bins = ap.parse_args().bin_dir.resolve()
    wasm = REPO / "crates/entangle-host/tests/fixtures/hello-pong.wasm"
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="ent-tier-") as tmp:
        home = Path(tmp)
        env = {**os.environ, "HOME": tmp, "TOKIO_WORKER_THREADS": "2", "RUST_LOG": "entangle::audit=info"}
        def cli(*args, expect=True, decision=None):
            if decision is None:
                r = subprocess.run([bins / "entangle", *args], env=env, stdin=subprocess.DEVNULL,
                                   capture_output=True, text=True, timeout=20)
            else:
                master, slave = pty.openpty()
                try:
                    with subprocess.Popen([bins / "entangle", *args], env=env, stdin=slave,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
                        os.write(master, (decision + "\n").encode())
                        stdout, stderr = process.communicate(timeout=20)
                        r = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
                finally:
                    os.close(master)
                    os.close(slave)
            check((r.returncode == 0) == expect, f"{args}: {r.stdout} {r.stderr}")
            return r

        def rpc(method, params):
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(5)
                sock.connect(str(home / ".entangle/sock"))
                sock.sendall(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
                with sock.makefile("rb") as stream:
                    return json.loads(stream.readline(1024 * 1024))

        cli("init", "--non-interactive")
        state = home / ".entangle"
        pub = subprocess.check_output(["openssl", "pkey", "-in", state / "identity.key",
                                      "-pubout", "-outform", "DER"], timeout=5)[-32:].hex()
        cli("keyring", "add", pub, "--name", "tier test publisher")
        packages = []
        ids = []
        for name in ("doc-index", "image-worker"):
            template = home / (name + "-source")
            template.mkdir()
            (template / "entangle.toml").write_text(
                f'[plugin]\nid="PUBLISHER_PLACEHOLDER/{name}@0.1.0"\nversion="0.1.0"\ntier=3\nruntime="wasm"\n')
            package = home / name
            cli("plugins", "build", str(template), "--wasm", str(wasm), "--out", str(package))
            packages.append(str(package))
            ids.append(tomllib.loads((package / "entangle.toml").read_text())["plugin"]["id"])
        config = state / "config.toml"
        initial = '# preserved policy comment\n[security]\nmax_tier_allowed = 5\n[runtime]\nplugins = ' + json.dumps(packages) + '\n'
        config.write_text(initial)
        log_file = home / "audit.log"

        def start():
            with log_file.open("ab") as logs:
                proc = subprocess.Popen([bins / "entangled", "run"], env=env, stdout=logs, stderr=logs)
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    check(proc.poll() is None, log_file.read_text())
                    try:
                        if "result" in rpc("version", None):
                            return proc
                    except OSError:
                        pass
                    time.sleep(0.1)
                raise RuntimeError("daemon did not start")
            except BaseException:
                if proc.poll() is None:
                    proc.terminate()
                proc.wait(timeout=10)
                raise

        def stop(proc):
            proc.terminate()
            proc.wait(timeout=10)

        def listed():
            return set(rpc("plugins/list", None)["result"]["plugins"])

        daemon = start()
        try:
            check(listed() == set(ids), "startup inventory")
            config.write_text(initial.replace("= 5", "= 2"))
            cli("config", "validate", expect=False)
            cli("config", "reload", expect=False)
            cancelled = cli("config", "reload", decision="c")
            check(all(i in cancelled.stdout for i in ids), "cancel omitted affected inventory")
            check(config.read_text() == initial and listed() == set(ids), "cancel modified runtime or unrelated config")

            # A concurrent wrapper command must not rewrite an old ceiling, and the daemon
            # must not unload anything while a configuration writer has the reservation.
            fd = os.open(state, os.O_RDONLY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                denied = cli("security", "set-max-tier", "2", "--force-unload", expect=False)
                check("configuration writer busy" in denied.stderr and listed() == set(ids), "tier update did not honor writer reservation")
                blocked = cli("wrapper", "enable", "--shell", "bash", expect=False)
                check("configuration writer busy" in blocked.stderr and not (home / ".bashrc").exists(), "wrapper edited files during reserved tier update")
                check(config.read_text() == initial, "concurrent writer modified config")
            finally:
                os.close(fd)

            approved = rpc("config/tier-policy", {"target": 2, "action": "review"})["result"]
            config.write_text(initial + "# concurrent edit\n")
            denied = rpc("config/tier-policy", {"target": 2, "action": "apply", "approved": approved})
            check("error" in denied and listed() == set(ids), "stale config review was accepted")
            approved = rpc("config/tier-policy", {"target": 2, "action": "review"})["result"]
            cli("plugins", "unload", ids[0])
            cli("plugins", "load", packages[0])
            denied = rpc("config/tier-policy", {"target": 2, "action": "apply", "approved": approved})
            check("error" in denied and listed() == set(ids), "replaced plugin accepted stale review")
            forced = cli("security", "set-max-tier", "2", "--force-unload")
            check(all(i in forced.stderr for i in ids), "force omitted affected inventories on stderr")
            check(not listed(), "forced plugins remain loaded")
            saved = tomllib.loads(config.read_text())
            check(saved["security"]["max_tier_allowed"] == 2, "saved ceiling")
            check(set(saved["runtime"]["disabled_plugins"]) == set(ids), "saved disabled entries")
            check("# concurrent edit" in config.read_text(), "unrelated config edit lost")
            cli("security", "set-max-tier", "5")
            cli("plugins", "load", packages[0], expect=False)
        finally:
            stop(daemon)

        daemon = start()
        try:
            check(not listed(), "disabled plugin loaded on restart")
            config.write_text(initial)
            cli("config", "reload")
            for package in packages:
                cli("plugins", "load", package)
            config.write_text(initial.replace("= 5", "= 2"))
            defaulted = cli("config", "reload", decision="")
            check(all(i in defaulted.stdout for i in ids) and not listed(), "default lowering decision")
        finally:
            stop(daemon)
        events = [json.loads(line) for line in log_file.read_text().splitlines() if line.startswith("{")]
        warnings = [e["fields"] for e in events if e.get("fields", {}).get("code") == "ENTANGLE-W0214"]
        check(len(warnings) == 4 and all(any(i in str(w) for w in warnings) for i in ids), "per-plugin audit")
        check(any(e.get("fields", {}).get("code") == "ENTANGLE-I0216" for e in events), "missing cancel audit")
        print(json.dumps({"interactive_default": "unload-and-disable", "cancel_restored": 5,
                          "forced_plugins": len(ids), "stale_reviews_rejected": 2, "restart_disabled": True}))


if __name__ == "__main__":
    main()
