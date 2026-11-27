#!/usr/bin/env python3
"""Exercise release tier policy boundaries with isolated, signed fixtures."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import shlex
import subprocess
import sys
import tempfile
import time
import tomllib


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def capture_source(root):
    return subprocess.check_output(
        [sys.executable, "scripts/production_score.py", "--source-id"], cwd=root, text=True
    ).strip()


def exercise(root, bins, run, audit_out, record):
    wasm = root / "crates/entangle-host/tests/fixtures/hello-pong.wasm"
    elf = Path("/usr/bin/true").resolve(strict=True)
    assert wasm.read_bytes().startswith(b"\0asm\x0d\0\x01\0")
    assert elf.read_bytes().startswith(b"\x7fELF")
    record["fixture_sha256"] = {str(path): sha(path) for path in [wasm, elf]}

    with tempfile.TemporaryDirectory(dir="/tmp", prefix="ent-tier-policy-") as directory:
        home = Path(directory)
        env = {**os.environ, "HOME": directory, "TOKIO_WORKER_THREADS": "2", "RUST_LOG": "entangle::audit=info"}
        env.pop("ENTANGLE_ALLOW_LOCAL", None)

        def cli(*args, **kwargs):
            return run(bins / "entangle", *args, env=env, **kwargs)

        cli("init", "--non-interactive")
        state = home / ".entangle"
        der = run("openssl", "pkey", "-in", state / "identity.key", "-pubout", "-outform", "DER", binary=True).stdout
        assert der.startswith(bytes.fromhex("302a300506032b6570032100")) and len(der) == 44
        cli("keyring", "add", der[-32:].hex(), "--name", "Tier policy conformance publisher")

        def template(name, tier, runtime):
            source = home / f"{name}-input"
            source.mkdir()
            (source / "entangle.toml").write_text(
                f'[plugin]\nid="PUBLISHER_PLACEHOLDER/{name}@0.1.0"\nversion="0.1.0"\n'
                f'tier={tier}\nruntime="{runtime}"\n[capabilities]\n"compute.cpu" = {{}}\n',
                encoding="utf-8",
            )
            return source

        def package(name, tier, runtime, artifact):
            dest = home / name
            cli("plugins", "build", template(name, tier, runtime), "--wasm", artifact, "--out", dest)
            manifest = tomllib.loads((dest / "entangle.toml").read_text())
            assert manifest["plugin"]["tier"] == tier and manifest["plugin"]["runtime"] == runtime
            assert set(manifest["capabilities"]) == {"compute.cpu"}
            assert sha(dest / "plugin.wasm") == sha(artifact)
            assert (dest / "plugin.wasm.sig").is_file()
            return dest, manifest["plugin"]["id"]

        refused_wasm = home / "wasm-tier-five-incompatible"
        rejected = cli(
            "plugins", "build", template(refused_wasm.name, 5, "wasm"), "--wasm", wasm,
            "--out", refused_wasm, expected=1,
        )
        assert "runtime 'Wasm' incompatible with tier Native" in rejected.stderr
        assert not refused_wasm.exists(), "packaging must reject before creating a signed Wasm bundle"

        survivor, survivor_id = package("wasm-tier-three-survivor", 3, "wasm", wasm)
        native, native_id = package("native-elf-rejection-fixture", 5, "native", elf)
        record["fixtures"] = {
            "survivor": {"id": survivor_id, "tier": 3, "runtime": "wasm", "capabilities": ["compute.cpu"]},
            "native": {"id": native_id, "tier": 5, "runtime": "native", "capabilities": ["compute.cpu"], "executed": False},
        }
        config = state / "config.toml"
        initial = '# isolated policy candidate\n[mesh]\ntransports=[]\n[security]\nmax_tier_allowed=5\n'
        initial += f'[runtime]\nplugins=[{json.dumps(str(survivor))}]\n'
        config.write_text(initial, encoding="utf-8")

        daemon_cmd = [bins / "entangled", "run"]
        audit_out.write(f"$ {shlex.join(map(str, daemon_cmd))}\n")
        audit_out.flush()
        daemon = subprocess.Popen(daemon_cmd, env=env, stdout=audit_out, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while not (state / "sock").is_socket():
                assert daemon.poll() is None and time.monotonic() < deadline, "daemon failed to start"
                time.sleep(0.05)
            assert daemon.poll() is None

            def survivor_works():
                inventory = cli("plugins", "list").stdout
                assert survivor_id in inventory and native_id not in inventory
                out = cli("plugins", "invoke", survivor_id, "--input", "survivor", "--raw").stdout
                assert out == "Hello, survivor!"

            survivor_works()
            rejected = cli("plugins", "load", native, expected=1)
            assert "requires a sandboxed native runner" in rejected.stderr
            blob = native / "plugin.wasm"
            original = blob.read_bytes()
            try:
                blob.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                rejected = cli("plugins", "load", native, expected=1)
                assert "ENTANGLE-E0102" in rejected.stderr
            finally:
                blob.write_bytes(original)

            config.write_text(initial.replace("max_tier_allowed=5", "max_tier_allowed=3"), encoding="utf-8")
            reload = cli("config", "reload", terminal=True)
            assert "Applied max_tier_allowed = 3." in reload.stdout
            assert "Decision [u]" not in reload.stdout and "affects" not in reload.stdout
            assert tomllib.loads(config.read_text())["security"]["max_tier_allowed"] == 3
            survivor_works()
            rejected = cli("plugins", "load", native, expected=1)
            assert "ENTANGLE-E0043" in rejected.stderr

            cli("security", "set-max-tier", "5")
            force = cli("security", "set-max-tier", "3", "--force-unload")
            assert "Applied max_tier_allowed = 3." in force.stdout
            assert "affects" not in force.stderr and survivor_id not in force.stderr
            assert tomllib.loads(config.read_text())["security"]["max_tier_allowed"] == 3
            survivor_works()
        finally:
            daemon.terminate()
            try:
                record["daemon_exit"] = daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()
                record["daemon_exit"] = daemon.wait(timeout=5)

    audit_out.flush()
    audit = Path(audit_out.name).read_text(encoding="utf-8")
    events = [json.loads(line).get("fields", {}) for line in audit.splitlines() if line.startswith("{")]
    lowers = [e for e in events if e.get("code") == "ENTANGLE-I0215" and e.get("previous") == "tier-5" and e.get("proposed") == "tier-3"]
    assert len(lowers) == 2
    assert not any(e.get("code") in ("ENTANGLE-W0214", "ENTANGLE-I0216") for e in events)
    record["exact_5_to_3"] = {"applied_transitions": len(lowers), "loaded_survivor": True, "affected": 0, "cancel_prompt_reachable": False}
    reduced = run(sys.executable, root / "scripts/tests/max-tier.py", "--bin-dir", bins, timeout=90)
    record["affected_set_5_to_2"] = json.loads(reduced.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    bins = args.bin_dir.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    log = out / "policy-boundary.log"
    audit = out / "daemon-audit.log"
    reference = json.loads(args.reference.read_text())
    record = {
        "command": shlex.join([sys.executable, *sys.argv]),
        "started_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "release_source_commit": reference["source_commit"],
        "source_before": capture_source(root),
        "binary_hashes_before": {name: sha(bins / name) for name in ("entangle", "entangled")},
        "host": {"os": platform.system(), "kernel": platform.release(), "arch": platform.machine()},
        "commands": [],
    }
    status = 1
    with log.open("x", encoding="utf-8") as evidence, audit.open("x", encoding="utf-8") as audit_out:
        def run(*args, env=None, expected=0, binary=False, terminal=False, timeout=20):
            cmd = list(map(str, args))
            evidence.write(f"\n$ {shlex.join(cmd)}\nPTY stdin = {terminal}\n")
            evidence.flush()
            descriptors = pty.openpty() if terminal else None
            try:
                result = subprocess.run(
                    cmd, cwd=root, env=env, capture_output=True, text=not binary,
                    stdin=descriptors[1] if descriptors else subprocess.DEVNULL, timeout=timeout,
                )
            finally:
                if descriptors:
                    for fd in descriptors:
                        os.close(fd)
            evidence.write(f"Exit = {result.returncode}\n")
            if binary:
                evidence.write(f"Binary stdout length = {len(result.stdout)}\n")
                evidence.write(result.stderr.decode("utf-8", "replace"))
            else:
                evidence.write(f"STDOUT\n{result.stdout}\nSTDERR\n{result.stderr}\n")
            evidence.flush()
            record["commands"].append({"argv": cmd, "exit_code": result.returncode, "pty_stdin": terminal, "expected_exit": expected})
            if result.returncode != expected:
                raise ValueError(f"unexpected exit from {shlex.join(cmd)}")
            return result

        try:
            assert record["source_before"] == reference["source_id"], "source watermark differs from release evidence"
            assert record["binary_hashes_before"] == reference["binary_sha256"], "binary hashes differ from release evidence"
            exercise(root, bins, run, audit_out, record)
            status = 0
        except (AssertionError, ValueError, OSError, subprocess.SubprocessError) as error:
            evidence.write(f"\nFAIL {error!r}\n")
        finally:
            record["source_after"] = capture_source(root)
            record["binary_hashes_after"] = {name: sha(bins / name) for name in ("entangle", "entangled")}
            if record["source_before"] != record["source_after"] or record["binary_hashes_before"] != record["binary_hashes_after"]:
                status = 1
            evidence.write(f"\nSource before = {record['source_before']}\nSource after = {record['source_after']}\nSuite exit = {status}\n")
    record.update(
        evidence_type="policy conformance",
        assessment="The current package validator rejects tier-5 Wasm. A genuine signed ELF is also refused at native runtime admission. The literal loaded native agent-host prerequisite for ATC-MAX-1-3 remains unmet.",
        source_id=record["source_before"],
        observed_at_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        exit_code=status,
        path=str(log.relative_to(root)),
        sha256=sha(log),
        audit_path=str(audit.relative_to(root)),
        audit_sha256=sha(audit),
    )
    (out / "receipt.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: record.get(key) for key in ("path", "exit_code", "source_id", "exact_5_to_3", "affected_set_5_to_2")}, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
