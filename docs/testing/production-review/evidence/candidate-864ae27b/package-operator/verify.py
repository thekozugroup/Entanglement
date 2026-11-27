#!/usr/bin/env python3
"""Capture a final-source cargo-entangle operator run in the evidence ledger."""
import argparse
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib


def sha(data):
    return hashlib.sha256(data).hexdigest()


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def exercise(run, root, operator, output, source_url, receipt):
    commit = run("Frozen Git commit", "git", "rev-parse", "HEAD").stdout.decode().strip()
    epoch = int(run("Git source timestamp", "git", "show", "-s", "--format=%ct", commit).stdout)
    receipt["commit"] = commit
    for cmd in (["cargo", "-Vv"], ["rustc", "-Vv"], ["git", "--version"], ["zstd", "--version"], ["openssl", "version"]):
        run("Tool version", *cmd)
    with tempfile.TemporaryDirectory(prefix="entangle final signed package ", dir="/tmp") as temp:
        work = Path(temp)
        binaries = work / "candidate binaries"
        binaries.mkdir()
        candidate = binaries / "cargo-entangle"
        shutil.copy2(operator, candidate)
        if sha(candidate.read_bytes()) != receipt["binary_before"]:
            raise ValueError("candidate executable changed while copying")
        env = {**os.environ, "PATH": str(binaries) + os.pathsep + os.environ["PATH"]}

        def cargo(label, *args, **kwargs):
            return run(label, "cargo", "entangle", *args, cwd=work, env=env, **kwargs)

        cargo("Cargo resolves the candidate subcommand", "--version")
        first, alternate = work / "first source checkout", work / "independent rebuild checkout"
        for checkout in (first, alternate):
            run("Clone frozen source", "git", "clone", "--no-local", "--no-checkout", "--", root, checkout, cwd=work)
            run("Check out exact candidate commit", "git", "checkout", "--detach", commit, cwd=checkout)

        key, public = work / "ephemeral publisher.pem", work / "publisher public.pem"
        run("Generate ephemeral fixture publisher", "openssl", "genpkey", "-algorithm", "Ed25519", "-out", key, cwd=work)
        run("Derive fixture verifying key", "openssl", "pkey", "-in", key, "-pubout", "-out", public, cwd=work)
        public_der = run("Read verifying key bytes", "openssl", "pkey", "-pubin", "-in", public, "-outform", "DER", cwd=work, stdout=False).stdout
        assert public_der[:12] == bytes.fromhex("302a300506032b6570032100") and len(public_der) == 44
        public_hex = public_der[12:].hex()

        packages = [work / "first package.tar.zst", work / "second package.tar.zst"]
        project = first / "examples/hello-world"
        for package in packages:
            cargo("Package pinned hello-world source in a clean build", "package", project, "--source-url", source_url, "--key", key, "--out", package)
        archive = packages[0]
        original = archive.read_bytes()
        hashes = [sha(p.read_bytes()) for p in packages]
        assert hashes[0] == hashes[1], "serial package digests differ"
        receipt["serial_archive_sha256"] = hashes

        payload = run("Decompress for archive layout inspection", "zstd", "-dc", "--", archive, cwd=work, stdout=False).stdout
        with tarfile.open(fileobj=BytesIO(payload), mode="r:") as bundle:
            files = bundle.getmembers()
            assert [f.name for f in files] == ["entangle.toml", "plugin.wasm", "plugin.wasm.sig", "rebuild.json"]
            assert all(f.isfile() and f.mtime == f.uid == f.gid == 0 and f.mode == 0o644 for f in files)
            parts = {f.name: bundle.extractfile(f).read() for f in files}
        receipt["archive_entry_sha256"] = {name: sha(data) for name, data in parts.items()}
        manifest = tomllib.loads(parts["entangle.toml"].decode())
        receipt["plugin_id"] = manifest["plugin"]["id"]
        provenance = json.loads(parts["rebuild.json"])
        receipt["provenance"] = provenance
        assert provenance["source_commit"] == commit
        assert provenance["source_date_epoch"] == epoch
        assert provenance["lock_sha256"] == sha((project / "Cargo.lock").read_bytes())
        assert provenance["rust_toolchain"] == "1.91.1" and provenance["zstd_threads"] == 1

        signer = cargo("Sign the compressed archive", "sign", archive, "--key", key)
        assert f"Publisher key: {public_hex}" in signer.stdout.decode()
        detached = archive.with_name(archive.name + ".sig")
        assert len(detached.read_bytes()) == 64
        receipt["detached_signature_sha256"] = sha(detached.read_bytes())
        data = work / "archive digest.bin"
        data.write_bytes(bytes.fromhex(hashes[0]))
        run("Independently verify detached Ed25519 over archive SHA-256", "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", public, "-sigfile", detached, "-rawin", "-in", data, cwd=work)

        keyring = work / "fixture keyring.toml"
        fingerprint = receipt["plugin_id"].split("/", 1)[0]
        keyring.write_text(f'[[entries]]\nfingerprint="{fingerprint}"\npublic_key="{public_hex}"\npublisher_name="Frozen-source fixture"\nadded_at=0\nnote="Ephemeral test publisher"\n', encoding="utf-8")
        verification = ["verify", "--rebuild", archive, "--keyring", keyring]
        result = cargo("Rebuild from an independently checked-out source", *verification, "--source", alternate)
        assert f"PASS: reproduced SHA-256 {hashes[0]}" in result.stdout.decode()
        archive.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        result = cargo("Reject tampering before resolving source", *verification, "--source", work / "nonexistent source", expected=1)
        assert "authenticating the package" in result.stderr.decode()

        # Retain only signed public test material for an independent rebuild.
        fixture = output / "published-fixture"
        fixture.mkdir()
        (fixture / "hello-world-0.1.0.tar.zst").write_bytes(original)
        shutil.copyfile(detached, fixture / "hello-world-0.1.0.tar.zst.sig")
        shutil.copyfile(public, fixture / "test-publisher.pub.pem")
        shutil.copyfile(keyring, fixture / "test-publisher-keyring.toml")
        (fixture / "source.json").write_text(json.dumps({
            "purpose": "test-only reproducibility fixture",
            "git_source_url": source_url,
            "git_source_commit": commit,
            "plugin_project": "examples/hello-world",
            "plugin_id": receipt["plugin_id"],
            "archive_sha256": hashes[0],
            "signature_sha256": receipt["detached_signature_sha256"],
            "test_publisher_public_key_hex": public_hex,
            "locked_fixture_provenance": provenance,
        }, indent=2) + "\n", encoding="utf-8")
        (fixture / "README.md").write_text(
            "# Test-only signed hello-world package\n\n"
            "These artifacts use a disposable test publisher. The public key and dedicated "
            "keyring are provided for this rebuild. `source.json` records the exact Git commit, "
            "source URL, SHA-256 digests and toolchain metadata.\n\n"
            "Run the verifier with the archive and its adjacent detached signature in the same directory.\n\n"
            "```sh\n"
            "cargo entangle verify --rebuild hello-world-0.1.0.tar.zst --keyring test-publisher-keyring.toml\n"
            "```\n",
            encoding="utf-8",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--cargo-entangle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--source-url", required=True)
    args = parser.parse_args()
    root = args.candidate_root.resolve(strict=True)
    path = args.cargo_entangle.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    log = out / "package-operator.log"
    receipt = {
        "command": shlex.join([sys.executable, *sys.argv]),
        "started_at_utc": timestamp(),
        "host": {"kernel": platform.release(), "os": platform.system(), "arch": platform.machine()},
        "binary": str(path),
        "binary_before": sha(path.read_bytes()),
        "candidate_lock_sha256": sha((root / "Cargo.lock").read_bytes()),
        "explicit_env": {k: os.environ.get(k) for k in ("CARGO_HOME", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN")},
        "stages": [],
    }
    with log.open("x", encoding="utf-8") as evidence:
        def run(label, *argv, cwd=root, env=None, expected=0, stdout=True):
            argv = list(map(str, argv))
            evidence.write(f"\n[{timestamp()}] {label}\n  cwd = {cwd}\n  $ {shlex.join(argv)}\n")
            evidence.flush()
            result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=480)
            if stdout:
                evidence.write(result.stdout.decode("utf-8", "replace"))
            evidence.write(result.stderr.decode("utf-8", "replace"))
            evidence.write(f"\n  exit = {result.returncode}\n")
            evidence.flush()
            receipt["stages"].append({"name": label, "argv": argv, "cwd": str(cwd), "exit_code": result.returncode})
            if result.returncode != expected:
                raise RuntimeError(f"{label}: exit {result.returncode}, expected {expected}")
            return result

        def watermark(label):
            return run(label, sys.executable, "scripts/production_score.py", "--source-id").stdout.decode().strip()

        status = 1
        try:
            receipt["source_before"] = watermark("Source before the suite")
            if receipt["source_before"] != args.expected_source:
                raise RuntimeError("source differs from the announced freeze")
            exercise(run, root, path, out, args.source_url, receipt)
            status = 0
        except (ValueError, AssertionError, OSError, RuntimeError, subprocess.SubprocessError) as error:
            evidence.write(f"\nFAIL: {error!r}\n")
        finally:
            receipt["source_after"] = watermark("Source after the suite")
            receipt["binary_after"] = sha(path.read_bytes())
            receipt["source_matches"] = receipt.get("source_before") == receipt["source_after"] == args.expected_source
            receipt["binary_matches"] = receipt["binary_after"] == receipt["binary_before"]
            if not receipt["source_matches"] or not receipt["binary_matches"]:
                status = 1
            evidence.write(f"\nSource stable = {receipt['source_matches']}\nBinary stable = {receipt['binary_matches']}\nSuite exit = {status}\n")
    receipt.update(path=str(log.relative_to(root)), sha256=sha(log.read_bytes()), source_id=receipt.get("source_before"), exit_code=status, observed_at_utc=timestamp(), claim="Linux serial reproducibility and authenticated rebuild from an independent checkout with the final candidate operator binary and Git commit.")
    (out / "package-operator.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: receipt.get(k) for k in ("path", "exit_code", "source_id", "source_matches", "commit", "serial_archive_sha256")}, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
