#!/usr/bin/env python3
"""Exercise the exact POSIX installer with a candidate's actual Jammy-built archive."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def capture(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--archive-receipt", required=True, type=Path)
    parser.add_argument("--source-id", required=True)
    args = parser.parse_args()
    root = args.repo.resolve(strict=True)
    output = Path(__file__).resolve().parent
    archive = args.archive.resolve(strict=True)

    def source_id():
        return capture("python3", "scripts/production_score.py", "--source-id", cwd=root)

    before = source_id()
    assert before == args.source_id
    commit = capture("git", "rev-parse", "HEAD", cwd=root)
    receipt = json.loads(args.archive_receipt.read_text())
    assert receipt["source_commit"] == commit
    assert receipt["source_before"] == receipt["source_after"] == before
    assert archive.name == receipt["name"] and archive.stat().st_size == receipt["size"]
    archive_hash = sha(archive)
    assert archive_hash == receipt["sha256"]
    sidecar = archive.with_name(archive.name + ".sha256")
    sidecar_hash = sha(sidecar)
    assert sidecar.read_text().split() == [archive_hash, archive.name]

    name = re.fullmatch(
        r"entanglement-(v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9_.-]+)?)-x86_64-unknown-linux-gnu\.tar\.gz",
        archive.name,
    )
    assert name is not None
    tag = name[1]
    expected_assets = receipt["files_sha256"]
    stem = archive.name.removesuffix(".tar.gz")
    with tarfile.open(archive, mode="r:gz") as package:
        entries = package.getmembers()
        assert len(entries) == len(expected_assets)
        assert {entry.name for entry in entries} == {f"{stem}/{asset}" for asset in expected_assets}
        for entry in entries:
            assert entry.isfile()
            asset = entry.name.removeprefix(stem + "/")
            with package.extractfile(entry) as data:
                assert hashlib.file_digest(data, "sha256").hexdigest() == expected_assets[asset]

    installer = root / "scripts/install.sh"
    installer_hash = sha(installer)
    assert installer.read_bytes() == subprocess.check_output(
        ["git", "show", f"{commit}:scripts/install.sh"], cwd=root
    )
    docker_security = json.loads(capture("docker", "info", "--format", "{{json .SecurityOptions}}"))
    assert "name=rootless" in docker_security
    results = {}
    with tempfile.TemporaryDirectory(prefix="entangle-install-jammy-", dir="/workspace") as temp:
        mounted = Path(temp)
        mounted.chmod(0o755)
        for src in (archive, sidecar, installer, output / "run-in-container.sh", output / "curl-fixture.sh"):
            dst = mounted / src.name
            shutil.copyfile(src, dst)
            dst.chmod(0o644)
            assert sha(dst) == sha(src)
        for version, libc in (("22.04", "2.35"), ("24.04", "2.39")):
            image = capture("docker", "image", "inspect", "ubuntu:" + version, "--format", "{{index .RepoDigests 0}}")
            image_id = capture("docker", "image", "inspect", image, "--format", "{{.Id}}")
            assert source_id() == before
            cmd = [
                "docker", "run", "--rm", "--pull", "never", "--network", "none",
                "--read-only", "--security-opt", "no-new-privileges", "--platform", "linux/amd64",
                "--user", "65534:65534", "--tmpfs", "/tmp:rw,nosuid,nodev,exec,mode=1777",
                "--mount", f"type=bind,src={mounted},dst=/fixture,readonly", image,
                "/bin/sh", "/fixture/run-in-container.sh", version, tag, archive.name,
                expected_assets["entangle"], expected_assets["entangled"],
            ]
            log = output / f"ubuntu-{version}-installer.log"
            start = stamp()
            with log.open("x") as file:
                print(shlex.join(cmd), file=file, flush=True)
                process = subprocess.run(cmd, stdout=file, stderr=subprocess.STDOUT, timeout=120)
            done = stamp()
            content = log.read_text()
            result = {
                "image": image,
                "image_id": image_id,
                "command": shlex.join(cmd),
                "exit_code": process.returncode,
                "assertions_passed": process.returncode == 0 and "Both archive-integrity checks passed." in content
                and re.search(rf"^ldd \(Ubuntu GLIBC .+\) {re.escape(libc)}$", content, re.MULTILINE) is not None,
                "source_before": before,
                "source_after": source_id(),
                "started_at_utc": start,
                "finished_at_utc": done,
                "log": log.name,
                "log_sha256": sha(log),
            }
            results[version] = result

    after = source_id()
    assert before == after and sha(archive) == archive_hash and sha(sidecar) == sidecar_hash
    overall = int(not all(result["assertions_passed"] and result["source_after"] == before for result in results.values()))
    result = {
        "source_commit": commit,
        "source_before": before,
        "source_after": after,
        "archive": str(archive),
        "archive_sha256": archive_hash,
        "archive_receipt_sha256": sha(args.archive_receipt),
        "checksum_sidecar_sha256": sidecar_hash,
        "installer_sha256": installer_hash,
        "runner_sha256": sha(output / "run-in-container.sh"),
        "fixture_transport_sha256": sha(output / "curl-fixture.sh"),
        "installed_asset_sha256": {name: expected_assets[name] for name in ("entangle", "entangled")},
        "docker_security": docker_security,
        "scope": "The actual Jammy-built Linux x86_64 release archive was supplied by an offline URL fixture to the candidate POSIX installer. The official release checksum comparison, no-install on corrupt bytes, extracted ELF hashes and executables running in two Ubuntu userspaces were exercised without a hosted job.",
        "results": results,
        "exit_code": overall,
    }
    (output / "jammy-posix-installer.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"archive_sha256": archive_hash, "exit_code": overall, "source_after": after}))
    return overall


if __name__ == "__main__":
    raise SystemExit(main())
