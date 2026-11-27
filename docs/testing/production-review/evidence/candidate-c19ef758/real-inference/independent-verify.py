#!/usr/bin/env python3
"""Reconstruct the signed inference outputs and verify the frozen run's identity."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EXPECTED_SOURCE = "sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644"
EXPECTED_COMMIT = "c19ef7587a2215ef9434b642413bebd0473caf20"
ENDPOINTS = ("/v1/completions", "/v1/chat/completions")
PROMPTS = (
    "Finish the sequence using five words: winter, spring, summer,",
    "Write one sentence describing a bicycle.",
    "The first three prime numbers are",
)
MODEL_ALIAS = "tinyllama-cpu-review"


def sha_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_group(group, helper, seen):
    endpoint = group["endpoint"]
    assert [row["prompt"] for row in group["samples"]] == list(PROMPTS)
    assert group["coordinator_peer"] != group["worker_peer"]
    for row in group["samples"]:
        task_id = uuid.UUID(row["task_id"])
        assert task_id not in seen
        seen.add(task_id)
        public = bytes.fromhex(row["public_key_hex"])
        peer = subprocess.check_output([helper], input=public.hex(), text=True, timeout=5).strip()
        assert peer == row["executor"] == group["worker_peer"]
        key = Ed25519PublicKey.from_public_bytes(public)
        output, received = bytearray(), []
        for index, chunk in enumerate(row["chunks"]):
            assert chunk["seq"] == index and chunk["timestamp_ms"] > 0
            payload = bytes.fromhex(chunk["payload_hex"])
            checksum = hashlib.sha256(payload)
            assert payload and checksum.hexdigest() == chunk["sha256"]
            message = (b"entangle/stream/chunk/1\x00" + task_id.bytes
                       + index.to_bytes(8, "big") + chunk["timestamp_ms"].to_bytes(8, "big")
                       + checksum.digest())
            key.verify(bytes.fromhex(chunk["signature_hex"]), message)
            output.extend(payload)
            received.append(chunk["received_ms"])
        assert len(received) >= 2 and received == sorted(received)
        assert 0 < received[0] == row["first_signed_chunk_ms"] <= received[-1] <= row["duration_ms"]
        assert output.decode("utf-8") == row["output"] and hashlib.sha256(output).hexdigest() == row["output_sha256"]
        direct = row["direct_response"]
        assert direct["model"] == MODEL_ALIAS
        choice, = direct["choices"]
        text = choice["message"]["content"] if endpoint == "/v1/chat/completions" else choice["text"]
        complete, prompt = direct["usage"]["completion_tokens"], direct["usage"]["prompt_tokens"]
        assert text == output.decode("utf-8") and row["matched_direct_greedy_output"] is True
        assert 0 < complete == row["generated_tokens"] <= 24 and prompt > 0
        assert direct["usage"]["total_tokens"] == prompt + complete
        assert row["end_to_end_tokens_per_second"] == round(1000 * complete / row["duration_ms"], 2)
        yield {"endpoint": endpoint, "peer": peer, "task_id": str(task_id), "prompt": row["prompt"],
               "chunks": len(received), "bytes": len(output), "output_sha256": row["output_sha256"],
               "first_ms": received[0], "duration_ms": row["duration_ms"],
               "completion_tokens": complete, "prompt_tokens": prompt}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--peer-fingerprint", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    path, helper, root = (path.resolve(strict=True) for path in (args.result, args.peer_fingerprint, args.root))
    evidence = path.parent
    result_sha = sha_file(path)
    result = read_json(path)
    started = utc()

    def source():
        return subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"], cwd=root, text=True).strip()

    def executables():
        return {name: sha_file(root / "target/release" / name) for name in ("entangle", "entangled")}

    source_before = source()
    expected_binaries = executables()
    assert source_before == EXPECTED_SOURCE == result["source_id"] == result["source_after"]
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip() == EXPECTED_COMMIT
    archive_path = evidence.parent / "linux-archive.json"
    archive = read_json(archive_path)
    build = read_json(evidence.parent / "release-build.json")
    assert build["exit_code"] == 0 and build["source_id"] == build["source_after"] == EXPECTED_SOURCE
    assert archive["source_commit"] == result["source_commit"] == EXPECTED_COMMIT
    assert archive["source_id"] == archive["source_after"] == EXPECTED_SOURCE
    assert expected_binaries == result["release_binaries_sha256"]
    assert all(digest == archive["files_sha256"][name] for name, digest in expected_binaries.items())
    assert result["driver_sha256"] == sha_file(evidence / "verify.py")

    model = read_json(evidence / "MODEL.json")
    provenance = read_json(evidence / "model-provenance.json")
    assert model["sha256"] == provenance["sha256"] == result["model_sha256"]
    assert model["sizeBytes"] == provenance["bytes"] == result["model_file_bytes"] == 322591712
    assert read_json(evidence / "model-tensor-inspection.json")["parameter_count"] == 1100048384
    server_command = result["server_command"]
    server_path = Path(server_command[0]).resolve(strict=True)
    options = dict(zip(server_command[1::2], server_command[2::2], strict=True))
    assert options["--alias"] == MODEL_ALIAS and options["--host"] == "127.0.0.1"
    assert options["--threads"] == str(result["threads"]) == "2"
    assert options["--n-gpu-layers"] == str(result["gpu_layers"]) == "0"
    assert Path(options["--model"]).stat().st_size == model["sizeBytes"]
    assert sha_file(server_path) == result["server_sha256"]
    assert {name: sha_file(server_path.parent / name) for name in result["server_library_sha256"]} == result["server_library_sha256"]
    backend_log = path.with_suffix(".server.log")
    trace = backend_log.read_text(encoding="utf-8")
    assert f"listening on http://127.0.0.1:{options['--port']}" in trace
    for endpoint in ENDPOINTS:
        assert len(re.findall(rf"(?m)request: POST {re.escape(endpoint)} 127\.0\.0\.1 200$", trace)) == 6

    groups = result["endpoints"]
    assert [group["endpoint"] for group in groups] == list(ENDPOINTS)
    seen = set()
    rows = [row for group in groups for row in verify_group(group, helper, seen)]
    source_after = source()
    assert len(seen) == len(rows) == 6
    assert source_before == source_after and executables() == expected_binaries
    assert sha_file(path) == result_sha
    print(json.dumps({
        "source_id": source_before, "source_after": source_after, "source_commit": EXPECTED_COMMIT,
        "command": shlex.join([sys.executable, *sys.argv]), "exit_code": 0, "started_utc": started, "finished_utc": utc(),
        "result_sha256": result_sha, "server_log_sha256": sha_file(backend_log),
        "verifier_sha256": sha_file(Path(__file__)), "peer_fingerprint_helper_sha256": sha_file(helper),
        "peer_fingerprint_source_sha256": sha_file(evidence / "independent-peer-fingerprint.rs"),
        "release_binaries_sha256": expected_binaries, "release_manifest_sha256": sha_file(archive_path),
        "server_sha256": result["server_sha256"], "server_library_sha256": result["server_library_sha256"],
        "model_sha256": result["model_sha256"], "verified_ed25519_chunks": sum(row["chunks"] for row in rows),
        "verified_direct_completion_tokens": sum(row["completion_tokens"] for row in rows), "samples": rows,
        "host_scope": result["host_scope"],
    }, indent=2))


if __name__ == "__main__":
    main()
