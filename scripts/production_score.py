#!/usr/bin/env python3
"""Score a fixed production rubric; evidence credibility needs independent review."""
import argparse
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUBRIC = ROOT / "docs/testing/production-review/rubric-v1.json"
RUBRIC_SHA256 = "d133c5f4f0df318c97080ea923ba65071d5599f05a7e1f1aa37b1fa2b1727322"
EXCLUDED = ("docs/testing/production-review/runs/", "docs/testing/production-review/evidence/")
EXPECTED_METRICS = {"correctness", "authorization_isolation", "reliability", "interoperability", "performance", "release_operations"}
EXPECTED_ATC = {f"ATC-{group}-{n}" for group, count in {"MAN":4, "PKG":4, "BRG":6, "INT":5, "STR":3, "WRP":3, "MAX":3, "MIR":2, "REL":2, "BUS":2}.items() for n in range(1, count + 1)}


def source_id(root=ROOT):
    """Hash tracked and non-ignored untracked inputs; exclude only run artifacts."""
    out = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root)
    paths = sorted(set(out.split(b"\0")) - {b""})
    digest = hashlib.sha256()
    for raw in paths:
        name = raw.decode("utf-8", "surrogateescape")
        if any(name.startswith(prefix) for prefix in EXCLUDED) or "__pycache__" in Path(name).parts:
            continue
        path = root / name
        if path.is_symlink():
            content = b"link\0" + str(path.readlink()).encode()
        elif path.is_file():
            content = (b"executable\0" if path.stat().st_mode & 0o111 else b"file\0") + path.read_bytes()
        else:
            content = b"missing\0"
        digest.update(len(raw).to_bytes(8, "big")); digest.update(raw)
        digest.update(hashlib.sha256(content).digest())
    return "sha256:" + digest.hexdigest()


def review_file(root, check, ref, kind):
    if not isinstance(ref, str) or not ref or Path(ref).is_absolute():
        raise ValueError(f"{check}: {kind} path must be workspace-relative")
    try:
        path = (root / ref).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError(f"{check}: cannot resolve {kind} file {ref!r}") from error
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"{check}: {kind} file missing or outside workspace")
    return path


def validate_receipt(root, check, evidence):
    """Check the execution record when a review cites one alongside its log."""
    path = review_file(root, check, evidence["receipt_path"], "receipt")
    receipt = json.loads(path.read_bytes())
    if not isinstance(receipt, dict) or not (
        receipt.get("source_before") == receipt.get("source_after") == evidence["source_id"]
        and receipt.get("log") == evidence["path"]
        and receipt.get("sha256") == evidence["sha256"]
        and type(receipt.get("exit_code")) is int
        and receipt["exit_code"] == evidence["exit_code"]
    ):
        raise ValueError(f"{check}: receipt disagrees with cited execution or log")
    procedure = receipt.get("command", receipt.get("method"))
    if isinstance(procedure, list) and procedure and all(isinstance(arg, str) for arg in procedure):
        procedure = procedure[0]
    if not isinstance(procedure, str) or not procedure.strip():
        raise ValueError(f"{check}: receipt needs a command or review method")
    times = []
    for key in ("started_utc", "finished_utc"):
        value = receipt.get(key)
        if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
            raise ValueError(f"{check}: receipt needs UTC start and finish times")
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        stamp = datetime.fromisoformat(value)
        if stamp.utcoffset() != timedelta(0):
            raise ValueError(f"{check}: receipt needs UTC start and finish times")
        times.append(stamp)
    if times[0] > times[1]:
        raise ValueError(f"{check}: receipt finishes before it starts")


def score(rubric, run, root=ROOT):
    if rubric != json.loads(RUBRIC.read_text()):
        raise ValueError("rubric must match the frozen file")
    checks = rubric["checks"]
    ids = [item["id"] for item in checks]
    if len(ids) != len(set(ids)) or set(rubric["metrics"]) != EXPECTED_METRICS:
        raise ValueError("rubric contains duplicate checks or incorrect metrics")
    if {item["id"] for item in checks if item["kind"] == "architecture"} != EXPECTED_ATC:
        raise ValueError("rubric must contain exactly the 34 architecture definitions")
    if any(item["metric"] not in EXPECTED_METRICS or item.get("hard_gate") is not True for item in checks):
        raise ValueError("all checks must be assigned to a metric and be mandatory")
    expected_digest = hashlib.sha256(RUBRIC.read_bytes()).hexdigest()
    if expected_digest != RUBRIC_SHA256:
        raise ValueError("frozen rubric bytes changed; define a new version")
    if run.get("rubric_sha256") != expected_digest:
        raise ValueError("run does not match the frozen rubric bytes")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", run.get("source_id", "")):
        raise ValueError("run must identify the exact candidate source snapshot")
    observations = run["observations"]
    if set(observations) != set(ids):
        raise ValueError("run must contain exactly one observation per rubric check")
    counts = {metric: {"pass": 0, "fail": 0, "not_evidenced": 0} for metric in EXPECTED_METRICS}
    blockers = []
    for item in checks:
        observation = observations[item["id"]]
        status = observation.get("status")
        if status not in ("pass", "fail", "not_evidenced"):
            raise ValueError(f"{item['id']}: invalid status")
        if not isinstance(observation.get("reason"), str) or not observation["reason"].strip():
            raise ValueError(f"{item['id']}: a reason is required")
        evidence = observation.get("evidence", [])
        if not isinstance(evidence, list):
            raise ValueError(f"{item['id']}: evidence must be a list")
        if status == "pass":
            if not evidence:
                raise ValueError(f"{item['id']}: pass requires evidence")
            if not observation.get("reviewer") or not observation.get("reviewed_at_utc"):
                raise ValueError(f"{item['id']}: pass requires an attributable review")
        else:
            blockers.append({"id": item["id"], "status": status, "reason": observation["reason"]})
        for ev in evidence:
            code = ev.get("exit_code")
            if ev.get("source_id") != run["source_id"] or type(code) is not int:
                raise ValueError(f"{item['id']}: evidence must identify exit code and exact source snapshot")
            if status == "pass" and code != 0:
                raise ValueError(f"{item['id']}: pass evidence must have a zero exit code")
            if not ev.get("command") or not ev.get("claim") or not ev.get("observed_at_utc"):
                raise ValueError(f"{item['id']}: evidence needs command, claim and observation time")
            candidate = review_file(root, item['id'], ev.get("path"), "evidence")
            data = candidate.read_bytes()
            if not data or hashlib.sha256(data).hexdigest() != ev.get("sha256"):
                raise ValueError(f"{item['id']}: evidence file empty or digest mismatch")
            if "receipt_path" in ev:
                validate_receipt(root, item['id'], ev)
        counts[item["metric"]][status] += 1
    metrics = {}
    for metric, values in sorted(counts.items()):
        total = sum(values.values())
        if not total:
            raise ValueError(f"{metric}: no checks")
        # Compare integers for strict >95, never rounded output.
        metrics[metric] = {**values, "total": total, "score_percent": 100 * values["pass"] / total,
                           "over_95": strict_over_95(values["pass"], total)}
    return {"source_id": run["source_id"], "rubric_sha256": expected_digest, "metrics": metrics,
            "ready_over_95": not blockers and all(v["over_95"] for v in metrics.values()), "blockers": blockers}


def strict_over_95(passed, total):
    return total > 0 and passed * 100 > 95 * total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-id", action="store_true", help="print a hash of the current candidate source")
    parser.add_argument("--run", type=Path, help="JSON observations to score")
    parser.add_argument("--historical", action="store_true", help="reproduce historical scores without asserting current-source readiness")
    args = parser.parse_args()
    try:
        if args.source_id:
            print(source_id()); return 0
        if not args.run:
            parser.error("--run is required unless --source-id is used")
        rubric = json.loads(RUBRIC.read_text())
        run = json.loads(args.run.read_text())
        if not args.historical and run.get("source_id") != source_id():
            raise ValueError("run source snapshot differs from current workspace")
        result = score(rubric, run)
        result["source_verified_current"] = not args.historical
        if args.historical:
            result["historical_ready_over_95"] = result["ready_over_95"]
            result["ready_over_95"] = False
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ready_over_95"] else 1
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"invalid score input: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
