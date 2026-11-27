#!/usr/bin/env python3
"""Run three locked workspace suites on one frozen source snapshot."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess


SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; "
    r"([0-9]+) measured; ([0-9]+) filtered out(?:;[^\r\n]*)?\r?$",
    re.MULTILINE,
)
COUNTS = ("passed", "failed", "ignored", "measured", "filtered_out")
ENVIRONMENT = (
    "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "CARGO_BUILD_JOBS",
    "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
)
ENV_SCRIPT = Path("/tmp/entangle-release-followup/env.sh")
WORKSPACE_COMMAND = ("cargo", "test", "--locked", "--workspace", "--no-fail-fast")
SESSION_COMMAND = ("cargo", "test", "--locked", "-p", "entangle-agent-host", "--test", "session",
                   "--", "--test-threads=1")


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    pending = path.with_suffix(".partial")
    pending.write_text(json.dumps(value, indent=2) + "\n")
    pending.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=Path("/workspace/Entanglement"), type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--skip-session", action="store_true")
    args = parser.parse_args()
    root = args.repo.resolve(strict=True)
    assert ENV_SCRIPT.is_file()
    env = dict(os.environ)
    for name in ("RUST_TEST_THREADS", "RUST_TEST_NOCAPTURE", "ENTANGLE_AGENT_SESSION_TEST_DIR"):
        env.pop(name, None)
    env["CARGO_TERM_COLOR"] = "never"
    env["CARGO_TARGET_DIR"] = str(root / "target")

    def output(*cmd):
        return subprocess.check_output(cmd, text=True, cwd=root, env=env).strip()

    def identify():
        return {"commit": output("git", "rev-parse", "HEAD"),
                "source_id": output("python3", "scripts/production_score.py", "--source-id")}

    frozen = {"commit": args.commit, "source_id": args.source_id}
    assert identify() == frozen, "source differs from the declared freeze"
    evidence = root / "docs/testing/production-review/evidence" / ("candidate-" + args.commit[:8]) / "workspace-tests"
    evidence.mkdir(parents=True, exist_ok=False)
    runner = Path(__file__).resolve()
    shutil.copyfile(runner, evidence / "workspace-qualification.py")
    shutil.copyfile(ENV_SCRIPT, evidence / "env.sh")
    index = {
        "source_commit": args.commit, "source_id": args.source_id, "source_before": args.source_id,
        "started_at_utc": stamp(), "cwd": str(root),
        "runner_sha256": sha(runner), "environment_script_sha256": sha(ENV_SCRIPT),
        "environment": {name: env.get(name) for name in ENVIRONMENT},
        "toolchain": {"cargo": output("cargo", "-Vv"), "rustc": output("rustc", "-vV")},
        "case_environment": "Workspace suites use the default libtest threading. AgentSession runs separately in serial.",
        "runs": [],
    }
    write_json(evidence / "index.json", index)

    def run(tag, cmd, claim):
        before = identify()
        if before != frozen:
            return False
        place = evidence / tag
        place.mkdir()
        log = place / "test.log"
        start = stamp()
        with log.open("xb") as stream:
            proc = subprocess.run(cmd, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
        finish = stamp()
        after = identify()
        summaries = SUMMARY.findall(log.read_text(errors="replace"))
        counts = {name: sum(int(item[column]) for item in summaries)
                  for column, name in enumerate(COUNTS, start=1)}
        receipt = {
            "command": shlex.join(cmd), "argv": cmd, "claim": claim,
            "source_commit": before["commit"], "source_commit_after": after["commit"],
            "source_id": before["source_id"], "source_before": before["source_id"], "source_after": after["source_id"],
            "source_matches": before == after == frozen,
            "started_at_utc": start, "finished_at_utc": finish, "observed_at_utc": finish,
            "exit_code": proc.returncode, "path": str(log.relative_to(root)), "sha256": sha(log),
            "result_groups": len(summaries), "failed_result_groups": sum(item[0] == "FAILED" for item in summaries),
            "tests": counts,
        }
        receipt_file = place / "receipt.json"
        write_json(receipt_file, receipt)
        index["runs"].append({"name": tag, "receipt": str(receipt_file.relative_to(root)),
                              "receipt_sha256": sha(receipt_file), **receipt})
        write_json(evidence / "index.json", index)
        print(tag, proc.returncode, json.dumps(counts), after["source_id"], flush=True)
        return receipt["source_matches"]

    for number in (1, 2, 3):
        if not run(f"run-{number}", WORKSPACE_COMMAND,
                   f"Locked workspace suite {number} using default libtest threading."):
            break
    if len(index["runs"]) == 3 and all(item["source_matches"] for item in index["runs"]) and not args.skip_session:
        assert (root / "crates/entangle-agent-host/tests/session.rs").is_file()
        run("agent-session-serial", SESSION_COMMAND, "AgentSession integration cases rerun in serial.")
    after = identify()
    enough = 3 if args.skip_session else 4
    success = (after == frozen and len(index["runs"]) == enough and
               all(item["source_matches"] and item["exit_code"] == 0 and
                   item["result_groups"] > 0 and item["failed_result_groups"] == 0 and
                   item["tests"]["passed"] > 0 and item["tests"]["failed"] == 0 for item in index["runs"]))
    workspace_runs = [item for item in index["runs"] if item["name"].startswith("run-")]
    totals_match = len(workspace_runs) == 3 and all(
        item["tests"] == workspace_runs[0]["tests"] and item["result_groups"] == workspace_runs[0]["result_groups"]
        for item in workspace_runs[1:]
    )
    index.update(source_after=after["source_id"], source_commit_after=after["commit"],
                 workspace_totals_match=totals_match, finished_at_utc=stamp(), exit_code=int(not success))
    write_json(evidence / "index.json", index)
    print(str(evidence / "index.json"), index["exit_code"], flush=True)
    return index["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
