#!/usr/bin/env python3
"""Compare complete native and remote Cargo inventories; retain target-specific differences."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import statistics


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("metadata", "native-artifacts", "native-log", "distributed", "out"):
        parser.add_argument("--" + arg, type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads(args.metadata.read_bytes())
    packages = {p["id"]: p["name"] for p in metadata["packages"]}
    libs = {t["name"]: p["name"] for p in metadata["packages"] for t in p["targets"] if "lib" in t["kind"]}
    run = json.loads(args.distributed.read_bytes())
    peers = set(run["peers"])
    assert len(peers) == 2 and run["coordinator"] not in peers
    bins = {}
    for line in args.native_artifacts.read_text().splitlines():
        record = json.loads(line)
        if record.get("executable") and record["package_id"] in packages and record["profile"]["test"]:
            bins[Path(record["executable"]).name] = (packages[record["package_id"]], "+".join(record["target"]["kind"]), record["target"]["name"])
    aliases = {"ok": "passed", "FAILED": "failed", "ignored": "ignored"}
    native = {}
    for line in args.native_log.read_text().splitlines():
        if match := re.match(r"\s*Running .+ \(([^)]+)\)$", line):
            target = bins[Path(match[1]).name]
        elif match := re.match(r"\s*Doc-tests (\S+)$", line):
            target = (libs[match[1]], "rustdoc", "doctest")
        elif match := re.fullmatch(r"test (.+?) \.\.\. (ok|FAILED|ignored)(?:, .*?)?", line):
            key = (*target, match[1].removesuffix(" - should panic"))
            assert key not in native
            native[key] = aliases[match[2]]
    remote = {}
    workers = Counter()
    details = {}
    standalone_times = []
    durations = []
    unsigned_doc_errors = []
    generated = {}
    for target in run["targets"]:
        report = target["report"]
        if "elapsed_s" in target:
            durations.append({"package": target["package"], "target": target["target"], "kind": target["kind"], "seconds": target["elapsed_s"]})
        unsigned_doc_errors.extend(report.get("infrastructure_errors", []))
        for case in report["results"]:
            key = (target["package"], target["kind"], target["target"], case["name"])
            assert key not in remote
            remote[key] = case["status"]
            details[key] = case
            for attempt in case["attempts"]:
                assert attempt["peer"] in peers
                workers.update([attempt["peer"]])
                if "raw_guest" in attempt:
                    assert attempt["raw_guest"] and attempt["raw_guest"]["peer"] == attempt["expected_peer"] == attempt["peer"]
                    assert not attempt["infrastructure_error"]
                    standalone_times.append(attempt["elapsed_s"])
                    generated["/".join(key)] = attempt["wasm_sha256"]
    def grouped(cases):
        return {name: dict(Counter(s for k,s in cases.items() if (k[1]=="rustdoc")==is_doc))
                for name,is_doc in (("ordinary",False),("rustdoc",True))}
    differences = []
    for key in sorted(set(native) | set(remote)):
        if native.get(key) != remote.get(key):
            differences.append({"id": list(key), "native": native.get(key), "distributed": remote.get(key), "guest": details.get(key)})
    result = {"source_id": run["daemon_source_id"], "source_commit": run["daemon_source_ref"],
              "upstream_commit": run["upstream_commit"], "lock_sha256": run["dependency_lock_sha256"],
              "known_workspace_members": sorted(packages.values()), "native_counts": grouped(native), "remote_counts": grouped(remote),
              "named_inventory_identical": set(native)==set(remote), "all_dispositions_identical": not differences,
              "differences": differences, "rustdoc_evidence_errors": unsigned_doc_errors, "cargo_exit": run["exit_code"],
              "worker_attempts": dict(workers), "native_log_sha256": digest(args.native_log),
              "distributed_report_sha256": digest(args.distributed), "sharder_sha256": run["sharder_sha256"],
              "driver_sha256": run["driver_sha256"], "rustdoc_observer_sha256": run["rustdoc_observer_sha256"],
              "ordinary_components": sorted(t["wasm_sha256"] for t in run["targets"] if t["kind"] != "rustdoc"),
              "standalone_doc_components": generated, "cluster_setup_s": run["cluster_setup_s"],
              "cargo_elapsed_s": run["elapsed_s"], "target_durations": durations,
              "standalone_ready_and_dispatch_s": {"count": len(standalone_times), "sum": sum(standalone_times),
                  "median": statistics.median(standalone_times) if standalone_times else None,
                  "max": max(standalone_times, default=None)},
              "ordinary_worker_execution_note": "Target-specific ignores have no successful guest execution."}
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    return int(not result["named_inventory_identical"] or bool(unsigned_doc_errors))


if __name__ == "__main__":
    raise SystemExit(main())
