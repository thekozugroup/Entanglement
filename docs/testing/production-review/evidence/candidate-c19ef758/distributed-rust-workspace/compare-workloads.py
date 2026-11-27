#!/usr/bin/env python3
"""Compare a single authenticated, descriptive workload pair and reveal all mismatches."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["baseline", "successor", "baseline-comparison", "successor-comparison", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    old, new, old_cases, new_cases = (json.loads(x.read_bytes()) for x in
        (args.baseline, args.successor, args.baseline_comparison, args.successor_comparison))
    fields = ("upstream_commit", "dependency_lock_sha256", "driver_sha256", "sharder_sha256", "rustdoc_observer_sha256", "command")
    input_checks = {k: old[k] == new[k] for k in fields}
    input_checks["prebuilt_ordinary_components"] = old_cases["ordinary_components"] == new_cases["ordinary_components"]
    input_checks["generated_standalone_doctest_components"] = old_cases["standalone_doc_components"] == new_cases["standalone_doc_components"]
    input_checks["fresh_distinct_worker_pairs"] = not (set(old["peers"]) & set(new["peers"]))
    input_checks["native_log"] = old_cases["native_log_sha256"] == new_cases["native_log_sha256"]
    def rows(report):
        return {(t["package"], t["kind"], t["target"], row["name"]): row["status"] for t in report["targets"] for row in t["report"]["results"]}
    baseline, successor = rows(old), rows(new)
    differences = [{"id": list(k), "baseline": baseline.get(k), "successor": successor.get(k)}
                   for k in sorted(baseline.keys() | successor.keys()) if baseline.get(k) != successor.get(k)]
    def phases(raw, summary):
        return {"cluster_setup": raw["cluster_setup_s"], "cargo_command": raw["elapsed_s"],
                "ordinary_targets": sum(t["seconds"] for t in summary["target_durations"] if t["kind"] != "rustdoc"),
                "host_rustdoc_targets": sum(t["seconds"] for t in summary["target_durations"] if t["kind"] == "rustdoc"),
                "standalone_guest_ready_and_dispatch": summary["standalone_ready_and_dispatch_s"]["sum"]}
    p0, p1 = phases(old, old_cases), phases(new, new_cases)
    comparison = {name: {"baseline_s":p0[name], "successor_s":p1[name], "baseline_over_successor":p0[name]/p1[name] if p1[name] else None} for name in p0}
    result = {"study":"single descriptive end-to-end workload pair", "candidate_refs":[old["daemon_source_ref"],new["daemon_source_ref"]],
              "report_sha256":[sha(args.baseline),sha(args.successor)],"input_checks":input_checks,
              "named_status_differences":differences, "baseline_counts":old_cases["remote_counts"],"successor_counts":new_cases["remote_counts"],
              "native_to_distributed_difference_counts":[len(old_cases["differences"]),len(new_cases["differences"])],
              "phase_elapsed": comparison, "workload_load_context":[{k:r[k] for k in ("started_utc","finished_utc","loadavg_before","loadavg_after","cgroup_cpu_before","cgroup_cpu_after")} for r in (old,new)],
              "scope":"Fresh authenticated loopback workers on one shared Linux VM during qualification. No throughput SLA or causal confidence interval is estimated from a single pair. Rustdoc phase already includes the standalone dispatch time."}
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    return int(not all(input_checks.values()) or bool(differences))


if __name__ == "__main__":
    raise SystemExit(main())
