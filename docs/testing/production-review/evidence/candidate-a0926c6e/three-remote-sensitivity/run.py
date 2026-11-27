"""Paired diagnostic for the unrestricted three-worker image route. See plan.md."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import statistics
import subprocess
import time

ROOT = Path("/workspace/Entanglement")
OUT = Path(__file__).resolve().parent
ELFS = Path("/tmp/entangle-recovery-performance-a0926c6e")
DRIVER = ROOT / "scripts/benchmark_image_batch.py"
PRIMARY = OUT.parent / "performance.json"
PIN = "d6ac0a430e96870a9d3ed8b6dbdb8a1bd1f16cdcb7a2821040d14f20d5e4d9e6"
WASM = ROOT / "target/catalog-smoke/wasm32-wasip2/release/entangle_image_resize.wasm"
PHOTO = Path("/usr/share/matplotlib/mpl-data/sample_data/grace_hopper.jpg")
median = statistics.median


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def utc():
    return datetime.now(timezone.utc).isoformat()


def source():
    return subprocess.check_output(["python3", "scripts/production_score.py", "--source-id"],
                                   cwd=ROOT, text=True).strip()


def context():
    cpu = Path("/sys/fs/cgroup/cpu.stat")
    return {"utc": utc(), "loadavg": Path("/proc/loadavg").read_text().strip(),
            "cgroup_cpu": dict(line.split() for line in cpu.read_text().splitlines()),
            "cpu_max": Path("/sys/fs/cgroup/cpu.max").read_text().strip()}


def processes():
    result = {}
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            raw = (entry / "stat").read_text()
            split = raw.rindex(")")
            fields = raw[split + 2:].split()
            if fields[0] != "Z":
                result[(entry.name, fields[19])] = (raw[raw.index("(") + 1:split],
                                                      int(fields[11]) + int(fields[12]), fields[2])
        except (OSError, IndexError, ValueError):
            continue
    return result


def run_arm(pair, arm, stamp, seen, primary):
    prefix = f"pair-{pair}-{arm}"
    data = OUT / (prefix + ".json")
    log = OUT / (prefix + ".log")
    cmd = [str(ROOT / "target/catalog-smoke-python/bin/python"), str(DRIVER), "--bin-dir",
           str(ELFS / arm), "--wasm", str(WASM), "--image", str(PHOTO), "--route", "three_remote",
           "--results", str(data)]
    before = context()
    started = time.monotonic()
    previous = processes()
    activity = []
    with log.open("x") as handle:
        p = subprocess.Popen(cmd, stdout=handle, stderr=subprocess.STDOUT, cwd=ROOT, start_new_session=True)
        try:
            while p.poll() is None and time.monotonic() - started < 240:
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                snap = processes()
                busy = [(v[1] - previous[k][1], k[0], v[0], v[2] == str(p.pid))
                        for k, v in snap.items() if k in previous and v[1] > previous[k][1]]
                activity.append({"utc": utc(), "busy_by_cpu_ticks": sorted(busy, reverse=True)[:12]})
                previous = snap
        finally:
            # The ordinary driver waits for all children. Kill remaining members of this arm only.
            survivors = [k[0] for k,v in processes().items() if v[2] == str(p.pid)]
            if survivors:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                    time.sleep(0.3)
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            p.wait(timeout=10)
    got = {"pair": pair, "arm": arm, "argv": cmd, "before": before, "after": context(),
           "elapsed_s": time.monotonic() - started, "exit": p.returncode,
           "cleanup_needed": survivors, "live_group_after": [k[0] for k,v in processes().items() if v[2] == str(p.pid)],
           "stdout_sha256": digest(log), "process_samples": activity}
    stamp.append(got)
    if p.returncode or survivors or got["live_group_after"] or not data.exists():
        got["error"] = "arm process validation failed"
        return
    j = json.loads(data.read_text())
    got["driver_result_sha256"] = digest(data)
    original = primary["image"][arm]
    fields = ("input_sha256", "png_digest_list_sha256", "source_sha256", "wasm_sha256", "daemon_sha256")
    trials = j["trials"]
    checks = [len(trials) == 3, j["concurrency"] == 4, j["images"] == 24, not j["worker_cpu_affinity"],
              all(j[k] == original[k] for k in fields)]
    checks.extend(r["route"] == "three_remote" and len(r["latency_ms_by_input"]) == 24
                  and len(r["workers"]) == 3 and sum(r["workers"].values()) == 24
                  and min(r["workers"].values()) > 0 and r["max_channel_mae"] <= 3 for r in trials)
    ids = set().union(*(r["workers"] for r in trials))
    checks.extend([len(ids) == 3, not ids & seen])
    seen.update(ids)
    if not all(checks):
        got["error"] = "corpus, oracle, executor, or topology validation failed"
        return
    got["p95_ms"] = median(r["p95_ms"] for r in trials)
    got["images_s"] = median(r["images_s"] for r in trials)


def main():
    receipt = OUT / "results.json"
    if receipt.exists() or any(OUT.glob("pair-*")):
        raise SystemExit("Output already exists")
    assert digest(PRIMARY) == PIN
    primary = json.loads(PRIMARY.read_text())
    assert digest(DRIVER) == "c181ac3f2d63b4c2696aa38c1a87eaf3cfc6340a1d69f41ceeca67b4ceda2daf"
    assert source() == primary["source_id"]
    for arm in ("baseline","candidate"):
        assert digest(ELFS / arm / "entangled") == primary["daemons"][arm]
        assert digest(ELFS / arm / "entangle") == primary["cli_sha256"]
    result = {"primary_sha256": PIN, "source_before": primary["source_id"],
              "script_sha256": digest(Path(__file__)), "plan_sha256": digest(OUT / "plan.md"),
              "utc_started": utc(), "arms": [], "clock_ticks_per_second": os.sysconf("SC_CLK_TCK")}
    seen = set()
    for pair in range(1,7):
        arms = ["baseline","candidate"] if pair % 2 else ["candidate","baseline"]
        for arm in arms:
            run_arm(pair,arm,result["arms"],seen,primary)
            write(receipt,result)
    result["source_after"] = source()
    result["utc_finished"] = utc()
    if not any("error" in a for a in result["arms"]) and result["source_after"] == result["source_before"]:
        paired = {i: {a["arm"]:a for a in result["arms"] if a["pair"]==i} for i in range(1,7)}
        for metric in ("p95_ms","images_s"):
            ratios = [both["candidate"][metric]/both["baseline"][metric] for both in paired.values()]
            breaches = sum(v>1.05 if metric=="p95_ms" else v<0.95 for v in ratios)
            result[metric] = {"paired_ratios": ratios, "median_ratio": median(ratios), "range": [min(ratios),max(ratios)],
                              "breaches":breaches, "repeated_directional_miss": breaches>=5,
                              "medians":{k:median(both[k][metric] for both in paired.values()) for k in arms}}
    write(receipt,result)
    return 0 if "p95_ms" in result else 1


if __name__ == "__main__":
    raise SystemExit(main())
