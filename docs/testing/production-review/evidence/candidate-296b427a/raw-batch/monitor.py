"""Run one benchmark with a one-second Linux procfs sampler."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import time


def snapshot():
    rows = {}
    for proc in Path("/proc").glob("[0-9]*/stat"):
        try:
            row = proc.read_text()
            end = row.rindex(")")
            name = row[row.index("(") + 1:end]
            stat = row[end + 2:].split()
            if stat[0] != "Z":
                rows[(proc.parent.name, stat[19])] = (
                    name, int(stat[11]) + int(stat[12]), int(stat[21])
                )
        except (FileNotFoundError, ProcessLookupError, PermissionError, UnicodeError):
            pass
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("command", nargs="+")
    args = parser.parse_args()
    ticks = os.sysconf("SC_CLK_TCK")
    page_size = os.sysconf("SC_PAGE_SIZE")
    builds = {"cargo", "rustc", "gcc", "cc1", "clang", "ld.lld", "ninja", "make"}
    nodes = {"entangle", "entangled", "dcraw_emu", "raw-identify"}
    rows = []
    last_time = time.monotonic()
    previous = snapshot()
    with subprocess.Popen(args.command) as proc:
        while proc.poll() is None:
            time.sleep(1)
            current = snapshot()
            now = time.monotonic()
            usage = {}
            rss = {}
            for key, (name, cpu, pages) in current.items():
                if key in previous:
                    usage[name] = usage.get(name, 0) + (cpu - previous[key][1]) / ticks / (now - last_time)
                if name in nodes:
                    rss[name] = rss.get(name, 0) + pages * page_size
            rows.append({
                "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "summed_observed_rss_bytes_by_name": rss,
                "live_build_processes": sorted({v[0] for v in current.values()} & builds),
                "cpu_cores_by_name": {k: round(v, 3) for k, v in usage.items() if v >= .02},
            })
            last_time, previous = now, current
    args.output.write_text(json.dumps({
        "command": args.command, "exit_code": proc.returncode,
        "cpu_quota_period": Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
        "method": "Sum RSS across concurrent processes with the same name. Shared pages can be counted multiple times. Short processes and peaks between samples may be missed.",
        "samples": rows,
    }, indent=2) + "\n")
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
