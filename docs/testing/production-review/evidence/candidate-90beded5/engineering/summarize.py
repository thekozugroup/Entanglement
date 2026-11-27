"""Render all trial ratios; the preregistered verdict uses the separate arm medians."""
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
r = json.loads((out / "performance.json").read_text())
passing = sum(c["meets_engineering_limit"] for c in r["comparisons"].values())
table = [f"# Ordinary signed workload measurements\n",
         f"{passing} of seven routes passed both limits against the preceding a5728c23 engineering release. "
         "Each route required candidate median p95 at most 1.05 times the comparator and candidate median rate at least 0.95 times the comparator. "
         "The production operator has yet to approve a baseline. [Registered plan](plan.md) · [Primary observations](../performance.json)\n",
         "| Route | Median p95 ratio | Median rate ratio | Trial 1 p95 / rate | Trial 2 p95 / rate | Trial 3 p95 / rate | Both limits |",
         "|---|---:|---:|---:|---:|---:|---|"]
for route in ("local / 1", "local / 4", "remote / 1", "remote / 4", "image local", "image one_remote", "image three_remote"):
    info = r["comparisons"][route]
    if route.startswith("image"):
        speed = "images_s"
        name = route.split()[1]
        observations = {k:[row for row in r["image"][k]["trials"] if row["route"] == name]
                        for k in ("baseline", "candidate")}
    else:
        speed = "requests_per_s"
        name, clients = route.split(" / ")
        observations = {k:[conf for row in r["hello"] if row["stage"] == k for conf in row["configurations"]
                           if conf["route"] == name and conf["concurrency"] == int(clients)] for k in ("baseline", "candidate")}
    assert len(observations["baseline"]) == len(observations["candidate"]) == 3
    pairs = [f'{b["p95_ms"]/a["p95_ms"]:.3f} / {b[speed]/a[speed]:.3f}'
             for a,b in zip(observations["baseline"],observations["candidate"])]
    table.append(f'| {route} | {info["p95_ratio"]:.3f} | {info["throughput_ratio"]:.3f} | '
                 + " | ".join(pairs) + " | " + ("Pass" if info["meets_engineering_limit"] else "Miss") + " |")
compilers = sorted({p for sample in r["cpu_monitor_samples"] for p in sample["known_build_processes"]})
def throttle(x):
    return int(dict(row.split() for row in r[x]["cpu_stat"].splitlines())["throttled_usec"])
table += ["", "Greeting trials used adjacent fresh clusters in AB, BA and AB order. Each arm checked 1,024 signed responses per route. "
          "Image trials compared the same within-version ordinal across three repetitions per route. "
          "Each version used one separately created cluster, with the candidate suite first. "
          "The prescribed verdict divides three-trial medians from the two versions. Trial columns retain the individual ratios.",
          "", f'Both image batches produced the same ordered SHA-256 digest of all 24 outputs, `{r["image"]["candidate"]["png_digest_list_sha256"]}`. '
          f'The candidate and comparator obtained three-worker versus one-worker rates of {r["image"]["candidate"]["three_over_one_remote"]:.3f}× and '
          f'{r["image"]["baseline"]["three_over_one_remote"]:.3f}× on the shared host. Four concurrent clients shared its CPU allocation.',
          "", f'The host monitor captured {len(r["cpu_monitor_samples"])} samples. Known build processes observed were '
          + (", ".join(compilers) if compilers else "none") + f'. Cgroup throttled time increased by {throttle("cpu_after")-throttle("cpu_before")} µs '
          f'from the pre-series to post-series snapshots. The entire series used one shared Linux VM. '
          'Image timing includes other work within the same cluster. These three-trial comparisons can fluctuate with host load and trial order.']
(out / "engineering/performance-interpretation.md").write_text("\n".join(table)+"\n")
