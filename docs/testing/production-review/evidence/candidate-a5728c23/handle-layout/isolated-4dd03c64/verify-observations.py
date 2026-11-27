"""Recheck all 24 recorded arms and paired values offline."""
import gzip
import hashlib
import json
from pathlib import Path
import statistics

d = Path(__file__).resolve().parent
def read(name):return json.loads((d/name).read_bytes())
p = read("preregistration.json")
with gzip.open(d / "results.json.gz", "rb") as f:
    raw = f.read()
v = json.loads(raw); s = read("paired-summary.json")
with gzip.open(d / "arm-observations.json.gz", "rt") as f:
    observations = json.load(f)
assert hashlib.sha256(raw).hexdigest() == s["results_sha256"]
assert p["arm_pairs_in_order"] == [r["order"] for r in v["pairs"]]
assert v["source_before"] == v["source_after"] == p["candidate_source"] and v["exit_code"] == 0
assert hashlib.sha256((d/"preregistration.json").read_bytes()).hexdigest() == v["plan_sha256"]
assert read("release-build.json")["files_sha256"]["entangled"] == v["daemons"]["B"]
counts = {"greetings": 0, "images": 0}
for pair in v["pairs"]:
    assert pair["order"] == "".join(arm["label"] for arm in pair["arms"])
    for arm in pair["arms"]:
        key = str(pair["pair"]) + "-" + arm["label"]
        record = observations["arms"][key]
        for item in record["greetings"]:
            assert item["requests"] == 1024
            route = item["route"] + " / " + str(item["clients"])
            assert [item["p95_ms"], item["requests_per_s"]] == arm["metrics"][route]
            counts["greetings"] += item["requests"]
        images = record["image_report"]
        assert images["daemon_sha256"] == v["daemons"]["B" if arm["label"] == "B" else "A"]
        for tag, digest in observations["image_oracles"].items(): assert images[tag] == digest
        for route in ("local", "one_remote", "three_remote"):
            trials = [t for t in images["trials"] if t["route"] == route]
            assert len(trials) == 3 and all(len(t["latency_ms_by_input"]) == 24 for t in trials)
            counts["images"] += sum(len(t["latency_ms_by_input"]) for t in trials)
            assert [statistics.median(t[m] for t in trials) for m in ("p95_ms", "images_s")] == arm["metrics"]["image " + route]
        for route, values in arm["metrics"].items():
            cmp = s["rows"][route]["different_daemons" if arm["label"] in "AB" else "same_daemon"]
            for metric, value in zip(["p95_ms","throughput"], values):
                obs, = [t for t in cmp[metric]["pair_observations"] if t["pair"] == pair["pair"]]
                side = "numerator" if arm["label"] in "BY" else "denominator"
                assert obs[side] == value
                assert obs["ratio"] == obs["numerator"]/obs["denominator"]
                assert cmp[metric]["median_ratio"] == statistics.median(t["ratio"] for t in cmp[metric]["pair_observations"])
assert counts == {"greetings": 98304, "images": 5184}
print(f"Verified {len(observations['arms'])} arms, {counts['greetings']} greetings, {counts['images']} images, seven routes and paired medians.")
