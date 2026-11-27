"""Replay the fixed pre-existing ledgers using this integrated candidate."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]


def main():
    prior = json.loads((HERE / "historical-replay.json").read_bytes())
    scorer = ROOT / "scripts/production_score.py"
    assert hashlib.sha256(scorer.read_bytes()).hexdigest() == prior["proposed_sha256"]
    runs = ROOT / "docs/testing/production-review/runs"
    for row in prior["rows"]:
        ledger = runs / row["ledger"]
        assert hashlib.sha256(ledger.read_bytes()).hexdigest() == row["sha256"]
        proc = subprocess.run([sys.executable, str(scorer), "--historical", "--run", str(ledger)],
                              cwd=ROOT, capture_output=True, check=False)
        assert proc.returncode == row["previous_exit"] and not proc.stderr
        got = json.loads(proc.stdout)
        values = {k: v["score_percent"] for k, v in got["metrics"].items()}
        assert values == row["numeric_percentages"]
        assert len(got["blockers"]) == row["blockers"]
        print(ledger.name, "historical exit", proc.returncode, "blockers", len(got["blockers"]))


if __name__ == "__main__":
    main()
