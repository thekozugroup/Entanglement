"""Reproduce the integrated scorecards and check local copies of the reviewed archives."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = "sha256:a43296d252b79d7a0762861de1251b0e2e77fde20af2ea5dd43254617376fce5"
SOURCE_COMMIT = "a5728c230e5049556b806cae8597fe823dd67987"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, action="append", default=[],
                        help="check an unsigned candidate tar.gz against its archive receipt (repeatable)")
    args = parser.parse_args()
    scorer = [sys.executable, str(ROOT / "scripts/production_score.py")]
    state = subprocess.check_output([*scorer, "--source-id"], cwd=ROOT, text=True).strip()
    if state != SOURCE:
        verifier = (HERE / "verify-review.py").relative_to(ROOT)
        commit = subprocess.check_output(
            ["git", "log", "-1", "--format=%H", "--diff-filter=A", "--", str(verifier)],
            cwd=ROOT,
            text=True,
        ).strip()
        sys.exit(
            "The working tree differs from the measured source. "
            f"Check out qualification commit {commit or '<qualification-commit>'} in a separate clone "
            "and run the verifier there."
        )
    approval = json.loads((HERE / "qa-rubric-adjudication.json").read_bytes())
    review = (HERE / "qa-rubric-adjudication.md").read_bytes()
    if approval["source_before"] != state or approval["source_after"] != state or hashlib.sha256(review).hexdigest() != approval["review_sha256"]:
        sys.exit("Independent review source or content digest differs.")
    reviewed = {}
    for name, digest in approval["drafts"].items():
        raw = gzip.decompress((HERE / "score-review-inputs" / (name + ".gz")).read_bytes())
        if hashlib.sha256(raw).hexdigest() != digest:
            sys.exit(f"Independent review input differs: {name}")
        reviewed[name] = json.loads(raw)
    index = reviewed["normalized-receipt-index.json"]
    for lane in ("final", "conservative"):
        ledger_path = HERE.parents[1] / "runs" / f"candidate-a5728c23-{lane}.json"
        ledger = json.loads(ledger_path.read_bytes())
        variant = "literal" if lane == "final" else lane
        adjudicated = reviewed[f"{variant}-draft.json"]["observations"]
        if ledger["observations"].keys() != adjudicated.keys():
            sys.exit(f"Independently reviewed {variant} gates differ.")
        for gate, record in adjudicated.items():
            actual = ledger["observations"][gate]
            if any(actual[k] != record[k] for k in ("status", "reason")):
                sys.exit(f"Independently reviewed disposition differs: {gate}")
            if actual["status"] == "pass" and (actual["reviewed_at_utc"] != approval["signed_off_utc"] or actual["reviewer"] != "Independent QA agent " + approval["reviewer"]):
                sys.exit(f"Independent reviewer or time differs: {gate}")
            expected = []
            for original in record.get("evidence", []):
                item = original.copy()
                key = item.pop("draft_normalized_receipt_key", None)
                if key is not None:
                    item["receipt_path"] = index[key]["proposed_workspace_path"]
                    digest = hashlib.sha256((ROOT / item["receipt_path"]).read_bytes()).hexdigest()
                    if digest != index[key]["sha256"]:
                        sys.exit(f"Reviewed normalized receipt differs: {gate}")
                expected.append(item)
            if expected != actual.get("evidence", []):
                sys.exit(f"Reviewed evidence references differ: {gate}")
        references = [ref for obs in ledger["observations"].values() for ref in obs.get("evidence", [])]
        for ref in references:
            for field in ("path", "receipt_path"):
                if not (ROOT / ref[field]).resolve().is_relative_to(HERE):
                    sys.exit(f"Evidence belongs to another review: {ref[field]}")
        scored = subprocess.run([*scorer, "--run", str(ledger_path)], cwd=ROOT, capture_output=True)
        if scored.returncode != 1 or json.loads(scored.stdout) != json.loads((HERE / f"{lane}-score.json").read_bytes()):
            sys.exit(f"Could not reproduce {lane} score. {scored.stderr.decode().strip()}")
        print(f"{lane}: verified {len(ledger['observations'])} checks and {len(references)} execution references")
    supplement = json.loads((HERE / "qa-supplement.json").read_bytes())
    if supplement["source_id"] != SOURCE or supplement["source_commit"] != SOURCE_COMMIT:
        sys.exit("Independent supplemental review refers to another candidate.")
    checked = dict(supplement["evidence_sha256"])
    checked[supplement["report"]] = supplement["report_sha256"]
    for name, digest in checked.items():
        target = (HERE / name).resolve(strict=True)
        if not target.is_relative_to(HERE) or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            sys.exit(f"Supplemental review digest differs: {name}")
    print(f"verified the supplemental review and {len(supplement['evidence_sha256'])} evidence files")
    if args.archive:
        receipts = [
            ("canonical x86-64", "linux-archive.json", "source_id", "sha256"),
            ("Ubuntu 22.04 x86-64", "linux-compatibility/jammy-replay/jammy-linux-archive.json", "source_before", "sha256"),
            ("AArch64 Linux", "linux-compatibility/current-arm64/arm-archive.json", "source_before", "archive_sha256"),
        ]
        hashes = {}
        for label, filename, source_key, digest_key in receipts:
            record = json.loads((HERE / filename).read_bytes())
            if (record[source_key] != SOURCE or record["source_after"] != SOURCE
                    or record["source_commit"] != SOURCE_COMMIT):
                sys.exit(f"Archive receipt refers to another source: {label}")
            hashes[record[digest_key]] = label
        for archive in args.archive:
            with archive.open("rb") as handle:
                actual = hashlib.file_digest(handle, "sha256").hexdigest()
            if actual not in hashes:
                sys.exit(f"Archive digest does not match a reviewed build: {archive}")
            print(f"verified {hashes[actual]} archive SHA-256 {actual}")


if __name__ == "__main__":
    main()
