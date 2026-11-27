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
SOURCE = "sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa"
SOURCE_COMMIT = "f499e3edf84e20f550312d05df51b9ea4e7cc699"


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
    inventory = json.loads((HERE / "artifact-inventory.json").read_bytes())
    if inventory["source_commit"] != SOURCE_COMMIT or inventory["source_id"] != state:
        sys.exit("Release inventory identifies another source.")
    for name, digest in inventory["files_sha256"].items():
        artifact = (HERE / name).resolve(strict=True)
        if not artifact.is_relative_to(HERE) or hashlib.sha256(artifact.read_bytes()).hexdigest() != digest:
            sys.exit(f"Release evidence digest differs: {name}")
    print(f"verified {len(inventory['files_sha256'])} release evidence files")
    previous = HERE.parent / "candidate-90beded5"
    prior_inventory = (previous / "artifact-inventory.json").read_bytes()
    if hashlib.sha256(prior_inventory).hexdigest() != inventory["previous_failed_candidate_inventory_sha256"]:
        sys.exit("The failed iteration's evidence inventory differs.")
    prior = json.loads(prior_inventory)
    if prior["source_commit"] != "90beded509f93909507c78f2986dea0e085e4f1e":
        sys.exit("The failed iteration's inventory identifies another source.")
    for name, digest in prior["files_sha256"].items():
        artifact = (previous / name).resolve(strict=True)
        if not artifact.is_relative_to(previous) or hashlib.sha256(artifact.read_bytes()).hexdigest() != digest:
            sys.exit(f"Failed-iteration evidence digest differs: {name}")
    print(f"verified {len(prior['files_sha256'])} files from the failed iteration")
    approval = json.loads((HERE / "qa-rubric-adjudication.json").read_bytes())
    if approval["source_commit"] != SOURCE_COMMIT or approval["reviewer"] != "independent QA (/root/qa)":
        sys.exit("Independent reviewer or revision differs.")
    review = (HERE / "qa-rubric-adjudication.md").read_bytes()
    if approval["source_before"] != state or approval["source_after"] != state or hashlib.sha256(review).hexdigest() != approval["report_sha256"]:
        sys.exit("Independent review source or content digest differs.")
    reviewed = {}
    bindings = {
        "literal-draft.json": approval["reviewed_literal_sha256"],
        "conservative-draft.json": approval["reviewed_conservative_sha256"],
        "normalized-receipt-index.json": approval["normalized_receipt_index_sha256"],
        **approval["approved_score_outputs"],
    }
    for name, digest in bindings.items():
        raw = gzip.decompress((HERE / "score-review-inputs" / (name + ".gz")).read_bytes())
        if hashlib.sha256(raw).hexdigest() != digest:
            sys.exit(f"Independent review input differs: {name}")
        reviewed[name] = json.loads(raw)
    index = reviewed["normalized-receipt-index.json"]
    for lane in ("final", "conservative"):
        ledger_path = HERE.parents[1] / "runs" / f"candidate-f499e3ed-{lane}.json"
        ledger = json.loads(ledger_path.read_bytes())
        variant = "literal" if lane == "final" else lane
        adjudicated = reviewed[f"{variant}-draft.json"]["observations"]
        if ledger["observations"].keys() != adjudicated.keys():
            sys.exit(f"Independently reviewed {variant} gates differ.")
        for gate, record in adjudicated.items():
            actual = ledger["observations"][gate]
            if any(actual[k] != record[k] for k in ("status", "reason")):
                sys.exit(f"Independently reviewed disposition differs: {gate}")
            if actual["status"] == "pass" and (actual["reviewed_at_utc"] != approval["reviewed_utc"] or actual["reviewer"] != approval["reviewer"]):
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
        if json.loads(scored.stdout) != reviewed[f"{variant}-score.json"]:
            sys.exit(f"Scorer differs from the output approved by QA for {variant}.")
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
            ("Ubuntu 22.04 x86-64", "linux-compatibility/jammy-build/jammy-linux-archive.json", "source_before", "sha256"),
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
