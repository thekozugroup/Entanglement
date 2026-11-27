"""Check every case disposition and export natural cross-peer recoveries from a saved cohort."""
import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("raw", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rec = json.loads(args.receipt.read_bytes())
    blob = args.raw.read_bytes()
    if args.raw.suffix == ".gz":
        blob = gzip.decompress(blob)
    assert rec["raw_sha256"] == hashlib.sha256(blob).hexdigest()
    assert rec["source_before"] == rec["source_after"]
    assert rec.get("errors") == 0 and not rec.get("fatal_error")
    blocks = [json.loads(line) for line in blob.splitlines()]
    assert len(blocks) == rec["expected_blocks"] == rec["blocks"] == 128
    assert len(set(rec["peers"])) == 2 and rec["coordinator"] not in rec["peers"]
    tally = dict(native=collections.Counter(), remote=collections.Counter())
    recoveries = []
    for number, block in enumerate(blocks, 1):
        assert block["block"] == number and not block.get("remote_evidence_error")
        assert block["order"] == (["native", "remote"] if number % 2 else ["remote", "native"])
        peers = rec["peers"] if number % 2 else rec["peers"][::-1]
        assert block["remote_peer_order"] == peers
        native = block["native"]
        remote = block["remote"]["results"]
        assert len(remote) == 1 and remote[0]["name"] == "now"
        assert block["remote"]["listing_peers"] == peers and block["remote"]["filtered"] == 22
        attempts = remote[0]["attempts"]
        trace = block["remote_raw_test_requests_and_replies"]
        assert len(trace) == len(attempts)
        for index, (row, raw) in enumerate(zip(attempts, trace)):
            result, request = raw["result"], raw["request"]
            assert row["peer"] == raw["peer"] == result["peer"] == peers[index]
            assert row["attempt"] == request["attempt"] == index + 1
            assert request["operation"] == "test" and request["name"] == "now"
            if "independent_signed_suite_identity" in rec:
                identity = rec["independent_signed_suite_identity"]
                assert request["expected_suite_identity"] == result["suite_identity"] == block["remote"]["suite_identity"] == identity
            output = result["stdout"] + result["stderr"]
            if row["status"] == "passed":
                assert result["exit_code"] == 0 and "1 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out" in output
            else:
                assert row["status"] == "failed" and result["exit_code"] != 0
                assert "panicked at jaq-core/tests/common/mod.rs:35" in output and "assertion `left == right` failed" in output
                values = re.search(r"left: \[Ok\(Int\(([0-9]+)\)\)\]\s*right: \[Ok\(Int\(([0-9]+)\)\)\]", output)
                assert values and int(values[1]) == int(values[2]) + 1
        for row in native:
            output = row["stdout"] + row["stderr"]
            assert row["outcome"] in ("failed", "passed")
            if row["outcome"] == "failed":
                assert row["exit"] != 0 and "jaq-core/tests/common/mod.rs:35" in output and "test now ... FAILED" in output
            else:
                assert row["exit"] == 0 and "1 passed; 0 failed" in output
        for side, pattern in [("native", [a["outcome"] for a in native]), ("remote", [a["status"] for a in attempts])]:
            assert pattern in (["passed"], ["failed","failed"], ["failed","passed"])
            tally[side]["->".join(pattern)] += 1
        expected = {("passed",):"passed", ("failed","failed"):"failed", ("failed","passed"):"flaky"}
        assert remote[0]["status"] == expected[tuple(a["status"] for a in attempts)]
        if remote[0]["status"] == "flaky":
            recoveries.append(dict(block=number, attempts=trace))
    for side, counts in tally.items():
        assert counts == rec[side + "_patterns"]
    assert rec["verified_remote_transitions"] == [r["block"] for r in recoveries]
    result = dict(checked_blocks=len(blocks), peer_distinct=True, all_attempts_classified=True, patterns=tally,
                  real_cross_peer_recoveries=recoveries, plan_sha256=rec["plan_sha256"], raw_payload_sha256=rec["raw_sha256"],
                  candidate_source=rec["source_before"], checked_requests_pinned="independent_signed_suite_identity" in rec,
                  witness_criterion_met=bool(recoveries and tally["native"]["passed"] and
                                                (tally["native"]["failed->failed"] or tally["native"]["failed->passed"])))
    args.output.write_text(json.dumps(result,indent=2)+"\n")


if __name__ == "__main__":
    main()
