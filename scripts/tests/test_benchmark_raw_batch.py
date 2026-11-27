"""Coverage failure evidence for the camera RAW benchmark."""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import benchmark_raw_batch as bench

encode_png = runpy.run_path(str(HERE / "image-dehaze-batch.py"))["encode_linear_png"]


class RawBenchmarkEvidence(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.sources = {"canon.cr2": 1, "nikon.nef": 2}

    def render(self, output, assignments, changed=False):
        outputs, records = {}, []
        for name, peer in assignments:
            pixels = bytes([self.sources[name] + int(changed)]) * 6
            data = encode_png(1, 1, pixels)
            fname = name + ".dehazed.png"
            (output / fname).write_bytes(data)
            outputs[name] = hashlib.sha256(data).hexdigest()
            records.append(dict(status="processed", input=name, output=fname, width=1, height=1,
                                workers={peer: 1}, tile_workers=[peer], elapsed_ms=0.5))
        records.append(dict(status="summary", processed=len(self.sources), resumed=0, failed=0))
        return outputs, "\n".join(json.dumps(record) for record in records).encode()

    def test_unused_peer_and_digest_mismatch_remain_failures(self):
        both = [("canon.cr2", "a"), ("nikon.nef", "b")]
        expected, original = self.render(self.root, both)
        verified, _, _ = bench.verify_run(original, self.root, self.sources, {"a", "b"}, 256, expected)
        self.assertEqual(verified, expected)
        observed, changed = self.render(self.root, both, changed=True)
        for peers, unused in (({"a", "b", "c"}, ["c"]), ({"a", "b"}, [])):
            with self.subTest(peers=peers), self.assertRaises(bench.BatchVerificationError) as failure:
                bench.verify_run(changed, self.root, self.sources, peers, 256, expected)
            details = failure.exception.observations
            self.assertEqual(details["unused_workers"], unused)
            self.assertEqual(details["output_sha256"], observed)
            self.assertIs(details["compared_output_hashes_match"], False)
            self.assertEqual(details["digest_mismatches"], {
                name: {"expected": expected[name], "actual": observed[name]} for name in self.sources
            })

    def test_missing_source_and_hash_state_without_reference(self):
        outputs, raw = self.render(self.root, [("canon.cr2", "a")])
        with self.assertRaises(bench.BatchVerificationError) as failure:
            bench.verify_run(raw, self.root, self.sources, {"a"}, 256, None)
        details = failure.exception.observations
        self.assertEqual(details["missing_sources"], ["nikon.nef"])
        self.assertEqual(details["output_sha256"], outputs)
        self.assertIsNone(details["compared_output_hashes_match"])

    def test_missing_output_does_not_mislabel_matching_bytes(self):
        expected, _ = self.render(self.root, [(name, "a") for name in self.sources])
        _, raw = self.render(self.root, [("canon.cr2", "a")])
        with self.assertRaises(bench.BatchVerificationError) as failure:
            bench.verify_run(raw, self.root, self.sources, {"a"}, 256, expected)
        details = failure.exception.observations
        self.assertEqual(details["missing_from_outputs"], ["nikon.nef"])
        self.assertEqual(details["digest_mismatches"], {})
        self.assertIs(details["compared_output_hashes_match"], True)
        self.assertNotIn("digest mismatch", str(failure.exception))

    def test_absent_reference_entry_is_distinct_from_mismatching_bytes(self):
        observed, raw = self.render(self.root, [(name, "a") for name in self.sources])
        with self.assertRaises(bench.BatchVerificationError) as failure:
            bench.verify_run(raw, self.root, self.sources, {"a"}, 256, {"other.nef": observed["nikon.nef"]})
        details = failure.exception.observations
        self.assertEqual(details["missing_from_reference"], ["canon.cr2", "nikon.nef"])
        self.assertEqual(details["missing_from_outputs"], ["other.nef"])
        self.assertEqual(details["digest_mismatches"], {})
        self.assertIsNone(details["compared_output_hashes_match"])

    def test_main_persists_failed_arm_without_a_speedup(self):
        sources = self.root / "input"
        sources.mkdir()
        for name in self.sources:
            (sources / name).write_bytes(name.encode())
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({name: bench.sha256(sources / name) for name in self.sources}))
        report = self.root / "report.json"
        argv = ["benchmark", "--input-dir", str(sources), "--manifest", str(manifest),
                "--cli", sys.executable, "--scratch", str(self.root), "--report", str(report),
                "--single-home", str(self.root), "--mesh-home", str(self.root), "--plugin", "test",
                "--worker", "a", "--worker", "b", "--worker", "c"]
        statuses = [{"local_peer_id": "a"}, {"local_peer_id": "coordinator"}, {"plugins": ["test"]}, {"plugins": []}]
        def dispatch(cmd, **kwargs):
            output = Path(cmd[cmd.index("--output-dir") + 1])
            output.mkdir()
            _, raw = self.render(output, [(name, "a") for name in self.sources])
            return subprocess.CompletedProcess(cmd, 0, raw, b"")
        with patch.object(bench.platform, "uname") as host, patch.object(sys, "argv", argv), \
                patch.object(bench, "cli_json", side_effect=statuses), \
                patch.object(bench.subprocess, "run", side_effect=dispatch), self.assertRaises(bench.BatchVerificationError):
            host.return_value._asdict.return_value = {}
            bench.main()
        result = json.loads(report.read_text())
        self.assertNotIn("median_wall_speedup", result)
        self.assertEqual(len(result["trials"]), 2)
        failure = result["trials"][1]["failed_verification"]
        self.assertEqual(failure["unused_workers"], ["b", "c"])
        self.assertEqual(failure["missing_sources"], [])
        self.assertEqual(failure["worker_tiles"], {"a": 2, "b": 0, "c": 0})
        self.assertEqual(set(failure["photos"]), set(self.sources))
        self.assertEqual(failure["photos"]["nikon.nef"], {"elapsed_ms": 0.5, "worker_tiles": {"a": 1}})
        self.assertEqual(failure["output_sha256"], result["verified_output_sha256"])
        self.assertIs(failure["compared_output_hashes_match"], True)


if __name__ == "__main__":
    unittest.main()
