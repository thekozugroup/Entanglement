"""Regression tests for binary scoring and evidence binding."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("production_score", ROOT / "scripts/production_score.py")
score = importlib.util.module_from_spec(spec)
spec.loader.exec_module(score)
RUBRIC = json.loads(score.RUBRIC.read_text())
SOURCE = "sha256:" + "a" * 64


class ProductionScoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.joinpath("log.txt").write_text("test fixture only\n")
        digest = hashlib.sha256(self.root.joinpath("log.txt").read_bytes()).hexdigest()
        ev = {"path": "log.txt", "sha256": digest, "source_id": SOURCE, "command": "fixture",
              "claim": "test-only mock evidence", "observed_at_utc": "2026-11-27T00:00:00Z", "exit_code": 0}
        self.run = {"rubric_sha256": score.RUBRIC_SHA256, "source_id": SOURCE,
                    "observations": {item["id"]: {"status": "pass", "reason": "test-only mock",
                         "reviewer": "test", "reviewed_at_utc": "2026-11-27T00:00:00Z", "evidence": [copy.deepcopy(ev)]}
                         for item in RUBRIC["checks"]}}

    def test_all_pass_and_no_average_masking(self):
        self.assertTrue(score.score(RUBRIC, self.run, self.root)["ready_over_95"])
        self.run["observations"]["INTEROP-TAILNET"] = {"status": "not_evidenced", "reason": "no two hosts"}
        result = score.score(RUBRIC, self.run, self.root)
        self.assertFalse(result["ready_over_95"])
        self.assertIn("INTEROP-TAILNET", [x["id"] for x in result["blockers"]])
        self.assertTrue(result["metrics"]["correctness"]["over_95"])

    def test_frozen_historical_review_and_rubric_are_intact(self):
        baseline = ROOT / "docs/testing/production-review/baseline-2026-11-26.md"
        self.assertEqual(hashlib.sha256(baseline.read_bytes()).hexdigest(),
                         "d4be6378b0de2fff49da822504777560303f314924eff4650c8e91f3c17f2f59")
        self.assertEqual(hashlib.sha256(score.RUBRIC.read_bytes()).hexdigest(), score.RUBRIC_SHA256)

    def test_strict_threshold_is_not_rounded(self):
        self.assertFalse(score.strict_over_95(19, 20))
        self.assertTrue(score.strict_over_95(20, 21))
        self.assertFalse(score.strict_over_95(0, 0))

    def test_missing_and_failed_are_distinct_blockers(self):
        self.run["observations"]["ATC-BUS-1"] = {"status": "fail", "reason": "roster insufficient"}
        self.run["observations"]["ATC-BUS-2"] = {"status": "not_evidenced", "reason": "review absent"}
        result = score.score(RUBRIC, self.run, self.root)
        self.assertEqual(result["metrics"]["release_operations"]["fail"], 1)
        self.assertEqual(result["metrics"]["release_operations"]["not_evidenced"], 1)

    def test_pass_needs_intact_exact_source_evidence_and_reviewer(self):
        obs = self.run["observations"]["ATC-MAN-1"]
        obs["evidence"][0]["source_id"] = "sha256:" + "b" * 64
        with self.assertRaises(ValueError): score.score(RUBRIC, self.run, self.root)
        obs["evidence"][0]["source_id"] = SOURCE
        obs["evidence"][0]["exit_code"] = 1
        with self.assertRaises(ValueError): score.score(RUBRIC, self.run, self.root)
        obs["evidence"][0]["exit_code"] = 0
        obs["reviewer"] = ""
        with self.assertRaises(ValueError): score.score(RUBRIC, self.run, self.root)
        obs["reviewer"] = "test"
        self.root.joinpath("log.txt").write_text("tampered\n")
        with self.assertRaises(ValueError): score.score(RUBRIC, self.run, self.root)

    def test_missing_extra_partial_or_changed_rubric_rejected(self):
        del self.run["observations"]["ATC-MAN-1"]
        with self.assertRaises(ValueError): score.score(RUBRIC, self.run, self.root)
        self.run["observations"]["ATC-MAN-1"] = {"status": "partial", "reason": "not binary"}
        with self.assertRaises(ValueError): score.score(RUBRIC, self.run, self.root)
        changed = copy.deepcopy(RUBRIC)
        changed["checks"][0]["requirement"] = "easier"
        with self.assertRaises(ValueError): score.score(changed, self.run, self.root)

    def test_path_escape_rejected(self):
        self.run["observations"]["ATC-MAN-1"]["evidence"][0]["path"] = "../outside"
        with self.assertRaises(ValueError): score.score(RUBRIC, self.run, self.root)


if __name__ == "__main__":
    unittest.main()
