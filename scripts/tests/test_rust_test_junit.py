import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


SCRIPT = Path(__file__).resolve().parents[1] / "rust-test-junit.py"
SPEC = importlib.util.spec_from_file_location("rust_test_junit", SCRIPT)
junit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(junit)


def report_fixture():
    counts = dict(passed=1, failed=1, error=1, flaky=1, ignored=1)

    def attempt(number, status):
        return dict(attempt=number, peer=f"peer-{number}", status=status,
                    stdout='Rust output: λ<&>\x01', stderr="first line\nsecond line",
                    exit_code=0 if status == "passed" else None)

    cases = [
        dict(name="ok", status="passed", attempts=[attempt(1, "passed")]),
        dict(name="left<&>λ\x00", status="failed", attempts=[attempt(1, "failed")]),
        dict(name="unavailable", status="error", attempts=[
            dict(attempt=1, status="error", peer="peer-1", error="connection lost")
        ]),
        dict(name="retry", status="flaky", attempts=[attempt(1, "failed"), attempt(2, "passed")]),
        dict(name="ignored", status="ignored", attempts=[]),
    ]
    suite = dict(suite="publisher/tests@1.0", counts=counts.copy(), results=cases, elapsed_ms=20)
    empty = dict(suite="filtered", counts=dict.fromkeys(counts, 0), results=[], elapsed_ms=1000)
    return dict(elapsed_ms=1021, counts=counts.copy(), suites=[suite, empty])


class JUnitTests(unittest.TestCase):
    def test_counts_identity_time_and_diagnostics_round_trip(self):
        report = report_fixture()
        source = report["suites"][0]
        source["suite_identity"] = dict(artifact_blake3="b" * 64, manifest_blake3="c" * 64)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.xml"
            junit.write_report(report, path)
            root = ET.parse(path).getroot()
        self.assertEqual(root.attrib, dict(tests="5", failures="1", errors="1", skipped="1", time="1.021"))
        full, empty = root.findall("testsuite")
        self.assertEqual((full.get("time"), empty.get("tests"), empty.get("time")), ("0.020", "0", "1.000"))
        self.assertEqual({p.get("name"): p.get("value") for p in full.findall("properties/property")},
                         source["suite_identity"])
        cases = full.findall("testcase")
        self.assertEqual(cases[1].get("name"), "left<&>λ\\x00")
        self.assertEqual([c.get("classname") for c in cases], [source["suite"]] * 5)
        self.assertEqual(cases[1].find("failure").get("message"), "first line")
        self.assertEqual(cases[2].find("error").get("message"), "connection lost")
        self.assertFalse(any(cases[3].find(tag) is not None for tag in ("failure", "error", "skipped")))
        self.assertIsNotNone(cases[4].find("skipped"))
        for case, record in zip(cases, source["results"]):
            self.assertEqual(json.loads(case.findtext("system-out")),
                             {"status": record["status"], "attempts": record["attempts"]})

    def test_cli_preserves_files_on_failure_and_exports_completed_failed_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = (Path(directory) / filename for filename in ("source.json", "report.xml"))

            def cli(destination):
                return subprocess.run([sys.executable, str(SCRIPT), source, destination],
                                      capture_output=True, text=True)

            report = report_fixture()
            source.write_text(json.dumps(report))
            self.assertEqual(cli(output).returncode, 0)
            previous = output.read_bytes()
            self.assertNotEqual(cli(source).returncode, 0)
            self.assertEqual(json.loads(source.read_text()), report)
            self.assertNotEqual(cli(Path(directory) / "missing" / "file.xml").returncode, 0)
            invalid = copy.deepcopy(report)
            invalid["suites"][0]["results"][0]["attempts"][0]["status"] = "error"
            for text in (json.dumps(invalid), json.dumps({}), "{" + " " * 100_000):
                source.write_text(text)
                result = cli(output)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Cannot convert Rust test report", result.stderr)
                self.assertEqual(output.read_bytes(), previous)
            report["counts"]["ignored"] = 7
            with self.assertRaisesRegex(ValueError, "counts disagree"):
                junit.convert(report)

    def test_duplicate_names_are_scoped_to_each_suite(self):
        report = report_fixture()
        suite, empty = report["suites"]
        empty["results"].append(copy.deepcopy(suite["results"][0]))
        empty["counts"]["passed"] += 1
        report["counts"]["passed"] += 1
        self.assertEqual(junit.convert(report).getroot().get("tests"), "6")
        empty["results"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate test case"):
            junit.convert(report)

    def test_incomplete_attempt_cannot_be_published(self):
        report = report_fixture()
        report["suites"][0]["results"][0]["attempts"][0].pop("stdout")
        with self.assertRaises(KeyError):
            junit.convert(report)
