import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "rust_test_sharder", Path(__file__).resolve().parents[1] / "run-rust-tests.py"
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

RUNNING_ONE = "\nrunning 1 test\n"
SUFFIX = "0 measured; 57 filtered out; finished in 0.00s\n\n"
IGNORED = RUNNING_ONE + "i\ntest result: ok. 0 passed; 0 failed; 1 ignored; " + SUFFIX
PASSED = RUNNING_ONE + ".\ntest result: ok. 1 passed; 0 failed; 0 ignored; " + SUFFIX
FAILED = RUNNING_ONE + "F\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; " + SUFFIX
PANIC = "thread 'case' (1) panicked at fixture.rs:7:5:\nassertion failed\n"
PEERS = ["worker-a", "worker-b"]


def capture(stdout, exit_code=0, stderr=""):
    return dict(stdout=stdout, stderr=stderr, exit_code=exit_code)


class ClassifyTests(unittest.TestCase):
    def test_completed_results_and_panic_abort(self):
        for expected, result in (
            ("passed", capture(PASSED)),
            ("ignored", capture(IGNORED)),
            ("failed", capture(FAILED, 101)),
            ("failed", capture(RUNNING_ONE, None, PANIC)),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(runner.classify(result), expected)

    def test_rejects_ambiguous_or_malformed_results(self):
        for result in (
            capture(RUNNING_ONE),
            capture(IGNORED + IGNORED),
            capture(IGNORED + "test result: malformed\n"),
            capture(IGNORED.replace("finished in 0.00s", "unexpected tail")),
            capture(IGNORED.replace("0 passed", "1 passed")),
            capture(IGNORED.replace("0 measured", "1 measured")),
            capture(IGNORED.replace("ok.", "FAILED.")),
            capture(IGNORED, 101),
            capture(IGNORED, None, PANIC),
            capture(PASSED, 101),
            capture(FAILED),
            capture(RUNNING_ONE, None, "unsupported guest operation\n"),
            capture("\nrunning 0 tests\n", None, PANIC),
            capture(IGNORED.replace("running 1 test", "running 0 tests")),
            capture(IGNORED.replace("1 ignored", "0 ignored")),
        ):
            with self.subTest(result=result):
                with self.assertRaises(runner.DispatchError):
                    runner.classify(result)

    def test_captured_running_line_does_not_replace_the_libtest_header(self):
        diagnostic = "running 2 tests\napplication progress\n"
        self.assertEqual(runner.classify(capture(PASSED.replace(".\n", diagnostic + ".\n", 1))), "passed")
        self.assertEqual(runner.classify(capture(RUNNING_ONE + diagnostic, None, PANIC)), "failed")


class RetryTests(unittest.TestCase):
    def test_ignore_and_retry_keep_attempts_and_outcomes(self):
        responses = {
            "ignored": capture(IGNORED),
            "passed": capture(PASSED),
            "failed": capture(RUNNING_ONE, None, PANIC),
        }
        for sequence, retries, expected in (
            (("ignored",), 2, "ignored"),
            (("failed", "ignored"), 1, "failed"),
            (("error", "ignored"), 1, "error"),
            (("failed", "ignored", "passed"), 2, "flaky"),
            (("error", "ignored", "passed"), 2, "passed"),
        ):
            with self.subTest(sequence=sequence):
                calls = []

                def dispatch(peer, request):
                    outcome = sequence[len(calls)]
                    calls.append((peer, request))
                    if outcome == "error":
                        raise runner.DispatchError("connection lost")
                    return {"peer": peer, **responses[outcome]}

                result = runner.run_test(dispatch, PEERS, 0, "case", False, retries)
                self.assertEqual(result["status"], expected)
                self.assertEqual(len(calls), len(sequence))
                self.assertEqual(
                    [(a["attempt"], a["peer"], a["status"]) for a in result["attempts"]],
                    [(i, PEERS[(i - 1) % len(PEERS)], status) for i, status in enumerate(sequence, 1)],
                )
                for attempt, (_, request) in enumerate(calls, 1):
                    self.assertEqual(request, {"operation": "test", "name": "case",
                                               "ignored": False, "attempt": attempt})
                if sequence[0] == "error":
                    self.assertEqual(result["attempts"][0]["error"], "connection lost")


class SuiteTests(unittest.TestCase):
    def test_listed_and_target_ignores_are_distinct(self):
        for include_ignored in (False, True):
            with self.subTest(include_ignored=include_ignored):
                calls = {}

                def dispatch(peer, request):
                    if request["operation"] == "list":
                        stdout = "listed: test\n"
                        if not request.get("ignored"):
                            stdout += "runtime: test\n"
                        return {"peer": peer, **capture(stdout)}
                    calls[request["name"]] = (peer, request["ignored"])
                    return {"peer": peer, **capture(IGNORED)}

                args = SimpleNamespace(peer=PEERS, socket=None, timeout_ms=1000, filter=None,
                                       exact=False, skip=[], ignored=False, include_ignored=include_ignored,
                                       retries=1)
                with patch.object(runner, "dispatcher", return_value=dispatch):
                    report = runner.run_suite(args, "plugin")
                self.assertEqual(report["counts"], dict(passed=0, flaky=0, failed=0, ignored=2, error=0))
                listed, runtime = report["results"]
                self.assertEqual(runtime["name"], "runtime")
                self.assertEqual(runtime["status"], "ignored")
                self.assertEqual(len(runtime["attempts"]), 1)
                self.assertEqual(runtime["attempts"][0]["peer"], calls["runtime"][0])
                self.assertEqual(runtime["attempts"][0]["status"], "ignored")
                self.assertEqual(len(listed["attempts"]), int(include_ignored))
                self.assertFalse(calls["runtime"][1])
                if include_ignored:
                    self.assertTrue(calls["listed"][1])
                    self.assertEqual(listed["attempts"][0]["status"], "ignored")
                else:
                    self.assertNotIn("listed", calls)


if __name__ == "__main__":
    unittest.main()
