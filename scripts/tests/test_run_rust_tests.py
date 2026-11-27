from collections import deque
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import threading
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
FAILED = (RUNNING_ONE + "case --- FAILED\n\nfailures:\n\nfailures:\n    case\n\n"
          "test result: FAILED. 0 passed; 1 failed; 0 ignored; " + SUFFIX)
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
                self.assertEqual(runner.classify(result, "case"), expected)

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
            capture(PASSED.replace(".\ntest result", "logged 1 passed\ntest result", 1)),
            capture(PASSED.removesuffix("\n")),
            capture(PASSED.replace(".\ntest result", "i\ntest result", 1)),
            capture(FAILED.replace("    case\n", "    different\n"), 1),
            capture(IGNORED + "test: different, ignore_message: other test\n\n"),
        ):
            with self.subTest(result=result):
                with self.assertRaises(runner.DispatchError):
                    runner.classify(result, "case")

    def test_captured_running_line_does_not_replace_the_libtest_header(self):
        diagnostic = "running 2 tests\napplication progress\n"
        self.assertEqual(runner.classify(capture(PASSED.replace(".\n", diagnostic + ".\n", 1)), "case"), "passed")
        self.assertEqual(runner.classify(capture(RUNNING_ONE + diagnostic, None, PANIC), "case"), "failed")

    def test_captured_result_lines_are_not_libtest_completion(self):
        diagnostic = "test result: previous parser accepted the input\n"
        quoted = PASSED.splitlines()[-2] + "\n"
        for line in (diagnostic, quoted):
            with self.subTest(line=line):
                successful = RUNNING_ONE + line + "inline log" + PASSED.removeprefix(RUNNING_ONE)
                aborted = RUNNING_ONE + line
                self.assertEqual(runner.classify(capture(successful), "case"), "passed")
                self.assertEqual(runner.classify(capture(aborted, None, PANIC), "case"), "failed")
                with self.assertRaises(runner.DispatchError):
                    runner.classify(capture(aborted), "case")

    def test_ignored_summary_can_have_a_named_reason(self):
        stdout = IGNORED + "test: case, ignore_message: unavailable on this target\ntest result: not run\n\n"
        self.assertEqual(runner.classify(capture(stdout), "case"), "ignored")


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

                with ThreadPoolExecutor(max_workers=len(PEERS)) as executor:
                    results = {"case": {"name": "case", "attempts": []}}
                    runner.schedule_tests(executor, dispatch, PEERS, deque(["case"]),
                                          set(), retries, results)
                result = results["case"]
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


class SchedulingTests(unittest.TestCase):
    def failed(self, peer, name):
        return {"peer": peer, **capture(FAILED.replace("case", name), 101)}

    def schedule(self, names, peers, retries, dispatch):
        results = {name: {"name": name, "attempts": []} for name in names}
        with ThreadPoolExecutor(max_workers=len(peers)) as executor:
            runner.schedule_tests(executor, dispatch, peers, deque(names), set(), retries, results)
        return results

    def test_available_worker_takes_independent_tests_without_a_backlog(self):
        names = ["a_long", "b_short", "c_short", "d_last"]
        started = threading.Event()
        released = threading.Event()

        def dispatch(peer, request):
            name = request["name"]
            if name == "a_long":
                started.set()
                if not released.wait(5):
                    raise runner.DispatchError("the free worker did not drain the queue")
            else:
                if not started.wait(5):
                    raise runner.DispatchError("the long test did not start")
                if name == "d_last":
                    released.set()
            return {"peer": peer, **capture(PASSED)}

        # Count submissions, including anything hidden in the executor's queue.
        class MeasuredExecutor(ThreadPoolExecutor):
            def __init__(self):
                super().__init__(max_workers=len(PEERS))
                self.futures = []
                self.peak = 0

            def submit(self, fn, *args):
                self.futures = [future for future in self.futures if not future.done()]
                self.peak = max(self.peak, len(self.futures) + 1)
                future = super().submit(fn, *args)
                self.futures.append(future)
                return future

        results = {name: {"name": name, "attempts": []} for name in names}
        with MeasuredExecutor() as executor:
            runner.schedule_tests(executor, dispatch, PEERS, deque(names), set(), 0, results)
        self.assertEqual(executor.peak, len(PEERS))
        self.assertEqual([results[name]["status"] for name in names], ["passed"] * 4)
        self.assertEqual([results[name]["attempts"][0]["peer"] for name in names],
                         [PEERS[0], PEERS[1], PEERS[1], PEERS[1]])

    def test_waiting_retry_leaves_previous_worker_free_for_new_work(self):
        long_started = threading.Event()
        fresh_started = threading.Event()

        def dispatch(peer, request):
            name = request["name"]
            if name == "a_retry" and request["attempt"] == 1:
                if not long_started.wait(5):
                    raise runner.DispatchError("long case never started")
                return self.failed(peer, name)
            if name == "b_long":
                long_started.set()
                if not fresh_started.wait(5):
                    raise runner.DispatchError("new work stalled behind a retry")
            if name == "c_fresh":
                fresh_started.set()
            return {"peer": peer, **capture(PASSED)}

        cases = self.schedule(["a_retry", "b_long", "c_fresh"], PEERS, 1, dispatch)
        self.assertEqual(cases["a_retry"]["status"], "flaky")
        self.assertEqual([a["peer"] for a in cases["a_retry"]["attempts"]], PEERS)
        self.assertEqual(cases["b_long"]["status"], "passed")
        self.assertEqual(cases["c_fresh"]["attempts"][0]["peer"], PEERS[0])

    def test_simultaneous_retries_rotate_between_workers(self):
        barrier = threading.Barrier(2)

        def dispatch(peer, request):
            if request["attempt"] == 1:
                barrier.wait(timeout=5)
                return self.failed(peer, request["name"])
            return {"peer": peer, **capture(PASSED)}

        results = self.schedule(["first", "second"], PEERS, 1, dispatch)
        for name, order in [("first", PEERS), ("second", PEERS[::-1])]:
            self.assertEqual(results[name]["status"], "flaky")
            self.assertEqual([a["peer"] for a in results[name]["attempts"]], order)
            self.assertEqual([a["attempt"] for a in results[name]["attempts"]], [1, 2])

    def test_only_case_on_one_worker_exhausts_bounded_retries(self):
        def dispatch(peer, request):
            return self.failed(peer, request["name"])

        result = self.schedule(["only"], PEERS[:1], 10, dispatch)["only"]
        self.assertEqual(result["status"], "failed")
        self.assertEqual([a["attempt"] for a in result["attempts"]], list(range(1, 12)))
        self.assertEqual({a["peer"] for a in result["attempts"]}, {PEERS[0]})

    def test_unexpected_exception_is_an_attempt_error_and_other_cases_finish(self):
        def dispatch(peer, request):
            if request["name"] == "only_error":
                raise RuntimeError("fixture unavailable")
            return {"peer": peer, **capture(PASSED)}

        results = self.schedule(["only_error", "works"], PEERS, 1, dispatch)
        self.assertEqual(results["works"]["status"], "passed")
        self.assertEqual(results["only_error"]["status"], "error")
        attempts = results["only_error"]["attempts"]
        self.assertEqual([a["peer"] for a in attempts], PEERS)
        self.assertTrue(all(a["error"] == "unexpected RuntimeError: fixture unavailable"
                            for a in attempts))


class SuiteTests(unittest.TestCase):
    def test_listed_and_target_ignores_are_distinct(self):
        for include_ignored in (False, True):
            with self.subTest(include_ignored=include_ignored):
                calls = {}

                def dispatch(peer, request):
                    identity = {"artifact_blake3": "1" * 64, "manifest_blake3": "2" * 64}
                    if request["operation"] == "list":
                        stdout = "listed: test\n"
                        if not request.get("ignored"):
                            stdout += "runtime: test\n"
                        return {"peer": peer, "suite_identity": identity, **capture(stdout)}
                    calls[request["name"]] = (peer, request["ignored"])
                    return {"peer": peer, "suite_identity": identity, **capture(IGNORED)}

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
