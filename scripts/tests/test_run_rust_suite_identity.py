"""Exercise signed suite pinning through the operator's normal RPC client."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "rust_suite_identity", Path(__file__).resolve().parents[1] / "run-rust-tests.py"
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

PIN = {"artifact_blake3": "a" * 64, "manifest_blake3": "b" * 64}
FOREIGN = {**PIN, "manifest_blake3": "c" * 64}
WORKERS = ["1" * 32, "2" * 32]
SUFFIX = "0 measured; 0 filtered out; finished in 0.00s\n\n"
PASSED = "\nrunning 1 test\n.\ntest result: ok. 1 passed; 0 failed; 0 ignored; " + SUFFIX
FAILED = ("\nrunning 1 test\ncase --- FAILED\n\nfailures:\n\nfailures:\n    case\n\n"
          "test result: FAILED. 0 passed; 1 failed; 0 ignored; " + SUFFIX)


def response(peer, payload, identity=PIN, exit_code=0):
    output = {"stdout": payload, "stderr": "", "exit_code": exit_code}
    if identity is not None:
        output["suite_identity"] = identity
    return {"chosen_peer": peer, "output": list(json.dumps(output).encode())}


def args(retries):
    return SimpleNamespace(peer=WORKERS, socket=None, timeout_ms=1000, filter=None,
                           skip=[], exact=False, ignored=False, include_ignored=False,
                           retries=retries)


class SuiteIdentityTests(unittest.TestCase):
    def run_cluster(self, reply, retries=0):
        def rpc(_socket, method, params, _timeout):
            self.assertEqual(method, "compute/dispatch")
            peer, = params["integrity"]["allowlist"]
            return reply(peer, json.loads(bytes(params["input"])))

        with patch.object(runner, "rpc", side_effect=rpc):
            return runner.run_suite(args(retries), "publisher/example@0.1.0")

    def test_pin_is_sent_on_every_later_listing_and_attempt(self):
        calls = []

        def reply(peer, request):
            calls.append((peer, request))
            if request["operation"] == "list":
                return response(peer, "" if request.get("ignored") else "case: test\n")
            if peer == WORKERS[0]:
                return response(peer, FAILED, exit_code=101)
            return response(peer, PASSED)

        report = self.run_cluster(reply, retries=2)
        self.assertEqual(calls[0], (WORKERS[0], {"operation": "list"}))
        self.assertEqual(calls[1], (WORKERS[0], {"operation": "list", "ignored": True,
                                                 "expected_suite_identity": PIN}))
        for _, request in calls[1:]:
            self.assertEqual(request["expected_suite_identity"], PIN)
        self.assertEqual(report["suite_identity"], PIN)
        result, = report["results"]
        self.assertEqual(result["status"], "flaky")
        self.assertEqual([item["suite_identity"] for item in result["attempts"]], [PIN, PIN])

    def test_identical_names_do_not_hide_a_different_signed_package(self):
        def reply(peer, request):
            self.assertEqual(request["operation"], "list")
            return response(peer, "" if request.get("ignored") else "case: test\n",
                            PIN if peer == WORKERS[0] else FOREIGN)

        with self.assertRaisesRegex(runner.SuiteIdentityError, WORKERS[1] + ".*identity mismatch"):
            self.run_cluster(reply)

    def test_ignored_inventory_cannot_change_the_pin(self):
        def reply(peer, request):
            self.assertEqual(peer, WORKERS[0])
            self.assertEqual(request["operation"], "list")
            if request.get("ignored"):
                self.assertEqual(request["expected_suite_identity"], PIN)
                return response(peer, "", FOREIGN)
            return response(peer, "case: test\n")

        with self.assertRaisesRegex(runner.SuiteIdentityError, WORKERS[0] + ".*identity mismatch"):
            self.run_cluster(reply)

    def test_a_mismatch_on_retry_is_terminal_and_preserves_prior_failure(self):
        for reject_in_host in (False, True):
            with self.subTest(reject_in_host=reject_in_host):
                attempts = []

                def reply(peer, request):
                    if request["operation"] == "list":
                        return response(peer, "" if request.get("ignored") else "case: test\n")
                    self.assertEqual(request["expected_suite_identity"], PIN)
                    attempts.append((peer, request["attempt"]))
                    if request["attempt"] == 1:
                        return response(peer, FAILED, exit_code=101)
                    if reject_in_host:
                        raise runner.DispatchError("rejected: libtest suite identity mismatch")
                    return response(peer, PASSED, FOREIGN)

                report = self.run_cluster(reply, retries=3)
                result, = report["results"]
                self.assertEqual(attempts, [(WORKERS[0], 1), (WORKERS[1], 2)])
                self.assertEqual(result["status"], "error")
                first, second = result["attempts"]
                self.assertEqual(first["status"], "failed")
                self.assertEqual(first["stdout"], FAILED)
                self.assertEqual(second["error_kind"], "suite_identity")
                self.assertIn("identity mismatch", second["error"])

    def test_legacy_worker_reports_an_upgrade_error(self):
        def old_first(peer, request):
            self.assertEqual(request, {"operation": "list"})
            return response(peer, "case: test\n", identity=None)

        def old_second(peer, request):
            if peer == WORKERS[1]:
                self.assertEqual(request["expected_suite_identity"], PIN)
                raise runner.DispatchError("invalid libtest request: unknown field `expected_suite_identity`")
            return response(peer, "" if request.get("ignored") else "case: test\n")

        for peer, legacy in zip(WORKERS, [old_first, old_second], strict=True):
            with self.subTest(peer=peer):
                with self.assertRaisesRegex(runner.SuiteIdentityError, peer + ".*upgrade the worker daemon"):
                    self.run_cluster(legacy)

    def test_initial_identity_must_contain_two_canonical_digests(self):
        for malformed in ([], {}, {**PIN, "manifest_blake3": "B" * 64},
                          {**PIN, "artifact_blake3": 1}, {**PIN, "extra": "token"}):
            with self.subTest(identity=malformed):
                with self.assertRaisesRegex(runner.SuiteIdentityError, "invalid libtest suite identity"):
                    self.run_cluster(lambda peer, _: response(peer, "case: test\n", malformed))


if __name__ == "__main__":
    unittest.main()
