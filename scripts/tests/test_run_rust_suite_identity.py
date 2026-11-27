"""Exercise signed suite pinning through the operator's normal RPC client."""

import importlib.util
import io
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
                        raise runner.RpcError("runtime rejected request", "suite-identity-mismatch")
                    return response(peer, PASSED, FOREIGN)

                report = self.run_cluster(reply, retries=3)
                result, = report["results"]
                self.assertEqual(attempts, [(WORKERS[0], 1), (WORKERS[1], 2)])
                self.assertEqual(result["status"], "error")
                first, second = result["attempts"]
                self.assertEqual(first["status"], "failed")
                self.assertEqual(first["stdout"], FAILED)
                self.assertEqual(second["error_kind"], "suite_identity")
                if reject_in_host:
                    self.assertEqual(second["remote_code"], "suite-identity-mismatch")
                    self.assertIn("runtime rejected request", second["error"])
                else:
                    self.assertIn("identity mismatch", second["error"])

    def test_legacy_worker_reports_an_upgrade_error(self):
        def old_first(peer, request):
            self.assertEqual(request, {"operation": "list"})
            return response(peer, "case: test\n", identity=None)

        def old_second(peer, request):
            if peer == WORKERS[1]:
                self.assertEqual(request["expected_suite_identity"], PIN)
                raise runner.RpcError("worker could not decode request", "execution")
            return response(peer, "" if request.get("ignored") else "case: test\n")

        with self.assertRaisesRegex(runner.SuiteIdentityError, WORKERS[0] + ".*upgrade the worker daemon"):
            self.run_cluster(old_first)
        with self.assertRaisesRegex(runner.DispatchError,
                                   WORKERS[1] + ".*could not decode request.*supports signed libtest suite pinning"):
            self.run_cluster(old_second)

    def test_a_different_or_missing_executor_is_terminal(self):
        for chosen in (WORKERS[1], None):
            with self.subTest(chosen=chosen):
                def reply(peer, request):
                    if request["operation"] == "list":
                        return response(peer, "" if request.get("ignored") else "case: test\n")
                    self.assertEqual(request["attempt"], 1)
                    data = response(chosen, PASSED)
                    if chosen is None:
                        del data["chosen_peer"]
                    return data

                report = self.run_cluster(reply, retries=3)
                result, = report["results"]
                self.assertEqual(result["status"], "error")
                attempt, = result["attempts"]
                self.assertEqual(attempt["error_kind"], "executor_integrity")
                self.assertEqual(attempt["peer"], WORKERS[0])
                self.assertIn(f"returned executor {chosen!r}", attempt["error"])

    def test_structured_security_rejections_are_terminal_even_without_matching_text(self):
        for code in ("not-authorized", "plugin-not-loaded"):
            with self.subTest(code=code):
                def reply(peer, request):
                    if request["operation"] == "list":
                        return response(peer, "" if request.get("ignored") else "case: test\n")
                    self.assertEqual(request["attempt"], 1)
                    raise runner.RpcError("request rejected", code)

                result, = self.run_cluster(reply, retries=3)["results"]
                self.assertEqual(result["status"], "error")
                attempt, = result["attempts"]
                self.assertEqual(attempt["error_kind"], "remote_rejected")
                self.assertEqual(attempt["remote_code"], code)

    def test_untrusted_messages_cannot_stop_an_ordinary_retry(self):
        for error in (runner.DispatchError("transport disconnected"),
                      runner.RpcError("libtest suite identity mismatch"),
                      runner.RpcError("unknown field expected_suite_identity", "execution")):
            with self.subTest(error=error):
                def reply(peer, request):
                    if request["operation"] == "list":
                        return response(peer, "" if request.get("ignored") else "case: test\n")
                    if peer == WORKERS[0]:
                        raise error
                    return response(peer, PASSED)

                result, = self.run_cluster(reply, retries=1)["results"]
                self.assertEqual(result["status"], "passed")
                self.assertEqual([attempt["status"] for attempt in result["attempts"]], ["error", "passed"])
                self.assertEqual(result["attempts"][0]["error"], str(error))
                self.assertNotIn("error_kind", result["attempts"][0])

    def test_initial_identity_must_contain_two_canonical_digests(self):
        for malformed in ([], {}, {**PIN, "manifest_blake3": "B" * 64},
                          {**PIN, "artifact_blake3": 1}, {**PIN, "extra": "token"}):
            with self.subTest(identity=malformed):
                with self.assertRaisesRegex(runner.SuiteIdentityError, "invalid libtest suite identity"):
                    self.run_cluster(lambda peer, _: response(peer, "case: test\n", malformed))


class CoordinatorProtocolTests(unittest.TestCase):
    def test_rpc_reads_only_nested_structured_code(self):
        for data, expected in (({"remote_code": "not-authorized"}, "not-authorized"),
                               ({"remote_code": 1}, None), ("not-authorized", None), (None, None)):
            with self.subTest(data=data), patch.object(runner.socket, "socket") as socket:
                error = {"code": -32000, "message": "arbitrary worker message", "data": data,
                         "remote_code": "plugin-not-loaded"}
                reply = {"jsonrpc": "2.0", "id": 1, "error": error}
                stream = socket.return_value.__enter__.return_value
                stream.makefile.return_value = io.BytesIO(json.dumps(reply).encode() + b"\n")
                with self.assertRaises(runner.RpcError) as rejection:
                    runner.rpc("/tmp/unused", "compute/dispatch", None, 1)
                self.assertEqual(rejection.exception.remote_code, expected)
                self.assertEqual(str(rejection.exception), error["message"])

    def test_stale_or_unknown_coordinator_stops_before_work(self):
        for advertised in ({}, {"libtest_remote_codes": 0}, {"libtest_remote_codes": 2},
                           {"libtest_remote_codes": "1"}, {"libtest_remote_codes": True}):
            with self.subTest(advertised=advertised), patch.object(runner, "rpc") as rpc:
                rpc.return_value = {"local_peer_id": "0" * 32, **advertised}
                with self.assertRaisesRegex(runner.DispatchError, "upgrade the coordinator daemon"):
                    runner.run_suites(args(0))
                rpc.assert_called_once_with(None, "mesh/status", None, 10)

    def test_current_coordinator_processes_suites_and_refuses_self_as_worker(self):
        options = args(0)
        options.plugins = ["publisher/example@0.1.0"]
        with (patch.object(runner, "rpc") as rpc, patch.object(runner, "run_suite") as run):
            rpc.return_value = {"local_peer_id": "0" * 32, "libtest_remote_codes": 1}
            run.return_value = {"counts": dict.fromkeys(runner.STATUSES, 0), "filtered": 0}
            self.assertEqual(runner.run_suites(options)["suites"], [run.return_value])
            run.assert_called_once_with(options, options.plugins[0])
            rpc.return_value["local_peer_id"] = WORKERS[0]
            with self.assertRaisesRegex(runner.DispatchError, "distinct remote peer identities"):
                runner.run_suites(options)
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
