"""Test the operator runner's libtest-compatible name selection."""

from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "rust_test_selectors", Path(__file__).resolve().parents[1] / "run-rust-tests.py"
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

NAMES = {"alpha::first", "alpha::second", "alpha::ignored", "beta::first", "beta::second", "gamma"}
IGNORED = {"alpha::ignored"}


class Selectors(unittest.TestCase):
    def select(self, filters, skips=(), *, exact=False, ignored=False):
        def completed(_dispatch, _peers, _index, name, _listed_as_ignored, _retries):
            return {"name": name, "status": "passed", "attempts": []}

        args = SimpleNamespace(peer=["worker-a", "worker-b"], socket=None, timeout_ms=1000,
                               filter=filters, skip=skips, exact=exact, ignored=ignored,
                               include_ignored=False, retries=0)
        with (
            patch.object(runner, "dispatcher"),
            patch.object(runner, "suite_listing", return_value=(NAMES, IGNORED)),
            patch.object(runner, "run_test", side_effect=completed),
        ):
            report = runner.run_suite(args, "plugin")
        selected = [row["name"] for row in report["results"]]
        self.assertEqual(report["filtered"], len(NAMES) - len(selected))
        return selected

    def test_any_filter_includes_and_any_skip_excludes(self):
        self.assertEqual(
            self.select(["alpha", "beta", "alpha"], ["::second", "::ignored"]),
            ["alpha::first", "beta::first"],
        )

    def test_exact_applies_to_both_filters_and_skips(self):
        self.assertEqual(
            self.select(["alpha::first", "alpha", "beta::second"], ["alpha::", "beta::second"], exact=True),
            ["alpha::first"],
        )
        self.assertEqual(self.select([], ["alpha::", "beta::first"], exact=True), sorted(NAMES - {"beta::first"}))

    def test_empty_and_legacy_scalar_filters_keep_their_meaning(self):
        self.assertEqual(self.select(None), sorted(NAMES))
        self.assertEqual(self.select([]), sorted(NAMES))
        self.assertEqual(self.select("alpha", ["second"]), ["alpha::first", "alpha::ignored"])
        self.assertEqual(self.select(["alpha", "beta"], ignored=True), ["alpha::ignored"])

    def test_cli_collects_all_filters_in_order(self):
        command = ["run-rust-tests.py", "example", "--peer", "1" * 32,
                   "--filter", "alpha", "--filter", "beta", "--skip", "gamma", "--exact"]
        result = {"counts": {"failed": 0, "error": 0}}
        with (
            patch.object(runner.sys, "argv", command),
            patch.object(runner, "run_suites", return_value=result) as run,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(runner.main(), 0)
        args, = run.call_args.args
        self.assertEqual(args.filter, ["alpha", "beta"])
        self.assertEqual(args.skip, ["gamma"])
        self.assertTrue(args.exact)


if __name__ == "__main__":
    unittest.main()
