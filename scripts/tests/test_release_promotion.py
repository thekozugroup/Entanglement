#!/usr/bin/env python3
"""Exercise ordinary release signature publication failures."""

import errno
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
publish_signatures = runpy.run_path(str(SCRIPTS / "verify-release-promotion.py"))["publish_signatures"]


class SignaturePublication(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="entangle-test-promotion-")
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        scratch = directory / "scratch"
        scratch.mkdir()
        self.signatures = {}
        for index in range(4):
            final = directory / f"release-{index}.tar.gz.sig"
            staged = scratch / f"signature-{index}"
            staged.write_bytes(bytes([index]) * 64)
            self.signatures[final] = staged
        self.destinations = list(self.signatures)
        self.unrelated = directory / "notes.txt"
        self.unrelated.write_bytes(b"operator's unrelated notes")

    def test_success_publishes_all_verified_files(self):
        publish_signatures(self.signatures)
        for destination, staged in self.signatures.items():
            self.assertEqual(destination.read_bytes(), staged.read_bytes())

    def test_late_collision_preserves_existing_signature(self):
        existing = self.destinations[2]
        link = os.link

        def collide(staged, destination):
            if destination == existing:
                existing.write_bytes(b"another publisher completed this path")
            link(staged, destination)

        with patch("os.link", side_effect=collide), self.assertRaises(FileExistsError):
            publish_signatures(self.signatures)
        self.assertEqual(existing.read_bytes(), b"another publisher completed this path")
        self.assertEqual(self.unrelated.read_bytes(), b"operator's unrelated notes")
        self.assertFalse(any(path.exists() for path in self.destinations if path != existing))

    def test_io_failure_rolls_back_only_signatures_from_this_invocation(self):
        replaced, _, failure, _ = self.destinations
        link = os.link

        def fail(staged, destination):
            if destination == failure:
                replaced.unlink()
                replaced.write_bytes(b"unrelated replacement")
                raise OSError(errno.EIO, "test signature publication I/O failure")
            link(staged, destination)

        with patch("os.link", side_effect=fail), self.assertRaisesRegex(OSError, "publication I/O failure"):
            publish_signatures(self.signatures)
        self.assertEqual(replaced.read_bytes(), b"unrelated replacement")
        self.assertEqual(self.unrelated.read_bytes(), b"operator's unrelated notes")
        self.assertFalse(any(path.exists() for path in self.destinations if path != replaced))


if __name__ == "__main__":
    unittest.main()
