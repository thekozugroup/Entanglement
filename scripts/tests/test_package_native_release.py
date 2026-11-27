#!/usr/bin/env python3
"""Local release packaging regression tests using the normal command."""

import gzip
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest


PACKAGER = Path(__file__).resolve().parents[1] / "package-native-release.py"
VERSION = "v1.2.3-rc.4"
TARGET = "aarch64-apple-darwin"
EPOCH = 1700000123
BASE = f"entanglement-{VERSION}-{TARGET}"
ASSET = BASE + ".tar.gz"
CONTENTS = {
    "LICENSE": b"fixture license\n",
    "README.md": b"fixture readme\n",
    "docs/architecture.md": b"fixture architecture\n",
    "entangle": b"#!/bin/sh\nexit 0\n",
    "entangled": b"#!/bin/sh\nexit 1\n",
    "docs/tutorial.md": b"fixture tutorial\n",
}


class Packaging(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="entangle-test-package-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def fixture(self, name, mtime, user_only=False):
        source = self.root / name
        (source / "scripts").mkdir(parents=True)
        (source / "docs").mkdir()
        binaries = source / "binaries"
        binaries.mkdir()
        script = source / "scripts" / PACKAGER.name
        shutil.copyfile(PACKAGER, script)
        for relative, data in CONTENTS.items():
            executable = relative in ("entangle", "entangled")
            path = (binaries if executable else source) / relative
            path.write_bytes(data)
            mode = 0o700 if executable else 0o600
            path.chmod(mode if user_only else 0o775)
            os.utime(path, (mtime, mtime))
        return script, binaries

    def package(self, fixture, destination, umask=0o022, timezone="UTC"):
        script, binaries = fixture
        return subprocess.run(
            [sys.executable, str(script), "--version", VERSION, "--target", TARGET,
             "--source-date-epoch", str(EPOCH), "--bin-dir", str(binaries),
             "--output-dir", str(destination)],
            env={**os.environ, "TZ": timezone}, umask=umask, cwd=self.root,
            text=True, capture_output=True, timeout=20,
        )

    def test_archive_and_sidecars_are_byte_identical(self):
        first, second = self.root / "out one", self.root / "out two"
        for fixture, destination, mask, timezone in [
            (self.fixture("left", 10), first, 0o022, "UTC"),
            (self.fixture("right", 20, user_only=True), second, 0o077, "Pacific/Honolulu"),
        ]:
            result = self.package(fixture, destination, mask, timezone)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, ASSET + "\n")

        artifacts = {ASSET, ASSET + ".sha256", ASSET + ".b3"}
        self.assertEqual({p.name for p in first.iterdir()}, artifacts)
        self.assertEqual({p.name for p in second.iterdir()}, artifacts)
        for name in artifacts:
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

        data = (first / ASSET).read_bytes()
        self.assertEqual(struct.unpack("<BBBBIBB", data[:10]), (0x1F, 0x8B, 8, 0, EPOCH, 2, 255))
        self.assertEqual(gzip.decompress(data)[257:265], b"ustar\x0000")
        with tarfile.open(first / ASSET, "r:gz") as archive:
            members = archive.getmembers()
            self.assertEqual([member.name for member in members],
                             [BASE, *(f"{BASE}/{Path(name).name}" for name in CONTENTS)])
            self.assertTrue(members[0].isdir())
            self.assertEqual(members[0].mode, 0o755)
            for member in members:
                self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime),
                                 (0, 0, "", "", EPOCH))
                self.assertEqual(member.pax_headers, {})
            for (original, contents), member in zip(CONTENTS.items(), members[1:], strict=True):
                self.assertTrue(member.isfile())
                self.assertEqual(member.mode, 0o755 if original in ("entangle", "entangled") else 0o644)
                self.assertEqual(archive.extractfile(member).read(), contents)

        blake3 = subprocess.check_output(["b3sum", "--no-names", str(first / ASSET)], text=True).strip()
        for suffix, digest in [(".sha256", hashlib.sha256(data).hexdigest()), (".b3", blake3)]:
            self.assertEqual((first / (ASSET + suffix)).read_bytes(), f"{digest}  {ASSET}\n".encode("ascii"))

    def test_missing_or_invalid_binary_publishes_nothing(self):
        fixture = self.fixture("invalid", 10)
        binary = fixture[1] / "entangled"
        destination = self.root / "out"
        binary.chmod(0o644)
        result = self.package(fixture, destination)
        self.assertEqual(result.returncode, 1)
        self.assertIn("expected an executable", result.stderr)
        self.assertEqual(list(destination.iterdir()), [])

        binary.unlink()
        result = self.package(fixture, destination)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(list(destination.iterdir()), [])

        binary.symlink_to(fixture[1] / "entangle")
        result = self.package(fixture, destination)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(list(destination.iterdir()), [])

    def test_conflicts_preserve_existing_files_and_remove_only_new_files(self):
        fixture = self.fixture("conflicts", 10)
        destination = self.root / "out"
        result = self.package(fixture, destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        previous = {p.name: p.read_bytes() for p in destination.iterdir()}
        (fixture[1] / "entangle").write_bytes(b"new binary")
        self.assertEqual(self.package(fixture, destination).returncode, 1)
        self.assertEqual({p.name: p.read_bytes() for p in destination.iterdir()}, previous)

        collision = self.root / "collision"
        (collision / ASSET).mkdir(parents=True)
        self.assertEqual(self.package(fixture, collision).returncode, 1)
        self.assertEqual(list(collision.iterdir()), [collision / ASSET])
        self.assertTrue((collision / ASSET).is_dir())


if __name__ == "__main__":
    unittest.main()
