#!/usr/bin/env python3
"""Local release packaging regression tests using the normal command."""

import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from native_release_layout import verify_archive_layout


PACKAGER = SCRIPTS / "package-native-release.py"
VERSION = "v1.2.3-rc.4"
TARGET = "aarch64-apple-darwin"
EPOCH = 1700000123
BASE = f"entanglement-{VERSION}-{TARGET}"
ASSET = BASE + ".tar.gz"


def macho_executable(machine=0x0100000C, platform=1, kind=2, legacy=False):
    if legacy:
        command = struct.pack("<4I", 0x24, 16, 0x000B0000, 0x000E0000)
    else:
        command = struct.pack("<6I", 0x32, 24, platform, 0x000B0000, 0x000E0000, 0)
    return struct.pack("<8I", 0xFEEDFACF, machine, 0, kind, 1, len(command), 0, 0) + command


def elf_executable(machine=62, entry=0x400080):
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHI3QI6H", ident, 3, machine, 1, entry, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    return header + struct.pack("<2I6Q", 1, 5, 0, 0x400000, 0x400000, 120, 120, 4096)


CONTENTS = {
    "LICENSE": b"fixture license\n",
    "README.md": b"fixture readme\n",
    "docs/architecture.md": b"fixture architecture\n",
    "entangle": macho_executable() + b"cli\n",
    "entangled": macho_executable() + b"daemon\n",
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
        shutil.copyfile(SCRIPTS / "native_release_layout.py", script.parent / "native_release_layout.py")
        for relative, data in CONTENTS.items():
            executable = relative in ("entangle", "entangled")
            path = (binaries if executable else source) / relative
            path.write_bytes(data)
            mode = 0o700 if executable else 0o600
            path.chmod(mode if user_only else 0o775)
            os.utime(path, (mtime, mtime))
        return script, binaries

    def package(self, fixture, destination, umask=0o022, timezone="UTC", target=TARGET):
        script, binaries = fixture
        return subprocess.run(
            [sys.executable, str(script), "--version", VERSION, "--target", target,
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

        verify_archive_layout(first / ASSET, TARGET)
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

    def test_promotion_binds_archive_members_to_the_release_tag_and_target(self):
        destination = self.root / "staged"
        result = self.package(self.fixture("tagged", 10), destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        other_target = "x86_64-apple-darwin"
        for name, target in (
            (ASSET.replace(VERSION, "v1.2.4"), TARGET),
            (ASSET.replace(TARGET, other_target), other_target),
        ):
            with self.subTest(name=name):
                artifact = destination / name
                shutil.copyfile(destination / ASSET, artifact)
                with self.assertRaisesRegex(ValueError, "unexpected or duplicate member"):
                    verify_archive_layout(artifact, target)

    def test_promotion_requires_each_regular_executable_exactly_once(self):
        artifact = self.root / ASSET
        for condition, message in (
            ("missing", "missing required members"),
            ("duplicate", "unexpected or duplicate member"),
            ("link", "incorrect type or mode"),
            ("mode", "incorrect type or mode"),
        ):
            with self.subTest(condition=condition):
                with tarfile.open(artifact, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
                    directory = tarfile.TarInfo(BASE)
                    directory.type = tarfile.DIRTYPE
                    directory.mode = 0o755
                    archive.addfile(directory)
                    for path, content in CONTENTS.items():
                        name = Path(path).name
                        member = tarfile.TarInfo(f"{BASE}/{name}")
                        member.mode = 0o755 if name in ("entangle", "entangled") else 0o644
                        if name == "entangled":
                            if condition == "missing":
                                continue
                            if condition == "link":
                                member.type = tarfile.SYMTYPE
                                member.linkname = "entangle"
                                archive.addfile(member)
                                continue
                            if condition == "mode":
                                member.mode = 0o644
                        member.size = len(content)
                        archive.addfile(member, io.BytesIO(content))
                        if name == "entangled" and condition == "duplicate":
                            archive.addfile(member, io.BytesIO(content))
                with self.assertRaisesRegex(ValueError, message):
                    verify_archive_layout(artifact, TARGET)

    def test_promotion_requires_both_binaries_to_match_the_target(self):
        cases = (
            ("x86_64-unknown-linux-gnu", elf_executable(), (elf_executable(183), elf_executable(entry=0))),
            ("aarch64-unknown-linux-gnu", elf_executable(183), (elf_executable(), macho_executable())),
            ("x86_64-apple-darwin", macho_executable(0x01000007, legacy=True), (macho_executable(),)),
            (TARGET, macho_executable(), (macho_executable(platform=2), macho_executable(kind=6), b"\xca\xfe\xba\xbe" * 8)),
        )
        for target, valid, invalid in cases:
            with self.subTest(target=target):
                script, binaries = self.fixture(target, 10)
                (binaries / "entangle").write_bytes(valid)
                name = f"entanglement-{VERSION}-{target}.tar.gz"
                for index, candidate in enumerate((valid, *invalid)):
                    (binaries / "entangled").write_bytes(candidate)
                    destination = self.root / f"{target}-{index}"
                    result = self.package((script, binaries), destination, target=target)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if index == 0:
                        verify_archive_layout(destination / name, target)
                    else:
                        with self.assertRaisesRegex(ValueError, f"/entangled'.*not a {target} native executable"):
                            verify_archive_layout(destination / name, target)

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
