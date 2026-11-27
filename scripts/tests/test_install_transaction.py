#!/usr/bin/env python3
"""Exercise pair validation, publication and rollback through the POSIX installer."""

from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"
TAG = "v1.2.3"
ASSET = f"entanglement-{TAG}-x86_64-unknown-linux-gnu"
FILES = ("entangle", "entangled")


class InstallerTransaction(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="entangle installer ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.prefix = self.work / "install here"
        self.bin = self.prefix / "bin"
        self.lock = self.bin / ".entangle-install.lock"
        self.stub = self.work / "stub"
        self.stub.mkdir()
        self.archive = self.work / (ASSET + ".tar.gz")
        self.checksum = self.archive.with_name(self.archive.name + ".sha256")
        self.requests = self.work / "requests"
        self.env = {
            **os.environ,
            "HOME": str(self.work),
            "PATH": f"{self.stub}:{os.defpath}",
            "ENTANGLE_INSTALL_OS": "linux",
            "ENTANGLE_INSTALL_ARCH": "x86_64",
            "FIXTURE_ARCHIVE": str(self.archive),
            "FIXTURE_REQUESTS": str(self.requests),
            "FIXTURE_REAL_MV": shutil.which("mv"),
        }
        self.executable(
            self.stub / "curl",
            """#!/bin/sh
set -eu
[ "$#" -eq 7 ]
[ "$1" = -fsSL ] && [ "$2" = --proto ] && [ "$3" = =https ]
[ "$4" = --tlsv1.2 ] && [ "$5" = -o ]
url="https://github.com/thekozugroup/Entanglement/releases/download/v1.2.3/${FIXTURE_ARCHIVE##*/}"
case "$7" in
    "$url") cp "$FIXTURE_ARCHIVE" "$6" ;;
    "$url.sha256") cp "$FIXTURE_ARCHIVE.sha256" "$6" ;;
    *) exit 2 ;;
esac
printf '%s\\n' "$7" >> "$FIXTURE_REQUESTS"
""",
        )
        self.executable(
            self.stub / "mv",
            """#!/bin/sh
set -eu
case "$2" in
    */.entangle-install.lock/new/entangled)
        [ "${FIXTURE_FAILURE:-}" != publish ] || exit 1
        [ "${FIXTURE_FAILURE:-}" != restore ] || exit 1
        ;;
    */.entangle-install.lock/previous/entangle)
        [ "${FIXTURE_FAILURE:-}" != restore ] || exit 1
        ;;
    */.entangle-install.lock/new/entangle)
        if [ "${FIXTURE_FAILURE:-}" = interrupt ]; then
            "$FIXTURE_REAL_MV" "$@"
            # The direct parent is the installer process for this private prefix.
            kill -TERM "$PPID"
            exit 0
        fi
        ;;
esac
exec "$FIXTURE_REAL_MV" "$@"
""",
        )
        self.package()

    def executable(self, path, body):
        path.write_text(body)
        path.chmod(0o755)

    def file(self, name, version, release):
        if version is None:
            return b"#!/bin/sh\nprintf 'fixture could not start\\n' >&2\nexit 126\n"
        return f"#!/bin/sh\n# {release}\nprintf '%s\\n' '{name} {version}'\n".encode()

    def package(self, daemon_version="1.2.3", include_daemon=True):
        members = list(FILES) if include_daemon else ["entangle"]
        with tarfile.open(self.archive, "w:gz") as archive:
            for name in members:
                version = "1.2.3" if name == "entangle" else daemon_version
                data = self.file(name, version, "new")
                member = tarfile.TarInfo(f"{ASSET}/{name}")
                member.mode = 0o755
                member.size = len(data)
                archive.addfile(member, BytesIO(data))
        self.checksum.write_text(f"{sha256(self.archive.read_bytes()).hexdigest()}  {self.archive.name}\n")

    def previous(self, version="1.2.2"):
        self.bin.mkdir(parents=True)
        for name in FILES:
            self.executable(self.bin / name, self.file(name, version, "old").decode())

    def pair(self):
        return tuple((self.bin / name).read_bytes() for name in FILES)

    def install(self, *args, failure="", expected=0, cleared=True):
        command = ["/bin/sh", INSTALLER, "--version", TAG, "--prefix", self.prefix, *args]
        if os.getuid() == 0:
            command.append("--allow-root")
        run = subprocess.run(
            command, env={**self.env, "FIXTURE_FAILURE": failure},
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(run.returncode, expected, run.stdout + run.stderr)
        self.assertEqual(self.lock.exists(), not cleared, run.stderr)
        return run.stderr

    def test_same_version_skip_and_repair(self):
        self.previous("1.2.3")
        self.assertIn("already installed", self.install())
        self.assertFalse(self.requests.exists())
        (self.bin / "entangled").unlink()
        self.install()
        self.assertEqual(self.pair(), tuple(self.file(name, "1.2.3", "new") for name in FILES))
        self.assertEqual(len(self.requests.read_text().splitlines()), 2)

    def test_missing_or_unusable_daemon_preserves_previous_pair(self):
        self.previous()
        before = self.pair()
        for version, include, message in (
            ("1.2.3", False, "not found inside"),
            ("1.2.2", True, "Expected entangled 1.2.3"),
            (None, True, "fixture could not start"),
        ):
            with self.subTest(version=version, include=include):
                self.package(version, include)
                self.assertIn(message, self.install(expected=1))
                self.assertEqual(self.pair(), before)

    def test_forced_publish_failure_restores_original_pair(self):
        self.previous("1.2.3")
        before = self.pair()
        identity = tuple((self.bin / name).stat().st_ino for name in FILES)
        self.assertIn("could not install", self.install("--force", failure="publish", expected=1))
        self.assertEqual(self.pair(), before)
        self.assertEqual(tuple((self.bin / name).stat().st_ino for name in FILES), identity)

    def test_failed_first_install_removes_partial_pair(self):
        self.assertIn("could not install", self.install(failure="publish", expected=1))
        self.assertFalse(any((self.bin / name).exists() for name in FILES))

    def test_publication_interrupt_rolls_back(self):
        self.previous()
        before = self.pair()
        self.install(failure="interrupt", expected=143)
        self.assertEqual(self.pair(), before)

    def test_restore_failure_retains_recovery_files(self):
        self.previous()
        before = self.pair()
        text = self.install(failure="restore", expected=1, cleared=False)
        self.assertIn("Recovery files are in", text)
        self.assertEqual((self.lock / "previous" / "entangle").read_bytes(), before[0])
        self.assertEqual((self.bin / "entangled").read_bytes(), before[1])

    def test_another_install_keeps_its_staging_directory(self):
        self.previous("1.2.3")
        before = self.pair()
        self.lock.mkdir()
        sentinel = self.lock / "in progress"
        sentinel.write_text("other install")
        self.assertIn("could not reserve", self.install(expected=1, cleared=False))
        self.assertEqual(sentinel.read_text(), "other install")
        self.assertFalse(self.requests.exists())
        self.assertEqual(self.pair(), before)


if __name__ == "__main__":
    unittest.main()
