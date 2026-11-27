"""Test the POSIX Entanglement installer with strict, local-only asset delivery."""

import argparse
import hashlib
import io
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile


RELEASES = "https://github.com/thekozugroup/Entanglement/releases/download"
TOOLS = "awk cat chmod cp dirname find gzip grep head id mkdir mktemp mv rm tar tr".split()
PROGRAMS = ("entangle", "entangled")


def asset_label(tag, target):
    return f"entanglement-{tag}-{target}"


def make_fixture(path, label, version):
    with tarfile.open(path, "w:gz") as archive:
        for name in PROGRAMS:
            content = f"#!/bin/sh\nprintf '%s\\n' '{name} {version}'\n".encode()
            entry = tarfile.TarInfo(f"{label}/{name}")
            entry.mode = 0o755
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))


def executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


def case(root, script, os_name, arch, target, hash_tool, tag, mode, real_archive=None):
    label = asset_label(tag, target)
    filename = f"{label}.tar.gz"
    root.mkdir()
    asset_dir = root / "assets"
    asset_dir.mkdir()
    archive = asset_dir / filename
    if real_archive is not None:
        assert real_archive.name == filename, real_archive
        archive.symlink_to(real_archive)
        sidecar = Path(f"{real_archive}.sha256")
        assert sidecar.is_file(), sidecar
        expected = sidecar.read_text().split()[0].lower()
        with archive.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == expected
        shutil.copyfile(sidecar, asset_dir / f"{filename}.sha256")
    else:
        make_fixture(archive, label, tag[1:])
        expected = hashlib.sha256(archive.read_bytes()).hexdigest()
        displayed = "0" * 64 if mode == "mismatch" else expected.upper()
        if mode != "missing":
            (asset_dir / f"{filename}.sha256").write_text(f"{displayed}  deliberately-different-filename\n")

    binary_dir = root / "tools"
    binary_dir.mkdir()
    for name in TOOLS:
        (binary_dir / name).symlink_to(shutil.which(name))
    executable(binary_dir / hash_tool, f"#!/bin/sh\nprintf '%s\\n' {hash_tool} >> \"$FIXTURE_HASH_LOG\"\n"
                                      f"exec {shlex.quote(shutil.which(hash_tool))} \"$@\"\n")
    archive_url = f"{RELEASES}/{tag}/{filename}"
    executable(binary_dir / "curl", """#!/bin/sh
set -eu
[ "$#" -eq 7 ] && [ "$1" = -fsSL ] && [ "$2" = --proto ] && [ "$3" = '=https' ] && [ "$4" = --tlsv1.2 ] && [ "$5" = -o ] || exit 2
printf '%s\n' "$7" >> "$FIXTURE_CURL_LOG"
case "$7" in
  "$FIXTURE_URL"|"$FIXTURE_URL.sha256") cp "$FIXTURE_ASSETS/${7##*/}" "$6" ;;
  *) exit 3 ;;
esac
""")
    isolated_home = root / "home"
    isolated_home.mkdir()
    bin_dir = isolated_home / "install/bin"
    hash_log = root / "hash.log"
    url_log = root / "url.log"
    env = {**os.environ, "HOME": str(isolated_home), "PATH": str(binary_dir),
           "ENTANGLE_INSTALL_OS": os_name, "ENTANGLE_INSTALL_ARCH": arch,
           "FIXTURE_HASH_LOG": str(hash_log), "FIXTURE_CURL_LOG": str(url_log),
           "FIXTURE_URL": archive_url, "FIXTURE_ASSETS": str(asset_dir)}
    version_arg = tag[1:] if real_archive is not None else tag
    argv = ["/bin/sh", str(script), "--version", version_arg, "--prefix", str(bin_dir)]
    result = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=120)
    print(f"{os_name}/{arch} {hash_tool} mode={mode}, {'native archive' if real_archive else 'synthetic archive'}")
    print(f"  {shlex.join(argv)} -> {result.returncode}")
    print(f"  Entangle override env: OS={os_name} ARCH={arch}; local downloader only")
    if result.returncode != (0 if mode == "positive" else 1):
        raise AssertionError(result.stderr + result.stdout)
    assert url_log.read_text().splitlines() == [archive_url, f"{archive_url}.sha256"]
    print(f"  requested {archive_url} and adjacent .sha256, no latest lookup")
    if mode == "missing":
        assert not hash_log.exists() and "checksum file missing" in result.stderr
    else:
        assert hash_log.read_text().splitlines() == [hash_tool], result.stderr
    if mode == "positive":
        assert f"ok: {expected}" in result.stderr, result.stderr
        print(f"  matched SHA-256 {expected}")
        with tarfile.open(archive) as bundle:
            for name in PROGRAMS:
                with bundle.extractfile(f"{label}/{name}") as source, (bin_dir / name).open("rb") as installed:
                    source_hash = hashlib.file_digest(source, "sha256").hexdigest()
                    assert hashlib.file_digest(installed, "sha256").hexdigest() == source_hash
                version = subprocess.check_output([bin_dir / name, "--version"], env=env, text=True).strip()
                assert version == f"{name} {tag[1:]}", version
                print(f"  {version}, installed SHA-256 {source_hash}")
    else:
        reason = "SHA-256 MISMATCH" if mode == "mismatch" else "checksum file missing"
        assert reason in result.stderr and "Extracting" not in result.stderr, result.stderr
        assert not any(bin_dir.iterdir())
        print(f"  rejected before extraction or installation: {reason}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    script = Path("scripts/install.sh").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="ent-final-install-", dir="/tmp") as tmp:
        root = Path(tmp)
        linux_target = "x86_64-unknown-linux-gnu"
        mac_target = "aarch64-apple-darwin"
        for number, mode in enumerate(("positive", "mismatch", "missing")):
            case(root / f"l{number}", script, "linux", "x86_64", linux_target, "sha256sum", "v1.2.3-rc.4", mode)
            case(root / f"m{number}", script, "darwin", "aarch64", mac_target, "shasum", "v1.2.3-rc.4", mode)
        case(root / "openssl", script, "linux", "x86_64", linux_target, "openssl", "v1.2.3-rc.4", "positive")
        if args.archive is not None:
            case(root / "native", script, "linux", "x86_64", linux_target, "sha256sum", "v0.1.0", "positive",
                 args.archive.resolve(strict=True))


if __name__ == "__main__":
    main()
