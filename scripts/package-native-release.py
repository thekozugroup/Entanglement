#!/usr/bin/env python3
"""Package the native release executables and documentation deterministically."""

import argparse
import gzip
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile

from native_release_layout import DIRECTORY_MODE, RELEASE_FILES, RELEASE_TARGETS


def member(name, mode, epoch):
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = epoch
    return info


def add_file(archive, source, info):
    # Read an already-validated descriptor and exclude links and special files.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"expected a regular file at {source}")
        if (info.mode & 0o111) and not (metadata.st_mode & 0o111):
            raise ValueError(f"expected an executable at {source}")
        info.size = metadata.st_size
        archive.addfile(info, stream)


def package(source, binaries, output, basename, epoch):
    filename = basename + ".tar.gz"

    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".entangle-package-", dir=output) as scratch:
        staging = Path(scratch)
        archive = staging / filename
        with (
            archive.open("wb") as raw,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch) as compressed,
            tarfile.open(mode="w", fileobj=compressed, format=tarfile.USTAR_FORMAT) as tar,
        ):
            directory = member(basename, DIRECTORY_MODE, epoch)
            directory.type = tarfile.DIRTYPE
            tar.addfile(directory)
            for relative_path, mode in RELEASE_FILES:
                parent = binaries if mode & 0o111 else source
                path = parent / relative_path
                add_file(tar, path, member(f"{basename}/{path.name}", mode, epoch))

        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        blake3 = subprocess.check_output(["b3sum", "--no-names", str(archive)], text=True).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", blake3):
            raise ValueError("b3sum did not return a BLAKE3 digest")

        sidecars = {filename + ".sha256": digest.hexdigest(), filename + ".b3": blake3}
        for name, checksum in sidecars.items():
            (staging / name).write_bytes(f"{checksum}  {filename}\n".encode("ascii"))
        # Publish without replacing a previous attempt. The first sidecar
        # also excludes competing writers of the same asset name.
        published = []
        try:
            for name in (*sidecars, filename):
                final = output / name
                os.link(staging / name, final)
                published.append(final)
        except OSError:
            for final in published:
                final.unlink(missing_ok=True)
            raise
    return filename


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="The release workflow takes the epoch from the checked-out tag's commit (%ct). "
        "The archive uses that epoch for every tar member and the gzip header. Use the "
        "same compression implementation and identical inputs to reproduce its bytes. "
        "Archive and checksum paths must be unused in the output directory.",
    )
    parser.add_argument("--version", required=True, help="release tag such as v0.1.0")
    parser.add_argument("--target", required=True, choices=RELEASE_TARGETS)
    parser.add_argument("--bin-dir", required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int, metavar="SECONDS")
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    args = parser.parse_args()

    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?", args.version):
        parser.error("expected an installable vX.Y.Z release tag")
    basename = f"entanglement-{args.version}-{args.target}"
    if len(basename) >= 100:
        parser.error("release archive directory name is too long for USTAR")
    if not 0 <= args.source_date_epoch <= 0xFFFFFFFF:
        parser.error("source-date-epoch must fit the unsigned 32-bit gzip timestamp")
    try:
        result = package(Path(__file__).resolve().parents[1], args.bin_dir, args.output_dir,
                         basename, args.source_date_epoch)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"packaging native release failed: {error}\n")
    print(result)


if __name__ == "__main__":
    main()
