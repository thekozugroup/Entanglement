"""The archive layout shared by native release packaging and promotion."""

from pathlib import Path
import struct
import tarfile


DIRECTORY_MODE = 0o755
RELEASE_FILES = (
    ("LICENSE", 0o644),
    ("README.md", 0o644),
    ("docs/architecture.md", 0o644),
    ("entangle", 0o755),
    ("entangled", 0o755),
    ("docs/tutorial.md", 0o644),
)
RELEASE_TARGETS = {
    "x86_64-unknown-linux-gnu": ("ELF64", 62),
    "aarch64-unknown-linux-gnu": ("ELF64", 183),
    "aarch64-apple-darwin": ("Mach-O", 0x0100000C),
    "x86_64-apple-darwin": ("Mach-O", 0x01000007),
}
MACHO_LOAD_COMMAND_LIMIT = 1024 * 1024


def is_elf_executable(stream, size, machine):
    header = stream.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01" or header[7] not in (0, 3):
        return False
    kind, cpu, version, entry, programs = struct.unpack_from("<HHIQQ", header, 16)
    header_size, program_size, program_count = struct.unpack_from("<HHH", header, 52)
    return (
        kind in (2, 3) and cpu == machine and version == 1 and entry != 0
        and header_size == 64 and programs >= header_size
        and program_size == 56 and program_count > 0
        and programs + program_size * program_count <= size
    )


def is_macos_executable(stream, size, machine):
    header = stream.read(32)
    if len(header) != 32:
        return False
    magic, cpu, _, kind, count, length, _, _ = struct.unpack("<8I", header)
    if (magic != 0xFEEDFACF or cpu != machine or kind != 2
            or length > min(size - len(header), MACHO_LOAD_COMMAND_LIMIT)):
        return False
    commands = stream.read(length)
    offset = 0
    macos = False
    for _ in range(count):
        if offset + 8 > len(commands):
            return False
        command, command_size = struct.unpack_from("<II", commands, offset)
        if command_size < 8 or command_size % 8 or offset + command_size > len(commands):
            return False
        if command == 0x32:  # LC_BUILD_VERSION with platform 1 for macOS.
            if command_size < 24 or struct.unpack_from("<I", commands, offset + 8)[0] != 1:
                return False
            macos = True
        elif command == 0x24:  # LC_VERSION_MIN_MACOSX, used by older linkers.
            if command_size != 16:
                return False
            macos = True
        elif command in (0x25, 0x2F, 0x30):  # Older iOS, tvOS and watchOS commands.
            return False
        offset += command_size
    return macos and offset == len(commands) == length


def verify_archive_layout(artifact: Path, target: str) -> None:
    """Match the signed archive members to the release filename."""
    root = artifact.name.removesuffix(".tar.gz")
    format_name, machine = RELEASE_TARGETS[target]
    is_expected_executable = is_elf_executable if format_name == "ELF64" else is_macos_executable
    remaining = {root: (True, DIRECTORY_MODE)}
    remaining.update({
        f"{root}/{Path(path).name}": (False, mode) for path, mode in RELEASE_FILES
    })
    try:
        with tarfile.open(artifact, "r|gz") as archive:
            for member in archive:
                expected = remaining.pop(member.name, None)
                if expected is None:
                    raise ValueError(f"{artifact.name} has an unexpected or duplicate member {member.name!r}")
                directory, mode = expected
                proper_type = member.isdir() if directory else (
                    member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.issparse()
                )
                if not proper_type or member.mode != mode:
                    raise ValueError(f"{artifact.name} member {member.name!r} has an incorrect type or mode")
                if not directory and mode & 0o111:
                    with archive.extractfile(member) as executable:
                        if not is_expected_executable(executable, member.size, machine):
                            raise ValueError(
                                f"{artifact.name} member {member.name!r} is not a {target} native executable"
                            )
    except (tarfile.TarError, EOFError) as error:
        raise ValueError(f"invalid release archive {artifact.name}: {error}") from error
    if remaining:
        raise ValueError(f"{artifact.name} is missing required members: {', '.join(sorted(remaining))}")
