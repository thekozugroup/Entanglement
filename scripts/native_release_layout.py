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
MACHO_FAT_TABLE_LIMIT = 1024 * 1024
MACHO_64_MAGIC = b"\xcf\xfa\xed\xfe"
MACHO_FAT_ARCHES = {
    b"\xca\xfe\xba\xbe": struct.Struct(">5I"),
    b"\xca\xfe\xba\xbf": struct.Struct(">IIQQII"),
}


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


def check_macos_slice(stream, size, machine, expected_subtype=None):
    if size < 32:
        return False
    # The caller has consumed this slice's four-byte Mach-O magic.
    header = stream.read(28)
    if len(header) != 28:
        return False
    cpu, subtype, kind, count, length, _, _ = struct.unpack("<7I", header)
    if (cpu != machine or kind != 2 or length > min(size - 32, MACHO_LOAD_COMMAND_LIMIT)
            or (expected_subtype is not None and (subtype ^ expected_subtype) & 0x00FFFFFF)):
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


def skip_bytes(stream, count):
    # Tar delivery is forward-only. Never request an entire inter-slice gap.
    while count > 0:
        chunk = stream.read(min(count, 64 * 1024))
        if not chunk:
            return False
        count -= len(chunk)
    return True


def is_macos_executable(stream, size, machine):
    magic = stream.read(4)
    if magic == MACHO_64_MAGIC:
        return check_macos_slice(stream, size, machine)
    layout = MACHO_FAT_ARCHES.get(magic)
    if layout is None:
        return False
    header = stream.read(4)
    if len(header) != 4:
        return False
    count = struct.unpack(">I", header)[0]
    table_length = count * layout.size
    if count == 0 or table_length > min(size - 8, MACHO_FAT_TABLE_LIMIT):
        return False
    table_end = 8 + table_length
    slices = []
    architectures = set()
    for _ in range(count):
        record = stream.read(layout.size)
        if len(record) != layout.size:
            return False
        cpu, subtype, offset, length, alignment, *reserved = layout.unpack(record)
        architecture = (cpu, subtype)
        if (architecture in architectures or any(reserved) or offset < table_end or length == 0
                or offset + length > size or alignment > 63 or offset % (1 << alignment)):
            return False
        architectures.add(architecture)
        slices.append((offset, length, cpu, subtype))

    previous_end = table_end
    found = False
    for offset, length, cpu, subtype in sorted(slices):
        if offset < previous_end:
            return False
        previous_end = offset + length
        if cpu != machine:
            continue
        if (length < 32 or not skip_bytes(stream, offset - stream.tell())
                or stream.read(4) != MACHO_64_MAGIC or not check_macos_slice(stream, length, cpu, subtype)):
            return False
        found = True
    return found


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
