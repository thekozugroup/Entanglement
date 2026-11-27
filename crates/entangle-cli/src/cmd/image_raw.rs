//! Operator-local LibRaw conversion to linear RGB16 with sRGB primaries.
//! The two fixed executables come from Debian's libraw-bin or Homebrew's libraw.
//! Tested with Debian libraw-bin 0.21.4-2+deb13u1 (LibRaw 0.21.4).

use anyhow::{bail, ensure, Context, Result};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

pub(super) const MAX_INPUT_BYTES: u64 = 128 << 20;
const MAX_PIXELS: u64 = 32_000_000;
const MAX_DIMENSION: u32 = 32_768;
const MAX_HEADER: u64 = 1024;
const MAX_PPM_BYTES: u64 = MAX_PIXELS * 6 + MAX_HEADER;

// Limit native CPU and staging space even when the caller schedules many inputs.
static DECODER: Mutex<()> = Mutex::new(());

pub(super) struct DecodedRaw {
    ppm: NamedTempFile,
    hash: blake3::Hash,
}

impl DecodedRaw {
    pub(super) fn path(&self) -> &Path {
        self.ppm.path()
    }

    pub(super) fn input_hash(&self) -> blake3::Hash {
        self.hash
    }
}

pub(super) fn is_raw(path: &Path) -> bool {
    const EXTENSIONS: &[&str] = &[
        "3fr", "arw", "cr2", "cr3", "crw", "dcr", "dng", "erf", "kdc", "mef", "mos", "mrw", "nef",
        "nrw", "orf", "pef", "raf", "raw", "rw2", "sr2", "srf", "srw", "x3f",
    ];
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| EXTENSIONS.iter().any(|e| extension.eq_ignore_ascii_case(e)))
}

fn pixel_count(width: u32, height: u32) -> Result<u64> {
    let count = u64::from(width) * u64::from(height);
    ensure!(
        width > 0
            && height > 0
            && width <= MAX_DIMENSION
            && height <= MAX_DIMENSION
            && count <= MAX_PIXELS,
        "RAW dimensions {width} × {height} exceed the supported range (32 MP, 32768 per axis)"
    );
    Ok(count)
}

fn stage(source: &mut File, output: &mut File) -> Result<blake3::Hash> {
    let metadata = source.metadata()?;
    ensure!(metadata.is_file(), "RAW input must be a regular file");
    ensure!(
        (1..=MAX_INPUT_BYTES).contains(&metadata.len()),
        "RAW input must be 1 byte through 128 MiB"
    );
    source.rewind()?;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0;
    let mut buffer = [0; 32 * 1024];
    loop {
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= metadata.len(), "RAW input grew during staging");
        output.write_all(&buffer[..n])?;
        hasher.update(&buffer[..n]);
    }
    ensure!(total == metadata.len(), "RAW input shrank during staging");
    Ok(hasher.finalize())
}

fn dimensions(record: &[u8]) -> Result<(u32, u32)> {
    // raw-identify can exit successfully for unsupported files and emit no record.
    // Camera metadata may contain non-UTF8 bytes. Only interpret the numeric fields.
    let line = record
        .strip_suffix(b"\n")
        .context("LibRaw did not identify a RAW image")?;
    ensure!(
        !line.contains(&b'\n'),
        "unexpected additional RAW identification record"
    );
    let fields: Vec<_> = line.split(|b| *b == b'\t').collect();
    ensure!(
        fields.len() == 5 && fields[0] == b"input.raw",
        "invalid LibRaw size record"
    );
    let number = |bytes| -> Result<u32> { Ok(std::str::from_utf8(bytes)?.parse()?) };
    let (width, height) = (number(fields[3])?, number(fields[4])?);
    pixel_count(width, height)?;
    Ok((width, height))
}

fn validate_ppm(ppm: &mut File) -> Result<()> {
    let length = ppm.metadata()?.len();
    ensure!(length <= MAX_PPM_BYTES, "LibRaw output exceeds 32 MP RGB16");
    ppm.rewind()?;
    let mut input = BufReader::new(ppm.take(MAX_HEADER));
    let mut line = String::new();
    let mut header_size = input.read_line(&mut line)?;
    ensure!(line == "P6\n", "LibRaw did not produce RGB P6");
    line.clear();
    header_size += input.read_line(&mut line)?;
    let mut fields = line.split_ascii_whitespace();
    let width = fields.next().context("missing P6 width")?.parse()?;
    let height = fields.next().context("missing P6 height")?.parse()?;
    ensure!(fields.next().is_none(), "unexpected P6 dimension field");
    let count = pixel_count(width, height)?;
    line.clear();
    header_size += input.read_line(&mut line)?;
    ensure!(line == "65535\n", "LibRaw did not produce 16-bit samples");
    ensure!(
        length == header_size as u64 + count * 6,
        "incorrect P6 raster length"
    );
    Ok(())
}

#[cfg(unix)]
fn executable(name: &str) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&path).filter(|p| p.is_absolute()) {
        let candidate = directory.join(name);
        if candidate
            .metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        {
            return Ok(candidate);
        }
    }
    bail!("missing {name} on PATH; install LibRaw tools (Debian: libraw-bin, Homebrew: libraw)")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_tool(
    tool: &Path,
    args: &[&str],
    dir: &Path,
    stdout: &File,
    file_limit: u64,
    wall: Duration,
) -> Result<()> {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    use std::os::unix::process::CommandExt;

    let limits = [
        (Resource::As, 2 << 30),
        (Resource::Cpu, wall.as_secs()),
        (Resource::Fsize, file_limit),
        (Resource::Core, 0),
    ]
    .map(|(resource, cap)| {
        let existing = getrlimit(resource);
        let limit = cap
            .min(existing.current.unwrap_or(cap))
            .min(existing.maximum.unwrap_or(cap));
        (
            resource,
            Rlimit {
                current: Some(limit),
                maximum: Some(limit),
            },
        )
    });
    let diagnostic = tempfile::tempfile()?;
    let mut command = Command::new(tool);
    command
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("LC_ALL", "C")
        .env("OMP_NUM_THREADS", "1")
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(diagnostic.try_clone()?);
    // SAFETY: after fork, only setrlimit syscalls and errno conversion occur, with no allocations or locks.
    unsafe {
        command.pre_exec(move || {
            for &(resource, limit) in &limits {
                setrlimit(resource, limit)?;
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("starting {}", tool.display()))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    let mut diagnostic = diagnostic;
                    diagnostic.rewind()?;
                    let mut bytes = Vec::new();
                    diagnostic.take(512).read_to_end(&mut bytes)?;
                    let message = String::from_utf8_lossy(&bytes);
                    bail!("{} exited {status}: {:?}", tool.display(), message.trim());
                }
                return Ok(());
            }
            Ok(None) if start.elapsed() < wall => std::thread::sleep(Duration::from_millis(20)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                result?;
                bail!(
                    "{} exceeded its {}s deadline",
                    tool.display(),
                    wall.as_secs()
                );
            }
        }
    }
}

pub(super) fn decode_raw_file(file: &mut File, source: &Path) -> Result<DecodedRaw> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        decode(file).with_context(|| format!("decoding camera RAW {}", source.display()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (file, source);
        bail!("bounded camera RAW decoding requires Linux or macOS")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn decode(file: &mut File) -> Result<DecodedRaw> {
    let _slot = DECODER
        .lock()
        .map_err(|_| anyhow::anyhow!("RAW decoder unavailable"))?;
    let identify = executable("raw-identify")?;
    let render = executable("dcraw_emu")?;
    let temporary = tempfile::tempdir()?;
    // Camera-supplied names, paths and metadata never become executable names or options.
    let hash = stage(file, &mut File::create(temporary.path().join("input.raw"))?)?;
    let mut metadata = tempfile::tempfile()?;
    run_tool(
        &identify,
        &["-s", "input.raw"],
        temporary.path(),
        &metadata,
        4096,
        Duration::from_secs(15),
    )?;
    metadata.rewind()?;
    let mut record = Vec::new();
    metadata.take(4097).read_to_end(&mut record)?;
    ensure!(record.len() <= 4096, "oversized RAW identification record");
    dimensions(&record)?;
    let mut ppm = NamedTempFile::new()?;
    // -4 selects linear 16-bit output and disables auto-brightening. LibRaw's normal
    // pipeline applies camera black calibration, demosaicing, WB and the color matrix.
    run_tool(
        &render,
        &["-4", "-w", "-o", "1", "-Z", "-", "input.raw"],
        temporary.path(),
        ppm.as_file(),
        MAX_PPM_BYTES,
        Duration::from_secs(60),
    )?;
    validate_ppm(ppm.as_file_mut())?;
    Ok(DecodedRaw { ppm, hash })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_requires_one_bounded_size_record() {
        assert_eq!(
            dimensions(b"input.raw\tKodak\tDC50\t768\t512\n").unwrap(),
            (768, 512)
        );
        assert!(dimensions(b"").is_err());
        assert!(dimensions(b"input.raw\tcam\tmodel\t8192\t4096\n").is_err());
        assert!(dimensions(b"input.raw\tcam\tmodel\t1\t32769\n").is_err());
        assert!(dimensions(b"input.raw\tcam\tmodel\t2\t3\nextra\n").is_err());
    }

    #[test]
    fn output_requires_exact_rgb16_payload() {
        let check = |data: &[u8]| {
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(data).unwrap();
            validate_ppm(&mut file)
        };
        assert!(check(b"P6\n1 1\n65535\nabcdef").is_ok());
        assert!(check(b"P6\n1 1\n65535\nabcde").is_err());
        assert!(check(b"P6\n1 1\n65535\nabcdefg").is_err());
        assert!(check(b"P6\n1 1\n255\nabc").is_err());
    }

    #[test]
    fn staging_hashes_the_open_descriptor_from_offset_zero() {
        let mut src = tempfile::tempfile().unwrap();
        src.write_all(b"already-open").unwrap();
        let mut dest = tempfile::tempfile().unwrap();
        assert_eq!(
            stage(&mut src, &mut dest).unwrap(),
            blake3::hash(b"already-open")
        );
    }
    #[test]
    fn rejects_oversized_source_before_copying() {
        let mut source = tempfile::tempfile().unwrap();
        source.set_len(MAX_INPUT_BYTES + 1).unwrap();
        let mut dest = tempfile::tempfile().unwrap();
        assert!(stage(&mut source, &mut dest).is_err());
        assert_eq!(dest.metadata().unwrap().len(), 0);
    }

    // CC0 files and input SHA-256 are pinned in docs/testing/raw-image-fixtures.md.
    // Pixel hashes were obtained independently with LibRaw's -6 -W -g 1 1 -o 1 -w.
    #[test]
    #[ignore = "requires Debian LibRaw 0.21.4 and the two CC0 files in ENTANGLE_RAW_FIXTURES"]
    fn libraw_camera_samples() -> Result<()> {
        let dir = PathBuf::from(
            std::env::var_os("ENTANGLE_RAW_FIXTURES")
                .context("set ENTANGLE_RAW_FIXTURES per docs/testing/raw-image-fixtures.md")?,
        );
        for (name, size, source_hash, pixel_hash) in [
            (
                "nikon_d40.nef",
                "3039 2014",
                "9d30436b8c980a294687e407e7189511e4d985f07f7a261bbd698a1959032273",
                "7e34121e1f3a142e4f823d402e7ae5169db01878157c306647177e94c3ae11c8",
            ),
            (
                "canon_350d.cr2",
                "3474 2314",
                "fc1607d95f73f9e52af675e61633e90760152eeb41c0cf8b844c777a0a1e7043",
                "67ff18c233ae444848c14a4cb76caf77192f88da9ef4aa6068abdd464147f94e",
            ),
        ] {
            let path = dir.join(name);
            let decoded = decode_raw_file(&mut File::open(&path)?, &path)?;
            assert_eq!(decoded.input_hash().to_hex().as_str(), source_hash);
            let mut input = BufReader::new(File::open(decoded.path())?);
            let header: Vec<_> = input
                .by_ref()
                .lines()
                .take(3)
                .collect::<std::io::Result<_>>()?;
            assert_eq!(header, ["P6", size, "65535"]);
            let hash = blake3::Hasher::new().update_reader(input)?.finalize();
            assert_eq!(hash.to_hex().as_str(), pixel_hash);
        }
        Ok(())
    }
}
