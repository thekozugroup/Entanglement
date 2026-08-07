//! Pure, host-testable compression core. No SDK, no wasm, no I/O.

use crate::error::{Error, Result};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
use flate2::{Compression, Crc};
use std::io::{Read, Write};

/// Largest payload we accept, compressed or uncompressed, in either direction.
///
/// The wasm store is capped at 256 MiB; a decompression pass needs room for the
/// input, the sliding window and the output at once, so we budget conservatively.
pub const MAX_PAYLOAD: usize = 64 * 1024 * 1024;

/// Bytes of the container header emitted by [`compress`].
pub const HEADER_LEN: usize = 16;

/// Container magic. Its presence at offset 0 means "this is already compressed".
pub const MAGIC: &[u8; 4] = b"ENTZ";

/// Container format version understood by this build.
pub const CONTAINER_VERSION: u8 = 1;

/// Longest directive line we will scan for. Keeps binary payloads from being
/// probed byte-by-byte looking for a newline.
const MAX_DIRECTIVE_LEN: usize = 64;

/// The DEFLATE wrapper used on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// RFC 1952 gzip stream (`1f 8b`). The default.
    Gzip,
    /// RFC 1950 zlib stream.
    Zlib,
    /// RFC 1951 raw DEFLATE, no wrapper.
    Deflate,
}

impl Format {
    /// Wire tag stored in byte 5 of the container header.
    pub fn tag(self) -> u8 {
        match self {
            Format::Gzip => 1,
            Format::Zlib => 2,
            Format::Deflate => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Format::Gzip),
            2 => Ok(Format::Zlib),
            3 => Ok(Format::Deflate),
            other => Err(Error::InvalidInput(format!(
                "ENTZ header declares unknown format tag {other}; expected 1 (gzip), 2 (zlib) or 3 (deflate)"
            ))),
        }
    }

    fn from_name(name: &str) -> Result<Self> {
        match name {
            "gzip" | "gz" => Ok(Format::Gzip),
            "zlib" => Ok(Format::Zlib),
            "deflate" | "raw" => Ok(Format::Deflate),
            other => Err(Error::InvalidInput(format!(
                "unknown compression format {other:?}; expected one of gzip, zlib, deflate"
            ))),
        }
    }

    /// Canonical lowercase name, as accepted in a directive line.
    pub fn name(self) -> &'static str {
        match self {
            Format::Gzip => "gzip",
            Format::Zlib => "zlib",
            Format::Deflate => "deflate",
        }
    }
}

/// What the caller asked us to do, after directive parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Wrap the payload in an ENTZ container.
    Compress {
        /// Wrapper to use.
        format: Format,
        /// miniz_oxide level, 0 (store) to 9 (max).
        level: u32,
    },
    /// Recover the original bytes.
    Decompress {
        /// `None` means "sniff it" (ENTZ header, then gzip/zlib magic).
        format: Option<Format>,
    },
}

/// A parsed request: the mode plus the payload slice it applies to.
#[derive(Debug)]
pub struct Request<'a> {
    /// Selected operation.
    pub mode: Mode,
    /// Bytes the operation consumes, with any directive line stripped.
    pub payload: &'a [u8],
}

/// Split an optional leading ASCII directive line off `input` and decide the mode.
///
/// Resolution order — see `README.md`:
/// 1. A leading directive line (`compress\n`, `decompress:zlib\n`, ...).
/// 2. Otherwise, an `ENTZ` magic at offset 0 means decompress.
/// 3. Otherwise, compress with gzip at level 6.
pub fn parse_request(input: &[u8]) -> Result<Request<'_>> {
    if input.is_empty() {
        return Err(Error::InvalidInput(
            "empty input: expected a payload, optionally preceded by a \
             `compress`/`decompress` directive line"
                .into(),
        ));
    }
    if input.len() > MAX_PAYLOAD {
        return Err(Error::ResourceExhausted(format!(
            "input is {} bytes, over the {MAX_PAYLOAD}-byte budget",
            input.len()
        )));
    }

    if let Some((line, rest)) = split_directive(input) {
        let mode = parse_directive(line)?;
        if rest.is_empty() {
            return Err(Error::InvalidInput(format!(
                "directive {line:?} was given but the payload after it is empty"
            )));
        }
        return Ok(Request {
            mode,
            payload: rest,
        });
    }

    if input.starts_with(MAGIC) {
        return Ok(Request {
            mode: Mode::Decompress { format: None },
            payload: input,
        });
    }

    Ok(Request {
        mode: Mode::Compress {
            format: Format::Gzip,
            level: 6,
        },
        payload: input,
    })
}

/// Look for `^[a-z0-9:._-]{1,64}\n`. Returns `None` for anything else, so binary
/// payloads are passed through untouched.
fn split_directive(input: &[u8]) -> Option<(&str, &[u8])> {
    let window = &input[..input.len().min(MAX_DIRECTIVE_LEN)];
    let nl = window.iter().position(|&b| b == b'\n')?;
    if nl == 0 {
        return None;
    }
    let line = &input[..nl];
    if !line
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'.' | b'_' | b'-'))
    {
        return None;
    }
    let text = core::str::from_utf8(line).ok()?;
    if !(text.starts_with("compress") || text.starts_with("decompress")) {
        return None;
    }
    Some((text, &input[nl + 1..]))
}

fn parse_directive(line: &str) -> Result<Mode> {
    let mut parts = line.split(':');
    // `split` on a non-empty string always yields at least one item.
    let verb = parts.next().unwrap_or("");
    let mut format: Option<Format> = None;
    let mut level: Option<u32> = None;

    for tok in parts {
        if tok.is_empty() {
            return Err(Error::InvalidInput(format!(
                "directive {line:?} has an empty `:`-separated field"
            )));
        }
        if tok.bytes().all(|b| b.is_ascii_digit()) {
            let n: u32 = tok.parse().map_err(|_| {
                Error::InvalidInput(format!("compression level {tok:?} is not a number"))
            })?;
            if n > 9 {
                return Err(Error::InvalidInput(format!(
                    "compression level {n} out of range; expected 0..=9"
                )));
            }
            if level.replace(n).is_some() {
                return Err(Error::InvalidInput(format!(
                    "directive {line:?} specifies more than one compression level"
                )));
            }
        } else {
            let f = Format::from_name(tok)?;
            if format.replace(f).is_some() {
                return Err(Error::InvalidInput(format!(
                    "directive {line:?} specifies more than one format"
                )));
            }
        }
    }

    match verb {
        "compress" => Ok(Mode::Compress {
            format: format.unwrap_or(Format::Gzip),
            level: level.unwrap_or(6),
        }),
        "decompress" => {
            if level.is_some() {
                return Err(Error::InvalidInput(
                    "a compression level is meaningless for `decompress`".into(),
                ));
            }
            Ok(Mode::Decompress { format })
        }
        other => Err(Error::InvalidInput(format!(
            "unknown directive verb {other:?}; expected `compress` or `decompress`"
        ))),
    }
}

/// Top-level entrypoint: parse the envelope and run the operation.
pub fn process(input: &[u8]) -> Result<Vec<u8>> {
    let req = parse_request(input)?;
    match req.mode {
        Mode::Compress { format, level } => compress(req.payload, format, level),
        Mode::Decompress { format } => decompress(req.payload, format),
    }
}

/// Compress `data` and prepend the 16-byte ENTZ header.
pub fn compress(data: &[u8], format: Format, level: u32) -> Result<Vec<u8>> {
    if data.len() > MAX_PAYLOAD {
        return Err(Error::ResourceExhausted(format!(
            "payload is {} bytes, over the {MAX_PAYLOAD}-byte budget",
            data.len()
        )));
    }
    if level > 9 {
        return Err(Error::InvalidInput(format!(
            "compression level {level} out of range; expected 0..=9"
        )));
    }
    let original_len = u32::try_from(data.len()).map_err(|_| {
        Error::ResourceExhausted("payload length does not fit in the u32 header field".into())
    })?;

    let mut crc = Crc::new();
    crc.update(data);
    let checksum = crc.sum();

    let c = Compression::new(level);
    let body = match format {
        Format::Gzip => {
            let mut e = GzEncoder::new(Vec::new(), c);
            e.write_all(data).map_err(io_internal)?;
            e.finish().map_err(io_internal)?
        }
        Format::Zlib => {
            let mut e = ZlibEncoder::new(Vec::new(), c);
            e.write_all(data).map_err(io_internal)?;
            e.finish().map_err(io_internal)?
        }
        Format::Deflate => {
            let mut e = DeflateEncoder::new(Vec::new(), c);
            e.write_all(data).map_err(io_internal)?;
            e.finish().map_err(io_internal)?
        }
    };

    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(MAGIC);
    out.push(CONTAINER_VERSION);
    out.push(format.tag());
    out.push(level as u8);
    out.push(0); // flags, reserved
    out.extend_from_slice(&original_len.to_le_bytes());
    out.extend_from_slice(&checksum.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Recover the original bytes from `data`.
///
/// Accepts an ENTZ container (header verified, CRC32 and length checked) or a
/// bare gzip / zlib / raw-DEFLATE stream.
pub fn decompress(data: &[u8], forced: Option<Format>) -> Result<Vec<u8>> {
    if data.starts_with(MAGIC) {
        return decompress_container(data, forced);
    }
    let format = match forced {
        Some(f) => f,
        None => sniff(data)?,
    };
    inflate(data, format, MAX_PAYLOAD)
}

fn decompress_container(data: &[u8], forced: Option<Format>) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN {
        return Err(Error::InvalidInput(format!(
            "ENTZ container truncated: {} bytes, need at least {HEADER_LEN} for the header",
            data.len()
        )));
    }
    let version = data[4];
    if version != CONTAINER_VERSION {
        return Err(Error::InvalidInput(format!(
            "ENTZ container version {version} is not supported; this build understands version {CONTAINER_VERSION}"
        )));
    }
    let format = match forced {
        Some(f) => f,
        None => Format::from_tag(data[5])?,
    };
    // data[6] = level (informational), data[7] = flags (reserved, must be 0).
    if data[7] != 0 {
        return Err(Error::InvalidInput(format!(
            "ENTZ header sets reserved flag bits (0x{:02x}); produced by a newer version",
            data[7]
        )));
    }
    let declared_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let declared_crc = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    if declared_len > MAX_PAYLOAD {
        return Err(Error::ResourceExhausted(format!(
            "ENTZ header declares {declared_len} decompressed bytes, over the {MAX_PAYLOAD}-byte budget"
        )));
    }

    let out = inflate(&data[HEADER_LEN..], format, declared_len)?;

    if out.len() != declared_len {
        return Err(Error::InvalidInput(format!(
            "decompressed {} bytes but the ENTZ header declared {declared_len}",
            out.len()
        )));
    }
    let mut crc = Crc::new();
    crc.update(&out);
    if crc.sum() != declared_crc {
        return Err(Error::InvalidInput(format!(
            "CRC32 mismatch: computed 0x{:08x}, header declared 0x{declared_crc:08x}; the stream is corrupt",
            crc.sum()
        )));
    }
    Ok(out)
}

/// Inflate `body`, refusing to produce more than `limit` bytes.
fn inflate(body: &[u8], format: Format, limit: usize) -> Result<Vec<u8>> {
    if body.is_empty() {
        return Err(Error::InvalidInput(
            "compressed body is empty; nothing to decompress".into(),
        ));
    }
    // Read one byte past the limit so an over-long stream is detectable rather
    // than silently truncated.
    let cap = limit.saturating_add(1);
    let mut out = Vec::new();
    let res = match format {
        Format::Gzip => GzDecoder::new(body).take(cap as u64).read_to_end(&mut out),
        Format::Zlib => ZlibDecoder::new(body).take(cap as u64).read_to_end(&mut out),
        Format::Deflate => DeflateDecoder::new(body).take(cap as u64).read_to_end(&mut out),
    };
    res.map_err(|e| {
        Error::InvalidInput(format!(
            "payload is not a valid {} stream: {e}",
            format.name()
        ))
    })?;
    if out.len() > limit {
        return Err(Error::ResourceExhausted(format!(
            "decompressed output exceeds the {limit}-byte budget (possible compression bomb)"
        )));
    }
    if out.is_empty() {
        // `compress` never emits an empty original, and raw DEFLATE happily
        // "decodes" some junk byte runs to nothing. Treat it as malformed.
        return Err(Error::InvalidInput(format!(
            "payload decompressed to zero bytes; it is not a valid {} stream",
            format.name()
        )));
    }
    Ok(out)
}

/// Guess the wrapper from leading bytes. Raw DEFLATE has no magic, so it is the
/// fallback rather than a positive match.
fn sniff(data: &[u8]) -> Result<Format> {
    if data.len() < 2 {
        return Err(Error::InvalidInput(format!(
            "cannot detect a compressed stream in {} byte(s); pass an explicit \
             `decompress:<format>` directive",
            data.len()
        )));
    }
    if data[0] == 0x1f && data[1] == 0x8b {
        return Ok(Format::Gzip);
    }
    // RFC 1950: CMF low nibble is 8 (deflate) and (CMF<<8 | FLG) % 31 == 0.
    if data[0] & 0x0f == 0x08 && (u16::from(data[0]) << 8 | u16::from(data[1])) % 31 == 0 {
        return Ok(Format::Zlib);
    }
    Ok(Format::Deflate)
}

fn io_internal(e: std::io::Error) -> Error {
    Error::Internal(format!("DEFLATE encoder failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Vec<u8> {
        // Compressible but not trivially so.
        let mut v = Vec::new();
        for i in 0..4096u32 {
            v.extend_from_slice(format!("line {i}: the quick brown fox\n").as_bytes());
        }
        v
    }

    #[test]
    fn round_trip_all_formats_and_levels() {
        let data = corpus();
        for format in [Format::Gzip, Format::Zlib, Format::Deflate] {
            for level in [0u32, 1, 6, 9] {
                let packed = compress(&data, format, level).expect("compress");
                assert_eq!(&packed[..4], MAGIC, "{format:?}/{level} missing magic");
                assert_eq!(packed[5], format.tag());
                assert_eq!(packed[6], level as u8);
                let back = decompress(&packed, None).expect("decompress");
                assert_eq!(back, data, "round trip failed for {format:?} level {level}");
            }
        }
    }

    #[test]
    fn compression_actually_shrinks_repetitive_input() {
        let data = vec![b'a'; 100_000];
        let packed = compress(&data, Format::Gzip, 6).unwrap();
        assert!(
            packed.len() < data.len() / 10,
            "expected >10x shrink, got {} from {}",
            packed.len(),
            data.len()
        );
        assert_eq!(decompress(&packed, None).unwrap(), data);
    }

    #[test]
    fn process_defaults_to_compress_then_detects_container() {
        let data = b"round trip me".to_vec();
        let packed = process(&data).expect("implicit compress");
        assert_eq!(&packed[..4], MAGIC);
        let back = process(&packed).expect("implicit decompress via ENTZ magic");
        assert_eq!(back, data);
    }

    #[test]
    fn header_records_length_and_crc() {
        let data = b"exactly twenty chars".to_vec();
        assert_eq!(data.len(), 20);
        let packed = compress(&data, Format::Zlib, 9).unwrap();
        assert_eq!(u32::from_le_bytes(packed[8..12].try_into().unwrap()), 20);
        let mut crc = Crc::new();
        crc.update(&data);
        assert_eq!(
            u32::from_le_bytes(packed[12..16].try_into().unwrap()),
            crc.sum()
        );
    }

    #[test]
    fn directive_line_selects_format_and_level() {
        let payload = corpus();
        let mut input = b"compress:zlib:9\n".to_vec();
        input.extend_from_slice(&payload);
        let packed = process(&input).unwrap();
        assert_eq!(packed[5], Format::Zlib.tag());
        assert_eq!(packed[6], 9);
        assert_eq!(process(&packed).unwrap(), payload);
    }

    #[test]
    fn directive_order_of_fields_is_free() {
        for line in ["compress:9:deflate\n", "compress:deflate:9\n"] {
            let mut input = line.as_bytes().to_vec();
            input.extend_from_slice(b"payload");
            let packed = process(&input).unwrap();
            assert_eq!(packed[5], Format::Deflate.tag());
            assert_eq!(packed[6], 9);
        }
    }

    #[test]
    fn explicit_decompress_directive_on_bare_gzip() {
        let data = b"bare gzip stream, no ENTZ wrapper".to_vec();
        let full = compress(&data, Format::Gzip, 6).unwrap();
        let bare = &full[HEADER_LEN..];

        let mut input = b"decompress:gzip\n".to_vec();
        input.extend_from_slice(bare);
        assert_eq!(process(&input).unwrap(), data);

        // ...and sniffing gets there on its own.
        assert_eq!(decompress(bare, None).unwrap(), data);
    }

    #[test]
    fn sniff_recognises_wrappers() {
        for format in [Format::Gzip, Format::Zlib] {
            let full = compress(b"sniff me please", format, 6).unwrap();
            assert_eq!(sniff(&full[HEADER_LEN..]).unwrap(), format);
        }
    }

    // ---- error paths: nothing below may panic ----

    #[test]
    fn empty_input_is_invalid_input() {
        let err = process(b"").unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "got {err:?}");
        assert!(err.to_string().contains("empty input"), "{err}");
    }

    #[test]
    fn directive_with_no_payload_is_rejected() {
        let err = process(b"compress\n").unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
        assert!(err.to_string().contains("payload after it is empty"), "{err}");
    }

    #[test]
    fn decompressing_garbage_errors_not_panics() {
        for junk in [
            &b"decompress:gzip\nnot even close to a gzip stream"[..],
            &b"decompress:zlib\n\xff\xff\xff\xff\xff\xff\xff\xff"[..],
            &b"decompress:deflate\n\x00\x01\x02\x03"[..],
        ] {
            let err = process(junk).unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)), "{junk:?} -> {err:?}");
        }
    }

    #[test]
    fn truncated_container_is_rejected() {
        let full = compress(b"some data to truncate later on", Format::Gzip, 6).unwrap();
        for cut in [4usize, 8, 12, 15] {
            let err = decompress(&full[..cut], None).unwrap_err();
            assert!(err.to_string().contains("truncated"), "cut {cut}: {err}");
        }
    }

    #[test]
    fn corrupt_body_trips_crc_or_codec() {
        let data = corpus();
        let mut packed = compress(&data, Format::Gzip, 6).unwrap();
        let mid = HEADER_LEN + (packed.len() - HEADER_LEN) / 2;
        packed[mid] ^= 0xff;
        let err = decompress(&packed, None).unwrap_err();
        // Either the gzip CRC/codec or our own CRC32 catches it; both are InvalidInput.
        assert!(matches!(err, Error::InvalidInput(_)), "got {err:?}");
    }

    #[test]
    fn tampered_length_field_is_caught() {
        let data = b"length field will be lied about".to_vec();
        let mut packed = compress(&data, Format::Gzip, 6).unwrap();
        packed[8] = packed[8].wrapping_add(1);
        let err = decompress(&packed, None).unwrap_err();
        assert!(err.to_string().contains("declared"), "{err}");
    }

    #[test]
    fn tampered_crc_field_is_caught() {
        let data = b"crc field will be lied about".to_vec();
        let mut packed = compress(&data, Format::Gzip, 6).unwrap();
        packed[12] ^= 0x01;
        let err = decompress(&packed, None).unwrap_err();
        assert!(err.to_string().contains("CRC32 mismatch"), "{err}");
    }

    #[test]
    fn unknown_container_version_is_rejected() {
        let mut packed = compress(b"version bump", Format::Gzip, 6).unwrap();
        packed[4] = 99;
        let err = decompress(&packed, None).unwrap_err();
        assert!(err.to_string().contains("version 99"), "{err}");
    }

    #[test]
    fn unknown_format_tag_is_rejected() {
        let mut packed = compress(b"tag bump", Format::Gzip, 6).unwrap();
        packed[5] = 42;
        let err = decompress(&packed, None).unwrap_err();
        assert!(err.to_string().contains("format tag 42"), "{err}");
    }

    #[test]
    fn reserved_flags_must_be_zero() {
        let mut packed = compress(b"flag bump", Format::Gzip, 6).unwrap();
        packed[7] = 0x80;
        let err = decompress(&packed, None).unwrap_err();
        assert!(err.to_string().contains("reserved flag"), "{err}");
    }

    #[test]
    fn bad_directives_are_rejected() {
        let cases: &[(&[u8], &str)] = &[
            (b"compress:brotli\npayload", "unknown compression format"),
            (b"compress:12\npayload", "out of range"),
            (b"compress:gzip:zlib\npayload", "more than one format"),
            (b"compress:1:2\npayload", "more than one compression level"),
            (b"compress::\npayload", "empty `:`-separated field"),
            (b"decompress:6\npayload", "meaningless for `decompress`"),
        ];
        for (input, needle) in cases {
            let err = process(input).unwrap_err();
            assert!(
                err.to_string().contains(needle),
                "{:?}: expected {needle:?}, got {err}",
                core::str::from_utf8(input)
            );
        }
    }

    #[test]
    fn binary_payload_is_not_mistaken_for_a_directive() {
        // Starts with a newline-containing byte run that is NOT a directive.
        let mut data = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        data.extend_from_slice(&[0u8; 512]);
        let packed = process(&data).unwrap();
        assert_eq!(&packed[..4], MAGIC);
        assert_eq!(process(&packed).unwrap(), data);
    }

    #[test]
    fn text_that_merely_starts_with_compress_word_is_treated_as_directive_only_when_well_formed() {
        // "compressing" is not a valid verb -> InvalidInput, never a silent misread.
        let err = process(b"compressing\nstuff").unwrap_err();
        assert!(err.to_string().contains("unknown directive verb"), "{err}");
        // A word without a trailing newline in range is just data.
        let packed = process(b"compress but no newline anywhere in this payload").unwrap();
        assert_eq!(&packed[..4], MAGIC);
    }

    #[test]
    fn single_byte_and_incompressible_input_round_trip() {
        for data in [vec![0u8], vec![0xff; 3], (0u8..=255).collect::<Vec<u8>>()] {
            let packed = compress(&data, Format::Deflate, 9).unwrap();
            assert_eq!(decompress(&packed, None).unwrap(), data);
        }
    }

    #[test]
    fn empty_compressed_body_is_rejected() {
        let mut packed = compress(b"x", Format::Gzip, 6).unwrap();
        packed.truncate(HEADER_LEN);
        let err = decompress(&packed, None).unwrap_err();
        assert!(err.to_string().contains("body is empty"), "{err}");
    }

    #[test]
    fn oversized_input_is_resource_exhausted() {
        // Cheap check on the parse path without allocating 64 MiB of real data:
        // a container whose header lies about a huge decompressed size.
        let mut packed = compress(b"small", Format::Gzip, 6).unwrap();
        packed[8..12].copy_from_slice(&(MAX_PAYLOAD as u32 + 1).to_le_bytes());
        let err = decompress(&packed, None).unwrap_err();
        assert!(matches!(err, Error::ResourceExhausted(_)), "got {err:?}");
    }

    #[test]
    fn decompression_bomb_is_capped() {
        // 8 MiB of zeros gzips to a few KiB; ask inflate for a 1 KiB ceiling.
        let data = vec![0u8; 8 * 1024 * 1024];
        let full = compress(&data, Format::Gzip, 9).unwrap();
        let err = inflate(&full[HEADER_LEN..], Format::Gzip, 1024).unwrap_err();
        assert!(matches!(err, Error::ResourceExhausted(_)), "got {err:?}");
    }
}
