//! The native-plugin wire protocol: length-prefixed frames on stdin/stdout.
//!
//! ```text
//! request  (host → plugin, stdin):   u32 BE length | input bytes
//! response (plugin → host, stdout):  u32 BE length | tag | body
//!                                    tag 0x00 = ok,  body = output bytes
//!                                    tag 0x01 = err, body = UTF-8 message
//! ```
//! The response length counts the tag byte. The host writes one request and
//! closes stdin; a plugin may loop "read request → write response" until
//! EOF, which keeps the protocol usable for a future long-lived mode.
//! stderr is free-form diagnostics; the host logs it.
//!
//! This is a deliberate simplification of the Cap'n Proto-over-UDS IPC in
//! spec §3.4 (recorded there as a deviation): one request/response shape
//! needs no schema compiler, and the framing is ~30 lines on either side.

use std::io::{self, Read, Write};

/// Size of the length prefix.
pub const HEADER_LEN: usize = 4;
/// Response tag: success, body is the output.
pub const TAG_OK: u8 = 0;
/// Response tag: failure, body is a UTF-8 error message.
pub const TAG_ERR: u8 = 1;

/// The 4-byte big-endian header for a frame of `len` bytes.
///
/// Errors when `len` does not fit the 32-bit prefix.
pub fn header(len: usize) -> io::Result<[u8; HEADER_LEN]> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds 4 GiB"))
}

/// Read one frame from `r`, refusing (before allocating) any frame larger
/// than `max`. Returns `Ok(None)` on a clean EOF before the header.
pub fn read_frame<R: Read>(r: &mut R, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; HEADER_LEN];
    let mut got = 0;
    while got < HEADER_LEN {
        match r.read(&mut hdr[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame header",
                ))
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {max}-byte limit"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write one frame (header + payload) to `w` and flush.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    w.write_all(&header(payload.len())?)?;
    w.write_all(payload)?;
    w.flush()
}

/// Write a response frame for `result` to `w` and flush.
pub fn write_response<W: Write>(w: &mut W, result: Result<&[u8], &str>) -> io::Result<()> {
    let (tag, body) = match result {
        Ok(b) => (TAG_OK, b),
        Err(m) => (TAG_ERR, m.as_bytes()),
    };
    w.write_all(&header(body.len() + 1)?)?;
    w.write_all(&[tag])?;
    w.write_all(body)?;
    w.flush()
}

/// Decode a response payload (tag + body).
pub fn decode_response(mut payload: Vec<u8>) -> Result<Result<Vec<u8>, String>, String> {
    if payload.is_empty() {
        return Err("empty response frame (missing tag byte)".into());
    }
    match payload[0] {
        TAG_OK => {
            payload.remove(0);
            Ok(Ok(payload))
        }
        TAG_ERR => Ok(Err(String::from_utf8_lossy(&payload[1..]).into_owned())),
        t => Err(format!("unknown response tag {t:#04x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        assert_eq!(&buf[..4], &5u32.to_be_bytes());
        let got = read_frame(&mut &buf[..], 1024).unwrap().unwrap();
        assert_eq!(got, b"hello");
        // EOF right after: clean end of stream.
        assert!(read_frame(&mut &buf[buf.len()..], 1024).unwrap().is_none());
    }

    #[test]
    fn response_round_trip_ok_and_err() {
        let mut buf = Vec::new();
        write_response(&mut buf, Ok(b"out")).unwrap();
        let payload = read_frame(&mut &buf[..], 1024).unwrap().unwrap();
        assert_eq!(decode_response(payload).unwrap(), Ok(b"out".to_vec()));

        let mut buf = Vec::new();
        write_response(&mut buf, Err("boom")).unwrap();
        let payload = read_frame(&mut &buf[..], 1024).unwrap().unwrap();
        assert_eq!(decode_response(payload).unwrap(), Err("boom".to_owned()));
    }

    #[test]
    fn oversized_and_malformed_frames_are_rejected() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &[0u8; 64]).unwrap();
        let err = read_frame(&mut &buf[..], 63).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let err = read_frame(&mut &[0u8, 0][..], 63).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        assert!(decode_response(vec![]).is_err());
        assert!(decode_response(vec![7, 1, 2]).is_err());
    }
}
