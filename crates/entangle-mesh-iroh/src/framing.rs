//! Length-prefixed framing for `mesh.iroh` streams.
//!
//! Wire format, on a QUIC bidirectional stream:
//!
//! ```text
//! +--------+--------+--------+--------+============ ... ============+
//! |            u32 length (big endian)  |        payload bytes       |
//! +--------+--------+--------+--------+============ ... ============+
//! ```
//!
//! One frame per direction per stream: the requester writes a frame and
//! finishes its send side, the responder writes a frame and finishes its send
//! side. Multiple concurrent requests use multiple streams, which QUIC gives
//! us for free without head-of-line blocking.
//!
//! # Threat model
//!
//! The length prefix arrives from a remote peer that has completed a QUIC
//! handshake but is otherwise untrusted (it may be paired-but-hostile, or a
//! peer we are still deciding whether to trust). It is therefore validated
//! *before* any allocation:
//!
//! * a declared length above the cap is rejected outright — no allocation, no
//!   body read;
//! * an in-cap length is still not trusted as an allocation hint: the body is
//!   read in [`READ_CHUNK_BYTES`] steps, so a peer that declares the maximum
//!   and then sends nothing costs one 64 KiB buffer and an error, not a
//!   maximum-sized `Vec`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::MeshIrohError;

/// Number of bytes in a frame header.
pub(crate) const HEADER_BYTES: usize = 4;

/// Granularity of body reads.
///
/// Bounds the memory a peer can make us commit before it has actually
/// delivered the bytes it promised.
pub(crate) const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Write one length-prefixed frame.
///
/// Returns [`MeshIrohError::FrameTooLarge`] without touching the stream if the
/// payload is over `max`, so an oversize *local* payload is a clean local
/// error rather than a half-written frame the peer has to recover from.
pub(crate) async fn write_frame<W>(
    writer: &mut W,
    payload: &[u8],
    max: usize,
) -> Result<(), MeshIrohError>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > max {
        return Err(MeshIrohError::FrameTooLarge {
            declared: payload.len() as u64,
            max,
        });
    }
    // Cast is safe: `max` is clamped to `MAX_FRAME_BYTES` (well under u32::MAX)
    // by `MeshIrohConfig::normalized`, and the check above bounds `payload`.
    let len = u32::try_from(payload.len()).map_err(|_| MeshIrohError::FrameTooLarge {
        declared: payload.len() as u64,
        max,
    })?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| MeshIrohError::Stream(format!("writing frame header: {e}")))?;
    writer
        .write_all(payload)
        .await
        .map_err(|e| MeshIrohError::Stream(format!("writing frame body: {e}")))?;
    Ok(())
}

/// Read one length-prefixed frame, rejecting anything over `max`.
pub(crate) async fn read_frame<R>(reader: &mut R, max: usize) -> Result<Vec<u8>, MeshIrohError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_BYTES];
    reader.read_exact(&mut header).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            MeshIrohError::Protocol("stream ended before a complete frame header".into())
        } else {
            MeshIrohError::Stream(format!("reading frame header: {e}"))
        }
    })?;

    // Untrusted. Compare in u64 so the check is identical on 32- and 64-bit
    // targets, and reject *before* allocating anything.
    let declared = u64::from(u32::from_be_bytes(header));
    if declared > max as u64 {
        return Err(MeshIrohError::FrameTooLarge { declared, max });
    }
    let declared = declared as usize;

    let mut out = Vec::with_capacity(declared.min(READ_CHUNK_BYTES));
    let mut scratch = vec![0u8; READ_CHUNK_BYTES];
    let mut remaining = declared;
    while remaining > 0 {
        let want = remaining.min(READ_CHUNK_BYTES);
        reader.read_exact(&mut scratch[..want]).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                MeshIrohError::Protocol(format!(
                    "frame truncated: declared {declared} bytes, got {}",
                    declared - remaining
                ))
            } else {
                MeshIrohError::Stream(format!("reading frame body: {e}"))
            }
        })?;
        out.extend_from_slice(&scratch[..want]);
        remaining -= want;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;

    use super::*;

    /// A reader that yields `header` and then panics if the body is read.
    ///
    /// This is how the "no huge allocation" property is proved mechanically:
    /// if `read_frame` ever got as far as reading (and therefore sizing) the
    /// body of an oversize frame, this reader would blow up.
    struct HeaderOnlyReader {
        header: [u8; HEADER_BYTES],
        pos: usize,
    }

    impl AsyncRead for HeaderOnlyReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            assert!(
                self.pos < HEADER_BYTES,
                "read_frame must not read past the header of an oversize frame"
            );
            let n = buf.remaining().min(HEADER_BYTES - self.pos);
            let start = self.pos;
            buf.put_slice(&self.header[start..start + n]);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn round_trips_payload() {
        let payload = b"entangle round trip".to_vec();
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload, 1024).await.unwrap();
        assert_eq!(buf.len(), HEADER_BYTES + payload.len());
        let mut cursor = std::io::Cursor::new(buf);
        let got = read_frame(&mut cursor, 1024).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn round_trips_empty_payload() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &[], 1024).await.unwrap();
        assert_eq!(buf, vec![0, 0, 0, 0]);
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_frame(&mut cursor, 1024).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn round_trips_payload_larger_than_one_read_chunk() {
        let payload = vec![0xa5u8; READ_CHUNK_BYTES * 2 + 7];
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload, payload.len())
            .await
            .unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let got = read_frame(&mut cursor, payload.len()).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn rejects_oversize_header_without_reading_the_body() {
        // Claim 4 GiB - 1 against a 1 KiB cap.
        let mut reader = HeaderOnlyReader {
            header: u32::MAX.to_be_bytes(),
            pos: 0,
        };
        let err = read_frame(&mut reader, 1024)
            .await
            .expect_err("must reject");
        match err {
            MeshIrohError::FrameTooLarge { declared, max } => {
                assert_eq!(declared, u64::from(u32::MAX));
                assert_eq!(max, 1024);
            }
            other => panic!("expected FrameTooLarge, got {other}"),
        }
    }

    #[tokio::test]
    async fn rejects_oversize_payload_on_write_without_emitting_bytes() {
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, &[0u8; 64], 16)
            .await
            .expect_err("must reject");
        assert!(matches!(err, MeshIrohError::FrameTooLarge { .. }));
        assert!(buf.is_empty(), "no bytes may reach the wire");
    }

    #[tokio::test]
    async fn truncated_body_is_a_protocol_error_not_a_hang() {
        // Header says 32 bytes, body has 4.
        let mut wire = 32u32.to_be_bytes().to_vec();
        wire.extend_from_slice(&[1, 2, 3, 4]);
        let mut cursor = std::io::Cursor::new(wire);
        let err = read_frame(&mut cursor, 1024).await.expect_err("must error");
        assert!(matches!(err, MeshIrohError::Protocol(_)), "got {err}");
        assert!(err.to_string().contains("ENTANGLE-E0637"));
    }

    #[tokio::test]
    async fn empty_stream_is_a_protocol_error() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let err = read_frame(&mut cursor, 1024).await.expect_err("must error");
        assert!(matches!(err, MeshIrohError::Protocol(_)), "got {err}");
    }

    /// An in-cap but undelivered length must fail, not hang or succeed. The
    /// buffer growth here is bounded by `READ_CHUNK_BYTES` regardless of the
    /// 8 MiB the peer claimed, which is the point of the chunked read loop.
    #[tokio::test]
    async fn in_cap_declaration_with_truncated_body_errors() {
        let big = 8 * 1024 * 1024usize;
        let mut wire = (big as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&[7u8; 16]);
        let mut cursor = std::io::Cursor::new(wire);
        let err = read_frame(&mut cursor, big).await.expect_err("must error");
        assert!(matches!(err, MeshIrohError::Protocol(_)), "got {err}");
    }
}
