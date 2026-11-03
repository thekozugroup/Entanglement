//! Length-prefixed frames: `u32` big-endian length, then the payload.
//!
//! The declared length is untrusted. It is compared with the cap *before* any
//! allocation, and even an in-cap length is not used as an allocation hint:
//! the body is read in [`READ_CHUNK_BYTES`] steps, so a peer that declares the
//! maximum and then stalls costs one 64 KiB buffer, not a maximum-size `Vec`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::MeshTailscaleError;

/// Granularity of body reads.
pub(crate) const READ_CHUNK_BYTES: usize = 64 * 1024;

pub(crate) async fn write_frame<W>(
    w: &mut W,
    payload: &[u8],
    max: usize,
) -> Result<(), MeshTailscaleError>
where
    W: AsyncWrite + Unpin,
{
    let too_large = || MeshTailscaleError::FrameTooLarge {
        declared: payload.len() as u64,
        max,
    };
    if payload.len() > max {
        return Err(too_large());
    }
    let len = u32::try_from(payload.len()).map_err(|_| too_large())?;
    let io = |e: std::io::Error| MeshTailscaleError::Stream(format!("writing frame: {e}"));
    w.write_all(&len.to_be_bytes()).await.map_err(io)?;
    w.write_all(payload).await.map_err(io)?;
    w.flush().await.map_err(io)
}

/// Read one frame; `Ok(None)` if the stream ended cleanly before the header.
pub(crate) async fn read_frame_opt<R>(
    r: &mut R,
    max: usize,
) -> Result<Option<Vec<u8>>, MeshTailscaleError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    let first = r
        .read(&mut header[..1])
        .await
        .map_err(|e| MeshTailscaleError::Stream(format!("reading frame header: {e}")))?;
    if first == 0 {
        return Ok(None);
    }
    r.read_exact(&mut header[1..]).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            MeshTailscaleError::Protocol("stream ended inside a frame header".into())
        } else {
            MeshTailscaleError::Stream(format!("reading frame header: {e}"))
        }
    })?;

    let declared = u64::from(u32::from_be_bytes(header));
    if declared > max as u64 {
        return Err(MeshTailscaleError::FrameTooLarge { declared, max });
    }
    let declared = declared as usize;

    let mut out = Vec::with_capacity(declared.min(READ_CHUNK_BYTES));
    let mut scratch = vec![0u8; declared.min(READ_CHUNK_BYTES)];
    let mut remaining = declared;
    while remaining > 0 {
        let want = remaining.min(READ_CHUNK_BYTES);
        r.read_exact(&mut scratch[..want]).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                MeshTailscaleError::Protocol(format!(
                    "frame truncated: declared {declared} bytes, got {}",
                    declared - remaining
                ))
            } else {
                MeshTailscaleError::Stream(format!("reading frame body: {e}"))
            }
        })?;
        out.extend_from_slice(&scratch[..want]);
        remaining -= want;
    }
    Ok(Some(out))
}

/// Read one frame; end-of-stream is a protocol error.
pub(crate) async fn read_frame<R>(r: &mut R, max: usize) -> Result<Vec<u8>, MeshTailscaleError>
where
    R: AsyncRead + Unpin,
{
    read_frame_opt(r, max).await?.ok_or_else(|| {
        MeshTailscaleError::Protocol("stream ended before a complete frame header".into())
    })
}
