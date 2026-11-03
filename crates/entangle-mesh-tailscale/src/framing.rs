//! Length-prefixed frames (`u32` big-endian length, then the payload) and the
//! sealed records built on them.
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
#[cfg(test)]
pub(crate) async fn read_frame<R>(r: &mut R, max: usize) -> Result<Vec<u8>, MeshTailscaleError>
where
    R: AsyncRead + Unpin,
{
    read_frame_opt(r, max).await?.ok_or_else(|| {
        MeshTailscaleError::Protocol("stream ended before a complete frame header".into())
    })
}

// ------------------------------------------------------------ sealed records --
//
// After the handshake every frame is a record: the same `u32` length prefix,
// then `ChaCha20-Poly1305(payload)` (ciphertext followed by a 16-byte tag)
// under a per-direction key derived from the handshake. Nonces are a
// per-direction counter, so a record cannot be replayed, reordered, dropped
// silently (the next one fails), or forged by anybody without the session
// key — including a tailnet node that relayed the handshake.

/// Poly1305 tag length.
pub(crate) const TAG_LEN: usize = 16;

fn next_nonce(counter: &mut u64) -> Result<ring::aead::Nonce, MeshTailscaleError> {
    let n = *counter;
    *counter = n
        .checked_add(1)
        .ok_or_else(|| MeshTailscaleError::Protocol("record counter exhausted".into()))?;
    let mut bytes = [0u8; ring::aead::NONCE_LEN];
    bytes[4..].copy_from_slice(&n.to_be_bytes());
    Ok(ring::aead::Nonce::assume_unique_for_key(bytes))
}

/// Sending half of a session: seals records under one direction's key.
pub(crate) struct Sealer {
    key: ring::aead::LessSafeKey,
    counter: u64,
}

/// Receiving half of a session: opens records under the other direction's key.
pub(crate) struct Opener {
    key: ring::aead::LessSafeKey,
    counter: u64,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealer")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opener")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl Sealer {
    pub(crate) fn new(key: ring::aead::UnboundKey) -> Self {
        Self {
            key: ring::aead::LessSafeKey::new(key),
            counter: 0,
        }
    }

    pub(crate) fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>, MeshTailscaleError> {
        let nonce = next_nonce(&mut self.counter)?;
        let mut buf = Vec::with_capacity(payload.len() + TAG_LEN);
        buf.extend_from_slice(payload);
        self.key
            .seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut buf)
            .map_err(|_| MeshTailscaleError::Protocol("sealing a record failed".into()))?;
        Ok(buf)
    }
}

impl Opener {
    pub(crate) fn new(key: ring::aead::UnboundKey) -> Self {
        Self {
            key: ring::aead::LessSafeKey::new(key),
            counter: 0,
        }
    }

    pub(crate) fn open(&mut self, mut record: Vec<u8>) -> Result<Vec<u8>, MeshTailscaleError> {
        let nonce = next_nonce(&mut self.counter)?;
        let len = self
            .key
            .open_in_place(nonce, ring::aead::Aad::empty(), &mut record)
            .map_err(|_| {
                MeshTailscaleError::Protocol(
                    "record failed authentication (tampered, replayed or forged)".into(),
                )
            })?
            .len();
        record.truncate(len);
        Ok(record)
    }
}

/// Seal `payload` and write it as one record. `max` caps the *plaintext*.
pub(crate) async fn write_sealed<W>(
    w: &mut W,
    sealer: &mut Sealer,
    payload: &[u8],
    max: usize,
) -> Result<(), MeshTailscaleError>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > max {
        return Err(MeshTailscaleError::FrameTooLarge {
            declared: payload.len() as u64,
            max,
        });
    }
    let record = sealer.seal(payload)?;
    write_frame(w, &record, max.saturating_add(TAG_LEN)).await
}

/// Read and open one record; `Ok(None)` on a clean end of stream before a
/// header. `max` caps the *plaintext*; the cap is still checked against the
/// declared length before anything is allocated.
pub(crate) async fn read_sealed_opt<R>(
    r: &mut R,
    opener: &mut Opener,
    max: usize,
) -> Result<Option<Vec<u8>>, MeshTailscaleError>
where
    R: AsyncRead + Unpin,
{
    let record = match read_frame_opt(r, max.saturating_add(TAG_LEN)).await {
        Ok(Some(rec)) => rec,
        Ok(None) => return Ok(None),
        Err(MeshTailscaleError::FrameTooLarge { declared, .. }) => {
            return Err(MeshTailscaleError::FrameTooLarge {
                declared: declared.saturating_sub(TAG_LEN as u64),
                max,
            })
        }
        Err(e) => return Err(e),
    };
    if record.len() < TAG_LEN {
        return Err(MeshTailscaleError::Protocol(format!(
            "record of {} bytes is shorter than its tag",
            record.len()
        )));
    }
    opener.open(record).map(Some)
}

/// [`read_sealed_opt`] where end of stream is a protocol error.
pub(crate) async fn read_sealed<R>(
    r: &mut R,
    opener: &mut Opener,
    max: usize,
) -> Result<Vec<u8>, MeshTailscaleError>
where
    R: AsyncRead + Unpin,
{
    read_sealed_opt(r, opener, max).await?.ok_or_else(|| {
        MeshTailscaleError::Protocol("stream ended before a complete record header".into())
    })
}
