//! Chunk signing and the stream transcript (spec §7.1, ATC-STR-3).
//!
//! Every output chunk is signed by the executor with its node Ed25519 key —
//! the same key its transport identity (`PeerId`) is derived from — over a
//! domain-separated message:
//!
//! ```text
//! "entangle/stream/chunk/v1" || 0x00 || task_id (16) || policy_hash (32)
//!     || request (32) || seq (u64 BE) || BLAKE3(chunk) (32)
//! ```
//!
//! `request` is [`request_digest`] of the task's `Open` frame: the plugin,
//! a hash of its input and every requested limit. The task id is the
//! submitter's choice and nothing stops it reusing one, so without
//! `request` a transcript would say *that* the executor produced some bytes
//! for task T, not *in answer to what*.
//!
//! The submitter verifies each chunk against the executor's
//! **transport-authenticated** public key (never a key named in the stream),
//! and requires `seq` to be exactly the next expected number, so a chunk
//! signed by any other key, a chunk from another task, policy or request,
//! and a replayed or reordered chunk are all refused with
//! [`StreamError::BadChunkSignature`].
//!
//! Chunks also chain into a running transcript hash,
//! `T(n+1) = BLAKE3("entangle/stream/transcript/v1" || T(n) || seq || BLAKE3(chunk))`,
//! starting from
//! `T(0) = BLAKE3("entangle/stream/transcript/v1" || task_id || policy_hash || request)`.
//! The executor's signed `End` frame commits to the chunk count, byte count
//! and final transcript, so a complete stream is attributable as a whole and
//! a partial one chunk by chunk (§7.1 billing / audit / blame, §11 #19).

use entangle_signing::{IdentityKeyPair, IdentityPublicKey, Signature};
use entangle_types::peer_id::PeerId;

use super::error::StreamError;
use super::frame::{OpenFrame, Signature64, WirePartial};
use crate::work_unit::PolicyHash;

/// Domain separator of a chunk signing message.
pub const CHUNK_DOMAIN: &[u8] = b"entangle/stream/chunk/v1";
/// Domain separator of an end-of-stream signing message.
pub const END_DOMAIN: &[u8] = b"entangle/stream/end/v1";
/// Domain separator of the transcript hash chain.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"entangle/stream/transcript/v1";
/// Domain separator of [`request_digest`].
pub const REQUEST_DOMAIN: &[u8] = b"entangle/stream/request/v1";

/// Length of a chunk signing message.
pub const CHUNK_MESSAGE_LEN: usize = CHUNK_DOMAIN.len() + 1 + 16 + 32 + 32 + 8 + 32;
/// Length of an end-of-stream signing message.
pub const END_MESSAGE_LEN: usize = END_DOMAIN.len() + 1 + 16 + 32 + 32 + 8 + 8 + 32;

/// The digest of what a stream's `Open` frame asks for, which every chunk
/// and `End` signature commits to: the plugin, `BLAKE3(input)`, the input
/// ceiling, the timeout, every requested channel limit and the
/// partial-result policy. (The task id and the policy are signed
/// separately, as `task_id` and `policy_hash`.)
///
/// ```text
/// BLAKE3("entangle/stream/request/v1" || 0x00
///     || u32 BE len(plugin) || plugin || BLAKE3(input)
///     || max_input_bytes || timeout_ms                      (u64 BE)
///     || max_chunk_bytes || max_total_bytes                 (u64 BE)
///     || credit_window || heartbeat_ms                      (u32 BE)
///     || credit_exhaustion_timeout_ms                       (u64 BE)
///     || partial_result                                     (u8: 0 discard, 1 keep, 2 keep-signed))
/// ```
///
/// Both ends compute it from the `Open` frame itself: the submitter from
/// the one it sends, the executor from the one it received.
pub fn request_digest(open: &OpenFrame) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(REQUEST_DOMAIN);
    h.update(&[0]);
    // A plugin id is far below 4 GiB; saturate rather than wrap regardless.
    let plugin_len = u32::try_from(open.plugin.len()).unwrap_or(u32::MAX);
    h.update(&plugin_len.to_be_bytes());
    h.update(open.plugin.as_bytes());
    h.update(blake3::hash(&open.input).as_bytes());
    h.update(&open.max_input_bytes.to_be_bytes());
    h.update(&open.timeout_ms.to_be_bytes());
    h.update(&open.channel.max_chunk_bytes.to_be_bytes());
    h.update(&open.channel.max_total_bytes.to_be_bytes());
    h.update(&open.channel.credit_window.to_be_bytes());
    h.update(&open.channel.heartbeat_ms.to_be_bytes());
    h.update(&open.channel.credit_exhaustion_timeout_ms.to_be_bytes());
    h.update(&[match open.partial_result {
        WirePartial::Discard => 0,
        WirePartial::Keep => 1,
        WirePartial::KeepSigned => 2,
    }]);
    *h.finalize().as_bytes()
}

/// The exact bytes the executor signs for chunk `seq`.
pub fn chunk_message(
    task_id: &[u8; 16],
    policy_hash: &PolicyHash,
    request: &[u8; 32],
    seq: u64,
    chunk_hash: &[u8; 32],
) -> [u8; CHUNK_MESSAGE_LEN] {
    let mut msg = [0u8; CHUNK_MESSAGE_LEN];
    let mut at = 0;
    for part in [
        CHUNK_DOMAIN,
        &[0u8][..],
        &task_id[..],
        &policy_hash.0[..],
        &request[..],
        &seq.to_be_bytes()[..],
        &chunk_hash[..],
    ] {
        msg[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    msg
}

/// The exact bytes the executor signs to end the stream.
pub fn end_message(
    task_id: &[u8; 16],
    policy_hash: &PolicyHash,
    request: &[u8; 32],
    chunks: u64,
    bytes: u64,
    transcript: &[u8; 32],
) -> [u8; END_MESSAGE_LEN] {
    let mut msg = [0u8; END_MESSAGE_LEN];
    let mut at = 0;
    for part in [
        END_DOMAIN,
        &[0u8][..],
        &task_id[..],
        &policy_hash.0[..],
        &request[..],
        &chunks.to_be_bytes()[..],
        &bytes.to_be_bytes()[..],
        &transcript[..],
    ] {
        msg[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    msg
}

/// `T(0)`: the transcript of a stream before its first chunk.
pub fn transcript_start(
    task_id: &[u8; 16],
    policy_hash: &PolicyHash,
    request: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TRANSCRIPT_DOMAIN);
    h.update(task_id);
    h.update(&policy_hash.0);
    h.update(request);
    *h.finalize().as_bytes()
}

/// `T(n+1)` from `T(n)` and chunk `seq`'s BLAKE3.
pub fn transcript_next(prev: &[u8; 32], seq: u64, chunk_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TRANSCRIPT_DOMAIN);
    h.update(prev);
    h.update(&seq.to_be_bytes());
    h.update(chunk_hash);
    *h.finalize().as_bytes()
}

/// Signs one stream's chunks with the executor's node key.
#[derive(Clone)]
pub struct ChunkSigner {
    key: IdentityKeyPair,
    task_id: [u8; 16],
    policy_hash: PolicyHash,
    request: [u8; 32],
}

impl std::fmt::Debug for ChunkSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkSigner")
            .field("key", &self.key)
            .field("policy_hash", &self.policy_hash)
            .finish_non_exhaustive()
    }
}

impl ChunkSigner {
    /// A signer for task `task_id` running under `policy_hash`, answering
    /// the request whose [`request_digest`] is `request`.
    pub fn new(
        key: IdentityKeyPair,
        task_id: [u8; 16],
        policy_hash: PolicyHash,
        request: [u8; 32],
    ) -> Self {
        Self {
            key,
            task_id,
            policy_hash,
            request,
        }
    }

    /// The executor's raw public key.
    pub fn public_key(&self) -> [u8; 32] {
        *self.key.public().as_bytes()
    }

    /// Sign chunk `seq` whose BLAKE3 is `chunk_hash`.
    pub fn sign_chunk(&self, seq: u64, chunk_hash: &[u8; 32]) -> Signature64 {
        let msg = chunk_message(
            &self.task_id,
            &self.policy_hash,
            &self.request,
            seq,
            chunk_hash,
        );
        Signature64::from_bytes(self.key.sign(&msg).0)
    }

    /// Sign the end of the stream.
    pub fn sign_end(&self, chunks: u64, bytes: u64, transcript: &[u8; 32]) -> Signature64 {
        let msg = end_message(
            &self.task_id,
            &self.policy_hash,
            &self.request,
            chunks,
            bytes,
            transcript,
        );
        Signature64::from_bytes(self.key.sign(&msg).0)
    }
}

/// Verifies one stream's chunks against the executor's key.
#[derive(Clone, Debug)]
pub struct ChunkVerifier {
    key: Option<IdentityPublicKey>,
    executor: PeerId,
    task_id: [u8; 16],
    policy_hash: PolicyHash,
    request: [u8; 32],
}

impl ChunkVerifier {
    /// A verifier for task `task_id` under `policy_hash` answering the
    /// request whose [`request_digest`] is `request`, executed by the holder
    /// of `executor_key` — which must be the key the transport
    /// authenticated, not one the stream named.
    ///
    /// A key that is not a valid Ed25519 point verifies nothing: every chunk
    /// is then refused.
    pub fn new(
        executor_key: [u8; 32],
        task_id: [u8; 16],
        policy_hash: PolicyHash,
        request: [u8; 32],
    ) -> Self {
        Self {
            key: IdentityPublicKey::from_bytes(&executor_key).ok(),
            executor: PeerId::from_public_key_bytes(&executor_key),
            task_id,
            policy_hash,
            request,
        }
    }

    /// The executor's peer id.
    pub const fn executor(&self) -> PeerId {
        self.executor
    }

    /// Check chunk `seq`'s signature.
    pub fn verify_chunk(
        &self,
        seq: u64,
        chunk_hash: &[u8; 32],
        signature: &Signature64,
    ) -> Result<(), StreamError> {
        let msg = chunk_message(
            &self.task_id,
            &self.policy_hash,
            &self.request,
            seq,
            chunk_hash,
        );
        self.verify(&msg, signature)
            .map_err(|detail| StreamError::BadChunkSignature {
                seq,
                executor: self.executor.to_hex(),
                detail,
            })
    }

    /// Check the end-of-stream signature.
    pub fn verify_end(
        &self,
        chunks: u64,
        bytes: u64,
        transcript: &[u8; 32],
        signature: &Signature64,
    ) -> Result<(), StreamError> {
        let msg = end_message(
            &self.task_id,
            &self.policy_hash,
            &self.request,
            chunks,
            bytes,
            transcript,
        );
        self.verify(&msg, signature)
            .map_err(|detail| StreamError::BadEnd(format!("end signature: {detail}")))
    }

    fn verify(&self, msg: &[u8], signature: &Signature64) -> Result<(), String> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| "the executor's key is not a valid Ed25519 public key".to_owned())?;
        key.verify(msg, &Signature(signature.to_bytes()))
            .map_err(|e| format!("signature does not verify against the executor's key: {e}"))
    }
}

/// One chunk of a recorded stream, as kept for audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedChunk {
    /// Sequence number.
    pub seq: u64,
    /// The chunk bytes.
    pub bytes: Vec<u8>,
    /// The executor's signature over it.
    pub signature: Signature64,
}

/// Re-verify a recorded stream: every chunk's signature and sequence, and
/// return the final transcript hash.
///
/// For a third party auditing a partial (or complete) result kept under
/// `PartialResultPolicy::KeepSigned`: given only the executor's public key,
/// the task id, the policy hash and the request digest (recomputed with
/// [`request_digest`] from the `Open` the auditor is shown), it proves
/// which executor produced which bytes, in which order, in answer to which
/// request.
pub fn verify_transcript(
    executor_key: [u8; 32],
    task_id: [u8; 16],
    policy_hash: PolicyHash,
    request: [u8; 32],
    chunks: &[SignedChunk],
) -> Result<[u8; 32], StreamError> {
    let verifier = ChunkVerifier::new(executor_key, task_id, policy_hash, request);
    let mut transcript = transcript_start(&task_id, &policy_hash, &request);
    for (expected, chunk) in (0u64..).zip(chunks) {
        if chunk.seq != expected {
            return Err(StreamError::BadChunkSignature {
                seq: chunk.seq,
                executor: verifier.executor().to_hex(),
                detail: format!("out of sequence: expected chunk {expected}"),
            });
        }
        let hash = *blake3::hash(&chunk.bytes).as_bytes();
        verifier.verify_chunk(chunk.seq, &hash, &chunk.signature)?;
        transcript = transcript_next(&transcript, chunk.seq, &hash);
    }
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: [u8; 32] = [5; 32];

    fn setup() -> (ChunkSigner, ChunkVerifier) {
        let key = IdentityKeyPair::from_seed(&[3; 32]);
        let signer = ChunkSigner::new(key, [1; 16], PolicyHash([2; 32]), REQ);
        let verifier = ChunkVerifier::new(signer.public_key(), [1; 16], PolicyHash([2; 32]), REQ);
        (signer, verifier)
    }

    #[test]
    fn a_signed_chunk_verifies_and_any_change_breaks_it() {
        let (signer, verifier) = setup();
        let h = *blake3::hash(b"tok").as_bytes();
        let sig = signer.sign_chunk(5, &h);
        verifier.verify_chunk(5, &h, &sig).unwrap();

        assert!(verifier.verify_chunk(6, &h, &sig).is_err(), "seq is signed");
        let other = *blake3::hash(b"tak").as_bytes();
        assert!(
            verifier.verify_chunk(5, &other, &sig).is_err(),
            "bytes are signed"
        );
        let other_task = ChunkVerifier::new(signer.public_key(), [9; 16], PolicyHash([2; 32]), REQ);
        assert!(
            other_task.verify_chunk(5, &h, &sig).is_err(),
            "task id is signed"
        );
        let other_policy =
            ChunkVerifier::new(signer.public_key(), [1; 16], PolicyHash([8; 32]), REQ);
        assert!(
            other_policy.verify_chunk(5, &h, &sig).is_err(),
            "policy hash is signed"
        );
        let other_request =
            ChunkVerifier::new(signer.public_key(), [1; 16], PolicyHash([2; 32]), [6; 32]);
        assert!(
            other_request.verify_chunk(5, &h, &sig).is_err(),
            "the request is signed"
        );
    }

    #[test]
    fn a_chunk_signature_is_not_an_end_signature() {
        let (signer, verifier) = setup();
        let t = [4u8; 32];
        let end = signer.sign_end(1, 3, &t);
        verifier.verify_end(1, 3, &t, &end).unwrap();
        // Domain separation: an end signature never verifies as a chunk.
        assert!(verifier.verify_chunk(1, &t, &end).is_err());
        assert!(verifier.verify_end(2, 3, &t, &end).is_err());
    }

    #[test]
    fn an_invalid_executor_key_refuses_everything() {
        let (signer, _) = setup();
        // Find 32 bytes that are not a valid compressed Edwards point.
        let bad = (0u8..=255)
            .map(|b| {
                let mut k = [b; 32];
                k[31] = 0xff;
                k
            })
            .find(|k| IdentityPublicKey::from_bytes(k).is_err())
            .expect("some byte pattern is not a curve point");
        let verifier = ChunkVerifier::new(bad, [1; 16], PolicyHash([2; 32]), REQ);
        let h = [0u8; 32];
        assert!(verifier
            .verify_chunk(0, &h, &signer.sign_chunk(0, &h))
            .is_err());
    }

    #[test]
    fn transcripts_verify_and_detect_reordering() {
        let (signer, _) = setup();
        let chunks: Vec<SignedChunk> = (0..3u64)
            .map(|seq| {
                let bytes = vec![seq as u8; 4];
                let sig = signer.sign_chunk(seq, blake3::hash(&bytes).as_bytes());
                SignedChunk {
                    seq,
                    bytes,
                    signature: sig,
                }
            })
            .collect();
        let t = verify_transcript(
            signer.public_key(),
            [1; 16],
            PolicyHash([2; 32]),
            REQ,
            &chunks,
        )
        .unwrap();
        assert_ne!(t, transcript_start(&[1; 16], &PolicyHash([2; 32]), &REQ));
        let mut swapped = chunks.clone();
        swapped.swap(0, 1);
        assert!(verify_transcript(
            signer.public_key(),
            [1; 16],
            PolicyHash([2; 32]),
            REQ,
            &swapped
        )
        .is_err());
        assert!(
            verify_transcript(
                signer.public_key(),
                [1; 16],
                PolicyHash([2; 32]),
                [6; 32],
                &chunks
            )
            .is_err(),
            "a transcript does not verify for another request"
        );
    }

    #[test]
    fn message_layout_is_fixed_length() {
        let m = chunk_message(&[0; 16], &PolicyHash([0; 32]), &REQ, u64::MAX, &[0; 32]);
        assert_eq!(m.len(), CHUNK_MESSAGE_LEN);
        assert!(m.starts_with(CHUNK_DOMAIN));
        let e = end_message(&[0; 16], &PolicyHash([0; 32]), &REQ, 1, 2, &[0; 32]);
        assert_eq!(e.len(), END_MESSAGE_LEN);
        assert!(e.starts_with(END_DOMAIN));
    }
}
