//! The integrity-policy envelope of a work unit (spec §7.5, INV-INT-1).
//!
//! > **INV-INT-1:** ∀ replica r ∈ task.replicas.
//! > r.observed_policy_hash == task.envelope.policy_hash, and the policy is
//! > immutable for the lifetime of the task.
//!
//! The submitter seals the task's [`IntegrityPolicy`] into a
//! [`PolicyEnvelope`]: the policy's **canonical bytes** plus
//! `policy_hash = SHA-256(canonical bytes)`. Both travel in every task frame.
//! The worker recomputes the hash before executing ([`verify_envelope`]) and
//! again before answering, and echoes the hash it observed; the submitter
//! refuses any replica whose echo differs (`ENTANGLE-E0315`). A control frame
//! that would change the policy of an in-flight task is refused by the worker
//! (`ENTANGLE-E0316`, see [`crate::remote`]).
//!
//! # Canonical encoding (format `EIP1`)
//!
//! Hand-written rather than derived from serde, so the bytes — and therefore
//! the hash — depend on nothing but this specification:
//!
//! ```text
//! policy   = "EIP1" tag body
//! tag      = u8: 0 None | 1 Deterministic | 2 SemanticEquivalent
//!                | 3 TrustedExecutor | 4 Attested
//! None               : (empty)
//! Deterministic      : replicas:u8
//! SemanticEquivalent : replicas:u8 quorum:u8 metric_plugin:str
//!                      publisher_key:[32] artifact_blake3:[32] threshold:f64
//! TrustedExecutor    : count:u32 peer_id:[16] * count      (order preserved)
//! Attested           : tee:str
//! str  = len:u32 utf8-bytes          u32 = 4 bytes big-endian
//! f64  = IEEE-754 bits, 8 bytes big-endian; -0.0 is written as +0.0
//! ```
//!
//! `metric_plugin` is the plugin id's display form
//! (`<publisher>/<name>@<version>`, publisher in lowercase hex).
//!
//! The encoding is *canonical*: [`decode_canonical_policy`] re-encodes what it
//! decoded and refuses the input unless the bytes are identical, so every
//! policy has exactly one valid encoding and one hash. A policy that cannot
//! survive that round trip (a `NaN` threshold, a non-normalised plugin id) is
//! refused by [`PolicyEnvelope::seal`] before anything is dispatched.

use entangle_runtime::IntegrityError;
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::{IntegrityPolicy, MetricRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Magic + format version that opens every canonical policy encoding.
pub const POLICY_MAGIC: &[u8; 4] = b"EIP1";

/// Ceiling on canonical policy bytes accepted from the wire (64 KiB — room
/// for a `TrustedExecutor` allowlist of ~4 000 peers).
pub const MAX_POLICY_BYTES: usize = 64 * 1024;

const TAG_NONE: u8 = 0;
const TAG_DETERMINISTIC: u8 = 1;
const TAG_SEMANTIC: u8 = 2;
const TAG_TRUSTED: u8 = 3;
const TAG_ATTESTED: u8 = 4;

/// `SHA-256` of a policy's canonical bytes.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyHash(pub [u8; 32]);

impl PolicyHash {
    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for PolicyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for PolicyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PolicyHash({})", self.to_hex())
    }
}

/// SHA-256 of `canonical`.
pub fn hash_canonical(canonical: &[u8]) -> PolicyHash {
    PolicyHash(Sha256::digest(canonical).into())
}

/// The canonical encoding of `policy` (see the module docs).
pub fn canonical_policy_bytes(policy: &IntegrityPolicy) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(POLICY_MAGIC);
    match policy {
        IntegrityPolicy::None => out.push(TAG_NONE),
        IntegrityPolicy::Deterministic { replicas } => {
            out.push(TAG_DETERMINISTIC);
            out.push(*replicas);
        }
        IntegrityPolicy::SemanticEquivalent {
            replicas,
            quorum,
            metric,
            threshold,
        } => {
            out.push(TAG_SEMANTIC);
            out.push(*replicas);
            out.push(*quorum);
            put_str(&mut out, &metric.plugin.to_string());
            out.extend_from_slice(&metric.publisher_key);
            out.extend_from_slice(&metric.artifact_blake3);
            // `-0.0 == 0.0`, so they must share one encoding.
            let t = if *threshold == 0.0 { 0.0 } else { *threshold };
            out.extend_from_slice(&t.to_bits().to_be_bytes());
        }
        IntegrityPolicy::TrustedExecutor { allowlist } => {
            out.push(TAG_TRUSTED);
            put_len(&mut out, allowlist.len());
            for peer in allowlist {
                out.extend_from_slice(&peer.as_bytes());
            }
        }
        IntegrityPolicy::Attested { tee } => {
            out.push(TAG_ATTESTED);
            put_str(&mut out, tee);
        }
    }
    out
}

/// `SHA-256(canonical_policy_bytes(policy))`.
pub fn policy_hash(policy: &IntegrityPolicy) -> PolicyHash {
    hash_canonical(&canonical_policy_bytes(policy))
}

/// Decode canonical policy bytes from an untrusted source.
///
/// Refuses (with [`IntegrityError::PolicyEncoding`]) anything over
/// [`MAX_POLICY_BYTES`], a wrong magic, an unknown tag, truncated or trailing
/// bytes, invalid UTF-8 or plugin ids, and any input that is not the
/// canonical encoding of the policy it decodes to.
pub fn decode_canonical_policy(bytes: &[u8]) -> Result<IntegrityPolicy, IntegrityError> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(enc(format!(
            "{} bytes exceeds the {MAX_POLICY_BYTES}-byte cap",
            bytes.len()
        )));
    }
    let mut r = Reader { rest: bytes };
    if r.take(4)? != POLICY_MAGIC {
        return Err(enc("missing EIP1 magic".into()));
    }
    let policy = match r.u8()? {
        TAG_NONE => IntegrityPolicy::None,
        TAG_DETERMINISTIC => IntegrityPolicy::Deterministic { replicas: r.u8()? },
        TAG_SEMANTIC => {
            let replicas = r.u8()?;
            let quorum = r.u8()?;
            let plugin: PluginId = r
                .str()?
                .parse()
                .map_err(|e| enc(format!("metric plugin id: {e}")))?;
            let publisher_key = r.array32()?;
            let artifact_blake3 = r.array32()?;
            let threshold = f64::from_bits(u64::from_be_bytes(r.array8()?));
            IntegrityPolicy::SemanticEquivalent {
                replicas,
                quorum,
                metric: MetricRef {
                    plugin,
                    publisher_key,
                    artifact_blake3,
                },
                threshold,
            }
        }
        TAG_TRUSTED => {
            let count = r.len()?;
            // Each entry is 16 bytes: refuse a count the input cannot hold
            // before allocating for it.
            if count.saturating_mul(16) > r.rest.len() {
                return Err(enc(format!("allowlist count {count} overruns the input")));
            }
            let mut allowlist = Vec::with_capacity(count);
            for _ in 0..count {
                let raw = r.take(16)?;
                allowlist
                    .push(PeerId::from_hex(&hex::encode(raw)).map_err(|e| enc(e.to_string()))?);
            }
            IntegrityPolicy::TrustedExecutor { allowlist }
        }
        TAG_ATTESTED => IntegrityPolicy::Attested { tee: r.str()? },
        other => return Err(enc(format!("unknown policy tag {other}"))),
    };
    if !r.rest.is_empty() {
        return Err(enc(format!("{} trailing bytes", r.rest.len())));
    }
    if canonical_policy_bytes(&policy) != bytes {
        return Err(enc(
            "bytes are not the canonical encoding of the policy".into()
        ));
    }
    Ok(policy)
}

/// Check that `canonical` hashes to `claimed`, then decode it.
///
/// This is the worker's INV-INT-1 gate, run before execution. A hash that
/// does not match is [`IntegrityError::PolicyHashMismatch`] (`peer` is
/// `"envelope"`: the envelope disagrees with itself); undecodable bytes are
/// [`IntegrityError::PolicyEncoding`].
pub fn verify_envelope(
    canonical: &[u8],
    claimed: &PolicyHash,
) -> Result<IntegrityPolicy, IntegrityError> {
    let actual = hash_canonical(canonical);
    if actual != *claimed {
        return Err(IntegrityError::PolicyHashMismatch {
            peer: "envelope".into(),
            expected: claimed.to_hex(),
            observed: actual.to_hex(),
        });
    }
    decode_canonical_policy(canonical)
}

/// A sealed integrity policy: the policy, its canonical bytes, and their hash.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyEnvelope {
    policy: IntegrityPolicy,
    canonical: Vec<u8>,
    hash: PolicyHash,
}

impl PolicyEnvelope {
    /// Seal `policy` for dispatch.
    ///
    /// Fails with [`IntegrityError::InvalidPolicy`] if the policy does not
    /// survive a canonical round trip (for example a `NaN` threshold, or a
    /// metric plugin id whose publisher is not lowercase hex), since a worker
    /// could never verify such an envelope.
    pub fn seal(policy: &IntegrityPolicy) -> Result<Self, IntegrityError> {
        let canonical = canonical_policy_bytes(policy);
        match decode_canonical_policy(&canonical) {
            Ok(decoded) if decoded == *policy => {}
            Ok(_) | Err(_) => {
                return Err(IntegrityError::InvalidPolicy(
                    "the policy has no canonical encoding (non-finite threshold or \
                     non-normalised plugin id?)"
                        .into(),
                ))
            }
        }
        Ok(Self {
            policy: policy.clone(),
            hash: hash_canonical(&canonical),
            canonical,
        })
    }

    /// Open an envelope received from the wire: [`verify_envelope`], keeping
    /// the bytes so the hash can be re-verified later.
    pub fn open(canonical: Vec<u8>, claimed: PolicyHash) -> Result<Self, IntegrityError> {
        let policy = verify_envelope(&canonical, &claimed)?;
        Ok(Self {
            policy,
            canonical,
            hash: claimed,
        })
    }

    /// The sealed policy.
    pub fn policy(&self) -> &IntegrityPolicy {
        &self.policy
    }

    /// The canonical bytes.
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// The policy hash `H`.
    pub fn hash(&self) -> PolicyHash {
        self.hash
    }

    /// Recompute `SHA-256(canonical bytes)` now. Equal to [`Self::hash`]
    /// unless the bytes changed after sealing — which is exactly what the
    /// re-check before returning a replica result guards against.
    pub fn recompute_hash(&self) -> PolicyHash {
        hash_canonical(&self.canonical)
    }
}

fn enc(msg: String) -> IntegrityError {
    IntegrityError::PolicyEncoding(msg)
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    // Policies are bounded far below u32::MAX (MAX_POLICY_BYTES); saturating
    // keeps an absurd value from wrapping into a small, wrong length.
    let len = u32::try_from(len).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_len(out, s.len());
    out.extend_from_slice(s.as_bytes());
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], IntegrityError> {
        if self.rest.len() < n {
            return Err(enc("truncated".into()));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, IntegrityError> {
        Ok(self.take(1)?[0])
    }

    fn len(&mut self) -> Result<usize, IntegrityError> {
        let raw: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| enc("truncated".into()))?;
        Ok(u32::from_be_bytes(raw) as usize)
    }

    fn array8(&mut self) -> Result<[u8; 8], IntegrityError> {
        self.take(8)?
            .try_into()
            .map_err(|_| enc("truncated".into()))
    }

    fn array32(&mut self) -> Result<[u8; 32], IntegrityError> {
        self.take(32)?
            .try_into()
            .map_err(|_| enc("truncated".into()))
    }

    fn str(&mut self) -> Result<String, IntegrityError> {
        let len = self.len()?;
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec()).map_err(|_| enc("string is not UTF-8".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric() -> MetricRef {
        let publisher_key = [5u8; 32];
        let publisher = hex::encode(&blake3::hash(&publisher_key).as_bytes()[..16]);
        MetricRef {
            plugin: format!("{publisher}/metric-bleu-4@0.1.0").parse().unwrap(),
            publisher_key,
            artifact_blake3: [6u8; 32],
        }
    }

    fn semantic(threshold: f64) -> IntegrityPolicy {
        IntegrityPolicy::SemanticEquivalent {
            replicas: 3,
            quorum: 2,
            metric: metric(),
            threshold,
        }
    }

    fn all_variants() -> Vec<IntegrityPolicy> {
        vec![
            IntegrityPolicy::None,
            IntegrityPolicy::Deterministic { replicas: 3 },
            semantic(0.15),
            IntegrityPolicy::TrustedExecutor {
                allowlist: vec![
                    PeerId::from_public_key_bytes(&[1; 32]),
                    PeerId::from_public_key_bytes(&[2; 32]),
                ],
            },
            IntegrityPolicy::Attested { tee: "sev".into() },
        ]
    }

    #[test]
    fn every_variant_round_trips_canonically() {
        for p in all_variants() {
            let bytes = canonical_policy_bytes(&p);
            assert_eq!(&bytes[..4], POLICY_MAGIC);
            assert_eq!(decode_canonical_policy(&bytes).unwrap(), p, "{p:?}");
            let env = PolicyEnvelope::seal(&p).unwrap();
            assert_eq!(env.canonical(), bytes.as_slice());
            assert_eq!(env.hash(), policy_hash(&p));
            assert_eq!(env.recompute_hash(), env.hash());
        }
    }

    /// The hash is pinned to the specification, not to whatever serde or a
    /// compiler happens to do: a known policy has a known hash.
    #[test]
    fn hash_is_sha256_of_the_documented_bytes() {
        let p = IntegrityPolicy::Deterministic { replicas: 3 };
        assert_eq!(canonical_policy_bytes(&p), b"EIP1\x01\x03");
        assert_eq!(
            policy_hash(&p).to_hex(),
            hex::encode(Sha256::digest(b"EIP1\x01\x03"))
        );
        assert_eq!(canonical_policy_bytes(&IntegrityPolicy::None), b"EIP1\x00");
    }

    /// Different policies — even ones differing only in the threshold, or
    /// the metric's artifact digest — hash differently.
    #[test]
    fn distinct_policies_have_distinct_hashes() {
        let mut hashes: Vec<PolicyHash> = all_variants().iter().map(policy_hash).collect();
        hashes.push(policy_hash(&semantic(0.16)));
        let mut other_artifact = metric();
        other_artifact.artifact_blake3[0] ^= 1;
        hashes.push(policy_hash(&IntegrityPolicy::SemanticEquivalent {
            replicas: 3,
            quorum: 2,
            metric: other_artifact,
            threshold: 0.15,
        }));
        let n = hashes.len();
        hashes.sort_by_key(|h| h.0);
        hashes.dedup();
        assert_eq!(hashes.len(), n);
    }

    #[test]
    fn negative_zero_threshold_shares_the_positive_zero_encoding() {
        assert_eq!(
            canonical_policy_bytes(&semantic(-0.0)),
            canonical_policy_bytes(&semantic(0.0))
        );
        PolicyEnvelope::seal(&semantic(-0.0)).expect("-0.0 == 0.0 seals");
    }

    #[test]
    fn a_nan_threshold_cannot_be_sealed() {
        assert!(matches!(
            PolicyEnvelope::seal(&semantic(f64::NAN)),
            Err(IntegrityError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn non_canonical_and_malformed_bytes_are_refused() {
        let good = canonical_policy_bytes(&semantic(0.25));
        // Trailing byte.
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(decode_canonical_policy(&trailing).is_err());
        // Every strict prefix is truncated.
        for cut in 0..good.len() {
            assert!(
                decode_canonical_policy(&good[..cut]).is_err(),
                "prefix {cut}"
            );
        }
        // Wrong magic, unknown tag.
        assert!(decode_canonical_policy(b"EIP2\x00").is_err());
        assert!(decode_canonical_policy(b"EIP1\x09").is_err());
        // -0.0 bits are not canonical.
        let mut neg_zero = canonical_policy_bytes(&semantic(0.0));
        let at = neg_zero.len() - 8;
        neg_zero[at..].copy_from_slice(&(-0.0f64).to_bits().to_be_bytes());
        assert!(decode_canonical_policy(&neg_zero).is_err());
        // An upper-case publisher in the plugin id is not canonical.
        let upper = String::from_utf8_lossy(&good).replace(
            &metric().plugin.publisher,
            &metric().plugin.publisher.to_ascii_uppercase(),
        );
        if upper.as_bytes() != good.as_slice() {
            assert!(decode_canonical_policy(upper.as_bytes()).is_err());
        }
        // An allowlist count larger than the input.
        assert!(decode_canonical_policy(b"EIP1\x03\xff\xff\xff\xff").is_err());
        // Over the cap.
        assert!(decode_canonical_policy(&vec![0u8; MAX_POLICY_BYTES + 1]).is_err());
    }

    #[test]
    fn verify_envelope_checks_the_hash_before_decoding() {
        let p = semantic(0.2);
        let bytes = canonical_policy_bytes(&p);
        assert_eq!(verify_envelope(&bytes, &policy_hash(&p)).unwrap(), p);

        let wrong = policy_hash(&semantic(0.9));
        match verify_envelope(&bytes, &wrong) {
            Err(IntegrityError::PolicyHashMismatch {
                expected, observed, ..
            }) => {
                assert_eq!(expected, wrong.to_hex());
                assert_eq!(observed, policy_hash(&p).to_hex());
            }
            other => panic!("expected PolicyHashMismatch, got {other:?}"),
        }
        // A garbage body whose hash *does* match is still refused.
        let junk = b"not a policy".to_vec();
        assert!(matches!(
            PolicyEnvelope::open(junk.clone(), hash_canonical(&junk)),
            Err(IntegrityError::PolicyEncoding(_))
        ));
    }

    #[test]
    fn garbage_never_panics() {
        for seed in 0u8..=255 {
            let junk: Vec<u8> = b"EIP1"
                .iter()
                .copied()
                .chain((0..40u8).map(|i| i.wrapping_mul(seed).wrapping_add(seed)))
                .collect();
            let _ = decode_canonical_policy(&junk);
        }
    }
}
