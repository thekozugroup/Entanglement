//! Shamir secret sharing over GF(2^8) (ATC-REL-2).
//!
//! Used for the release-key ceremony (`docs/governance/key-ceremony.md`): the
//! release signing key is split 2-of-3 and the shares are held by different
//! maintainers.
//!
//! # Construction
//! Each byte of the payload is the constant term of an independent random
//! polynomial of degree `threshold - 1` over GF(256) (AES polynomial `0x11B`);
//! share `i` holds the evaluation at `x = i` (`1..=255`). Any `threshold`
//! shares recover the payload by Lagrange interpolation at `x = 0`; fewer
//! reveal nothing about it (information-theoretically: for any single share
//! every payload value is consistent with exactly one polynomial per byte).
//!
//! # Constant time
//! All field arithmetic is branch-free and table-free: [`gf_mul`] is a
//! shift-and-mask loop with a fixed trip count and [`gf_inv`] is
//! exponentiation by the public constant 254. No memory access is indexed by
//! secret data. (Share *indices* are public.)
//!
//! # Detecting wrong or mixed shares
//! The payload is `secret || BLAKE3(secret)[..4]`; the check bytes are shared
//! like the rest, so a single share still reveals nothing, but
//! [`combine`] rejects a reconstruction whose trailer does not match (a wrong,
//! corrupted or foreign share). Every share additionally carries a random
//! per-split set id (mixing shares of two splits is rejected up front), the
//! threshold, and a 4-byte BLAKE3 checksum over the whole encoded share
//! (transcription errors are caught on [`Share::decode`]).

use rand_core::{CryptoRng, RngCore};

/// Number of check bytes appended to the secret before sharing.
const CHECK_LEN: usize = 4;
/// Share wire-format version.
const SHARE_VERSION: u8 = 1;
/// Text prefix of an encoded share.
pub const SHARE_PREFIX: &str = "entangle-share-v1:";
/// Largest secret that can be split.
pub const MAX_SECRET_LEN: usize = 4096;

/// Errors from splitting and combining.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShamirError {
    /// `threshold`/`shares` out of range.
    #[error("ENTANGLE-E0850: invalid split parameters: {0}")]
    InvalidParameters(String),
    /// Empty or oversized secret.
    #[error("ENTANGLE-E0851: secret must be 1..={MAX_SECRET_LEN} bytes (got {0})")]
    BadSecretLength(usize),
    /// A share string could not be parsed or failed its checksum.
    #[error("ENTANGLE-E0852: malformed share: {0}")]
    MalformedShare(String),
    /// Shares from different splits (or with different thresholds) were mixed.
    #[error("ENTANGLE-E0853: shares come from different splits")]
    MixedShares,
    /// Two shares carry the same index.
    #[error("ENTANGLE-E0854: duplicate share index {0}")]
    DuplicateShare(u8),
    /// Fewer shares than the threshold.
    #[error("ENTANGLE-E0855: need {needed} shares to reconstruct, got {got}")]
    NotEnoughShares {
        /// Threshold recorded in the shares.
        needed: u8,
        /// Number of shares supplied.
        got: usize,
    },
    /// The reconstruction's check bytes do not match: a share is wrong.
    #[error(
        "ENTANGLE-E0856: reconstruction failed its integrity check (a share is wrong or corrupted)"
    )]
    CheckFailed,
}

/// One share of a split secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// Random identifier of the split this share belongs to.
    pub set_id: [u8; 4],
    /// Number of shares needed to reconstruct.
    pub threshold: u8,
    /// Evaluation point, `1..=255`.
    pub index: u8,
    /// Evaluations of the payload polynomials at `index`.
    data: Vec<u8>,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("set_id", &hex::encode(self.set_id))
            .field("threshold", &self.threshold)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl Share {
    /// Encode as `entangle-share-v1:<hex>`.
    pub fn encode(&self) -> String {
        let mut b = Vec::with_capacity(8 + self.data.len() + 4);
        b.push(SHARE_VERSION);
        b.extend_from_slice(&self.set_id);
        b.push(self.threshold);
        b.push(self.index);
        b.extend_from_slice(&self.data);
        let ck = blake3::hash(&b);
        b.extend_from_slice(&ck.as_bytes()[..4]);
        format!("{SHARE_PREFIX}{}", hex::encode(b))
    }

    /// Parse and checksum-verify an encoded share.
    pub fn decode(s: &str) -> Result<Self, ShamirError> {
        let bad = |m: &str| ShamirError::MalformedShare(m.to_owned());
        let body = s
            .trim()
            .strip_prefix(SHARE_PREFIX)
            .ok_or_else(|| bad("missing entangle-share-v1: prefix"))?;
        let b = hex::decode(body).map_err(|_| bad("not valid hex"))?;
        if b.len() < 1 + 4 + 1 + 1 + CHECK_LEN + 1 + 4 {
            return Err(bad("too short"));
        }
        let (head, ck) = b.split_at(b.len() - 4);
        if blake3::hash(head).as_bytes()[..4] != *ck {
            return Err(bad("checksum mismatch (typo or corruption)"));
        }
        if head[0] != SHARE_VERSION {
            return Err(bad("unsupported share version"));
        }
        let mut set_id = [0u8; 4];
        set_id.copy_from_slice(&head[1..5]);
        let (threshold, index) = (head[5], head[6]);
        if threshold < 2 || index == 0 {
            return Err(bad("invalid threshold or index"));
        }
        Ok(Self {
            set_id,
            threshold,
            index,
            data: head[7..].to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// GF(256), constant time
// ---------------------------------------------------------------------------

/// Multiply in GF(2^8) modulo `x^8 + x^4 + x^3 + x + 1`. Constant time.
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let (mut a, mut b, mut r) = (a, b, 0u8);
    for _ in 0..8 {
        r ^= a & 0u8.wrapping_sub(b & 1);
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & carry);
        b >>= 1;
    }
    r
}

/// Multiplicative inverse (`a^254`; `0` maps to `0`). Constant time: the
/// exponent is a public constant.
pub fn gf_inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    for _ in 0..8 {
        if exp & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Horner evaluation of `coeffs[0] + coeffs[1] x + ...` at public `x`.
fn eval(coeffs: &[u8], x: u8) -> u8 {
    coeffs.iter().rev().fold(0u8, |acc, &c| gf_mul(acc, x) ^ c)
}

fn check_bytes(secret: &[u8]) -> [u8; CHECK_LEN] {
    let mut c = [0u8; CHECK_LEN];
    c.copy_from_slice(&blake3::hash(secret).as_bytes()[..CHECK_LEN]);
    c
}

// ---------------------------------------------------------------------------
// Split / combine
// ---------------------------------------------------------------------------

/// Split `secret` into `shares` shares, any `threshold` of which reconstruct
/// it. Uses the operating-system RNG.
pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<Share>, ShamirError> {
    split_with_rng(secret, threshold, shares, &mut rand_core::OsRng)
}

/// [`split`] with a caller-supplied cryptographic RNG.
pub fn split_with_rng<R: RngCore + CryptoRng>(
    secret: &[u8],
    threshold: u8,
    shares: u8,
    rng: &mut R,
) -> Result<Vec<Share>, ShamirError> {
    if threshold < 2 {
        return Err(ShamirError::InvalidParameters(
            "threshold must be at least 2 (a threshold of 1 is the secret itself)".into(),
        ));
    }
    if shares < threshold {
        return Err(ShamirError::InvalidParameters(format!(
            "shares ({shares}) must be >= threshold ({threshold})"
        )));
    }
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(ShamirError::BadSecretLength(secret.len()));
    }
    let mut payload = secret.to_vec();
    payload.extend_from_slice(&check_bytes(secret));

    let mut set_id = [0u8; 4];
    rng.fill_bytes(&mut set_id);

    let mut out: Vec<Share> = (1..=shares)
        .map(|index| Share {
            set_id,
            threshold,
            index,
            data: Vec::with_capacity(payload.len()),
        })
        .collect();
    let mut coeffs = vec![0u8; usize::from(threshold)];
    for &byte in &payload {
        coeffs[0] = byte;
        rng.fill_bytes(&mut coeffs[1..]);
        for share in &mut out {
            share.data.push(eval(&coeffs, share.index));
        }
    }
    Ok(out)
}

/// Reconstruct the secret from at least `threshold` shares of one split.
///
/// Fails (rather than returning garbage) on too few shares, shares of
/// different splits, duplicate indices, or a wrong share.
pub fn combine(shares: &[Share]) -> Result<Vec<u8>, ShamirError> {
    let first = shares
        .first()
        .ok_or(ShamirError::NotEnoughShares { needed: 2, got: 0 })?;
    for s in shares {
        if s.set_id != first.set_id
            || s.threshold != first.threshold
            || s.data.len() != first.data.len()
        {
            return Err(ShamirError::MixedShares);
        }
    }
    for (i, a) in shares.iter().enumerate() {
        if shares[..i].iter().any(|b| b.index == a.index) {
            return Err(ShamirError::DuplicateShare(a.index));
        }
    }
    let t = usize::from(first.threshold);
    if shares.len() < t {
        return Err(ShamirError::NotEnoughShares {
            needed: first.threshold,
            got: shares.len(),
        });
    }
    let used = &shares[..t];
    // Lagrange basis at x = 0: l_i = prod_{j != i} x_j / (x_i ^ x_j).
    let basis: Vec<u8> = used
        .iter()
        .map(|si| {
            used.iter()
                .filter(|sj| sj.index != si.index)
                .fold(1u8, |acc, sj| {
                    gf_mul(acc, gf_mul(sj.index, gf_inv(si.index ^ sj.index)))
                })
        })
        .collect();
    let payload: Vec<u8> = (0..first.data.len())
        .map(|k| {
            used.iter()
                .zip(&basis)
                .fold(0u8, |acc, (s, &l)| acc ^ gf_mul(s.data[k], l))
        })
        .collect();
    if payload.len() <= CHECK_LEN {
        return Err(ShamirError::CheckFailed);
    }
    let (secret, check) = payload.split_at(payload.len() - CHECK_LEN);
    let expect = check_bytes(secret);
    // Constant-time comparison of the trailer.
    let diff = expect.iter().zip(check).fold(0u8, |d, (a, b)| d | (a ^ b));
    if diff != 0 {
        return Err(ShamirError::CheckFailed);
    }
    Ok(secret.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_axioms() {
        // AES test vector: 0x57 * 0x83 = 0xC1.
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a}");
        }
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn any_two_of_three_reconstruct() {
        let secret = b"release signing key material \x00\xff";
        let s = split(secret, 2, 3).unwrap();
        for (i, j) in [(0, 1), (0, 2), (1, 2), (2, 0), (2, 1)] {
            assert_eq!(combine(&[s[i].clone(), s[j].clone()]).unwrap(), secret);
        }
        assert_eq!(combine(&s).unwrap(), secret);
    }

    #[test]
    fn one_share_is_not_enough() {
        let s = split(b"secret", 2, 3).unwrap();
        assert_eq!(
            combine(&s[..1]),
            Err(ShamirError::NotEnoughShares { needed: 2, got: 1 })
        );
    }

    /// Perfect secrecy for a single share, checked exhaustively: for a
    /// 1-byte payload, threshold 2, and any observed share `(x, y)`, every one
    /// of the 256 possible secrets has exactly one slope that yields `y`, so
    /// the share carries no information about the secret.
    #[test]
    fn single_share_is_consistent_with_every_secret() {
        for x in [1u8, 2, 3, 77, 255] {
            for y in [0u8, 1, 0x5A, 0xFF] {
                for secret in 0..=255u8 {
                    let slopes = (0..=255u8)
                        .filter(|&a1| eval(&[secret, a1], x) == y)
                        .count();
                    assert_eq!(slopes, 1, "x={x} y={y} secret={secret}");
                }
            }
        }
    }

    #[test]
    fn wrong_and_mixed_shares_are_detected() {
        let a = split(b"alpha secret", 2, 3).unwrap();
        let b = split(b"alpha secret", 2, 3).unwrap();
        assert_eq!(
            combine(&[a[0].clone(), b[1].clone()]),
            Err(ShamirError::MixedShares)
        );
        // A tampered (but self-consistent) share fails the integrity check.
        let mut t = a[1].clone();
        t.data[0] ^= 1;
        assert_eq!(
            combine(&[a[0].clone(), t.clone()]),
            Err(ShamirError::CheckFailed)
        );
        // A transcription error fails the checksum at decode time.
        let enc = a[0].encode();
        let mut chars: Vec<char> = enc.chars().collect();
        let n = chars.len() - 9;
        chars[n] = if chars[n] == '0' { '1' } else { '0' };
        let corrupted: String = chars.into_iter().collect();
        assert!(matches!(
            Share::decode(&corrupted),
            Err(ShamirError::MalformedShare(_))
        ));
        assert_eq!(
            combine(&[a[0].clone(), a[0].clone()]),
            Err(ShamirError::DuplicateShare(1))
        );
    }

    #[test]
    fn encoding_roundtrips_and_parameters_are_validated() {
        let s = split(b"k", 3, 5).unwrap();
        for sh in &s {
            assert_eq!(&Share::decode(&sh.encode()).unwrap(), sh);
        }
        assert!(split(b"k", 1, 3).is_err());
        assert!(split(b"k", 4, 3).is_err());
        assert!(split(b"", 2, 3).is_err());
        let picked = [s[4].clone(), s[0].clone(), s[2].clone()];
        assert_eq!(combine(&picked).unwrap(), b"k");
    }
}
