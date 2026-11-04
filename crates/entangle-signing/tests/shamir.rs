//! ATC-REL-2 at the library level: Shamir 2-of-3 over GF(256).

use entangle_signing::shamir::{combine, gf_inv, gf_mul, split, ShamirError, Share};

#[test]
fn atc_rel_2_two_of_three_reconstructs_from_any_pair() {
    let key = [0xA5u8; 32];
    let shares = split(&key, 2, 3).unwrap();
    assert_eq!(shares.len(), 3);
    for (i, j) in [(0, 1), (1, 0), (0, 2), (2, 1)] {
        let got = combine(&[shares[i].clone(), shares[j].clone()]).unwrap();
        assert_eq!(got, key, "pair ({i},{j})");
    }
}

#[test]
fn atc_rel_2_one_share_cannot_reconstruct() {
    let shares = split(&[7u8; 32], 2, 3).unwrap();
    for s in &shares {
        assert!(matches!(
            combine(std::slice::from_ref(s)),
            Err(ShamirError::NotEnoughShares { needed: 2, got: 1 })
        ));
    }
}

/// Information-theoretic secrecy of one share, exhaustive over the secret
/// space of a single byte at threshold 2: for every observed `(x, y)` and
/// every candidate secret `s` there is exactly one slope `a` with
/// `s + a*x = y` in GF(256). So the share is equally consistent with every
/// secret, and cannot narrow it down. Uses only the public field arithmetic
/// the splitter itself uses.
#[test]
fn atc_rel_2_single_share_is_equally_consistent_with_every_secret() {
    for x in 1..=255u8 {
        for y in [0u8, 1, 0x80, 0xFF] {
            for s in 0..=255u8 {
                let consistent: Vec<u8> = (0..=255u8).filter(|&a| s ^ gf_mul(a, x) == y).collect();
                assert_eq!(consistent.len(), 1, "x={x} y={y} s={s}");
                // and that slope is the one the combiner's algebra implies
                assert_eq!(consistent[0], gf_mul(y ^ s, gf_inv(x)));
            }
        }
    }
}

#[test]
fn atc_rel_2_shares_roundtrip_through_text_and_reject_corruption() {
    let shares = split(b"key", 2, 3).unwrap();
    let text = shares[0].encode();
    assert!(text.starts_with("entangle-share-v1:"));
    assert_eq!(Share::decode(&text).unwrap(), shares[0]);
    let mut bad = text.clone().into_bytes();
    let n = bad.len() - 3;
    bad[n] = if bad[n] == b'a' { b'b' } else { b'a' };
    assert!(Share::decode(std::str::from_utf8(&bad).unwrap()).is_err());
}

/// The data bytes of an encoded share: `version(1) set_id(4) threshold(1)
/// index(1) data.. checksum(4)`, hex after the prefix.
fn share_data(s: &Share) -> Vec<u8> {
    let enc = s.encode();
    let raw = hex::decode(enc.strip_prefix("entangle-share-v1:").unwrap()).unwrap();
    raw[7..raw.len() - 4].to_vec()
}

/// The field-identity test above never calls `split`. This one exercises the
/// generator itself: a splitter with no randomness (zero slopes, a constant
/// RNG) would hand every custodian the plaintext, yet still round-trip.
#[test]
fn atc_rel_2_split_shares_do_not_carry_the_secret() {
    let secret = [0x5Au8; 32];
    let mut equal_bytes = 0usize;
    let mut total_bytes = 0usize;
    let mut previous: Option<Vec<Vec<u8>>> = None;
    for _ in 0..200 {
        let shares = split(&secret, 2, 3).unwrap();
        let datas: Vec<Vec<u8>> = shares.iter().map(share_data).collect();
        for d in &datas {
            // 32 secret bytes plus the integrity tag.
            assert!(d.len() > secret.len());
            assert_ne!(&d[..secret.len()], &secret[..], "a share is the secret");
            equal_bytes += d[..secret.len()]
                .iter()
                .zip(&secret)
                .filter(|(a, b)| a == b)
                .count();
            total_bytes += secret.len();
        }
        // Distinct custodians hold distinct data.
        assert_ne!(datas[0], datas[1]);
        assert_ne!(datas[1], datas[2]);
        assert_ne!(datas[0], datas[2]);
        // Two splits of one secret are independent.
        if let Some(prev) = &previous {
            assert_ne!(prev[0], datas[0], "two splits produced identical shares");
        }
        previous = Some(datas);
    }
    // A uniform byte equals the secret byte with probability 1/256: about 75
    // of 19200 here. Plaintext-carrying shares would match all of them.
    assert!(
        equal_bytes < 200,
        "{equal_bytes} of {total_bytes} share bytes equal the secret byte"
    );
}

/// One share byte, over many splits of the same secret, takes every value:
/// it is uniform and so independent of the secret byte.
#[test]
fn atc_rel_2_a_share_byte_is_uniform_over_splits_of_one_secret() {
    let secret = [0u8; 16];
    let mut seen = [false; 256];
    for _ in 0..4000 {
        let shares = split(&secret, 2, 3).unwrap();
        seen[usize::from(share_data(&shares[0])[0])] = true;
    }
    let distinct = seen.iter().filter(|s| **s).count();
    // Expected about 256 * (1 - e^-15.6) = 256; a degenerate generator gives 1.
    assert!(distinct >= 250, "only {distinct} distinct values");
}
