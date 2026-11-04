//! ATC-REL-2 at the library level: Shamir 2-of-3 over GF(256).

use entangle_signing::shamir::{combine, gf_inv, gf_mul, split, Share, ShamirError};

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
