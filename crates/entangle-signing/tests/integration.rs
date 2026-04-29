//! Integration tests for entangle-signing (8 test cases per spec).

use entangle_signing::{
    artifact::{sign_artifact, verify_artifact, VerificationError},
    keypair::IdentityKeyPair,
    keyring::{Keyring, TrustEntry},
};

fn make_entry(kp: &IdentityKeyPair, name: &str) -> TrustEntry {
    TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: name.to_owned(),
        added_at: 1_714_000_000,
        note: String::new(),
    }
}

fn keyring_with(kp: &IdentityKeyPair) -> Keyring {
    let mut kr = Keyring::new();
    kr.add(make_entry(kp, "test-publisher"));
    kr
}

// Test 1: sign and verify happy path.
#[test]
fn test_sign_and_verify_ok() {
    let kp = IdentityKeyPair::generate();
    let artifact = b"hello, entangle!";
    let bundle = sign_artifact(artifact, &kp);
    let kr = keyring_with(&kp);
    let entry = verify_artifact(artifact, &bundle, &kr).expect("verification must succeed");
    assert_eq!(entry.publisher_name, "test-publisher");
}

// Test 2: wrong key in keyring → UnknownPublisher.
#[test]
fn test_wrong_key_unknown_publisher() {
    let signer = IdentityKeyPair::generate();
    let other = IdentityKeyPair::generate();
    let artifact = b"some bytes";
    let bundle = sign_artifact(artifact, &signer);
    // Only other's key is in the keyring.
    let kr = keyring_with(&other);
    let err = verify_artifact(artifact, &bundle, &kr).unwrap_err();
    assert!(
        matches!(err, VerificationError::UnknownPublisher),
        "expected UnknownPublisher, got {err}"
    );
}

// Test 3: tampered artifact bytes → ArtifactHashMismatch.
#[test]
fn test_tampered_artifact_hash_mismatch() {
    let kp = IdentityKeyPair::generate();
    let original = b"original content";
    let tampered = b"tampered content";
    let bundle = sign_artifact(original, &kp);
    let kr = keyring_with(&kp);
    let err = verify_artifact(tampered, &bundle, &kr).unwrap_err();
    assert!(
        matches!(err, VerificationError::ArtifactHashMismatch { .. }),
        "expected ArtifactHashMismatch, got {err}"
    );
}

// Test 4: correct artifact but corrupted signature → BadSignature.
#[test]
fn test_corrupted_signature_bad_signature() {
    let kp = IdentityKeyPair::generate();
    let artifact = b"correct bytes";
    let mut bundle = sign_artifact(artifact, &kp);
    // Flip a byte in the signature.
    bundle.signature[0] ^= 0xff;
    let kr = keyring_with(&kp);
    let err = verify_artifact(artifact, &bundle, &kr).unwrap_err();
    assert!(
        matches!(err, VerificationError::BadSignature),
        "expected BadSignature, got {err}"
    );
}

// Test 5: keyring round-trip (3 entries, save, load, assert equal).
#[test]
fn test_keyring_round_trip() {
    let kps: Vec<_> = (0..3).map(|_| IdentityKeyPair::generate()).collect();
    let names = ["alice", "bob", "carol"];
    let mut kr = Keyring::new();
    for (kp, name) in kps.iter().zip(names.iter()) {
        kr.add(make_entry(kp, name));
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keyring.toml");
    kr.save(&path).expect("save must succeed");

    let loaded = Keyring::load(&path).expect("load must succeed");

    for kp in &kps {
        let fp = kp.fingerprint();
        let orig = kr.lookup(&fp).unwrap();
        let got = loaded.lookup(&fp).expect("entry must survive round-trip");
        assert_eq!(orig.fingerprint, got.fingerprint);
        assert_eq!(orig.public_key, got.public_key);
        assert_eq!(orig.publisher_name, got.publisher_name);
    }
}

// Test 6: PEM round-trip — fingerprint must be stable.
#[test]
fn test_pem_round_trip_fingerprint_stable() {
    let kp = IdentityKeyPair::generate();
    let fp_before = kp.fingerprint_hex();
    let pem = kp.to_pem();
    let kp2 = IdentityKeyPair::from_pem(&pem).expect("from_pem must succeed");
    let fp_after = kp2.fingerprint_hex();
    assert_eq!(
        fp_before, fp_after,
        "fingerprint must be stable across PEM round-trip"
    );
}

// Test 7: unsupported algorithm in bundle → UnsupportedAlgorithm.
#[test]
fn test_unsupported_algorithm() {
    let kp = IdentityKeyPair::generate();
    let artifact = b"data";
    let mut bundle = sign_artifact(artifact, &kp);
    bundle.algorithm = "rsa-pss".to_owned();
    let kr = keyring_with(&kp);
    let err = verify_artifact(artifact, &bundle, &kr).unwrap_err();
    assert!(
        matches!(err, VerificationError::UnsupportedAlgorithm(ref s) if s == "rsa-pss"),
        "expected UnsupportedAlgorithm(rsa-pss), got {err}"
    );
}

// Test 8: deterministic fingerprint from a known seed.
#[test]
fn test_deterministic_fingerprint_from_seed() {
    // seed = all zeros
    let seed = [0u8; 32];
    let kp = IdentityKeyPair::from_seed(&seed);
    let fp = kp.fingerprint_hex();
    // Precompute: BLAKE3-16 of the verifying key for the zero seed.
    // We derive and record it here as a regression anchor.
    let vk_bytes = kp.public().as_bytes().to_owned();
    let expected_fp = {
        let hash = blake3::hash(&vk_bytes);
        hex::encode(&hash.as_bytes()[..16])
    };
    assert_eq!(
        fp, expected_fp,
        "fingerprint must be deterministic for a fixed seed"
    );
    // Also assert the same keypair produces the same fingerprint every time.
    let kp2 = IdentityKeyPair::from_seed(&seed);
    assert_eq!(fp, kp2.fingerprint_hex());
}
