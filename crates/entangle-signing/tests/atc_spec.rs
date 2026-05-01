//! §16 ATC-SIG-* acceptance tests for `entangle-signing`.
//!
//! Each test name is the ATC code lowercased, enabling's matrix runner
//! to scrape `cargo test -- --list` output for spec coverage.
//!
//! ATC IDs implemented here:
//! ATC-SIG-1 sign-and-verify happy path
//! ATC-SIG-2 empty keyring → UnknownPublisher
//! ATC-SIG-3 mutated artifact bytes → ArtifactHashMismatch
//! ATC-SIG-4 mutated signature bytes → BadSignature
//! ATC-SIG-5 unsupported algorithm → UnsupportedAlgorithm
//! ATC-REP-1 Ed25519+BLAKE3 signatures are deterministic (differ only in created_at)
//!
//! ATC IDs deferred (out of scope for entangle-signing):
//! ATC-BRG-{1..6} — crates/entangle-signing (bridge biscuit module, future iter)
//! ATC-PKG-{1..4} — crates/cargo-entangle (reproducible packaging CLI)
//! ATC-INT-{1..6} — crates/entangle-plugin-scheduler (IntegrityPolicy + verifier locality)
//! ATC-MAN-{1..4} — crates/entangle-manifest (manifest + tier checks)
//! ATC-STR-{1..3} — crates/entangle-plugin-scheduler (streaming credit/heartbeat)
//! ATC-WRP-{1..3} — tests/bats (wrapper UX shell tests)
//! ATC-MAX-{1..3} — tests/bats (max_tier_allowed interactive tests)
//! ATC-MIR-{1..2} — crates/entangle-oci (mirror-as-CDN listing verification)
//! ATC-REL-{1..2} — tests/integration (cosign + Shamir release signing)
//! ATC-BUS-{1..2} — .github/workflows (bus-factor CI invariant)

use entangle_signing::{
    artifact::{sign_artifact, verify_artifact, VerificationError},
    keypair::IdentityKeyPair,
    keyring::{Keyring, TrustEntry},
};

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

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
    kr.add(make_entry(kp, "atc-publisher"));
    kr
}

// ---------------------------------------------------------------------------
// ATC-SIG-1
// ---------------------------------------------------------------------------

/// §16 ATC-SIG-1 — Sign-and-verify happy path.
///
/// GIVEN keypair K,
/// WHEN sign_artifact(A, K) produces bundle B AND verify_artifact(A, B, keyring{K}) runs,
/// THEN Ok(TrustEntry) is returned AND publisher_name matches.
#[test]
fn atc_sig_1_sign_verify_happy_path() {
    let kp = IdentityKeyPair::generate();
    // Signing target is BLAKE3(bytes) per §3.6 — sign_artifact handles this internally.
    let artifact = b"atc-sig-1 test artifact bytes";
    let bundle = sign_artifact(artifact, &kp);

    let kr = keyring_with(&kp);
    let entry = verify_artifact(artifact, &bundle, &kr)
        .expect("ATC-SIG-1: verification must succeed with correct keypair");

    assert_eq!(
        entry.publisher_name, "atc-publisher",
        "ATC-SIG-1: returned TrustEntry must match registered publisher"
    );
    // Confirm bundle records correct algorithm per §3.6.
    assert_eq!(
        bundle.algorithm, "ed25519",
        "ATC-SIG-1: algorithm must be ed25519"
    );
}

// ---------------------------------------------------------------------------
// ATC-SIG-2
// ---------------------------------------------------------------------------

/// §16 ATC-SIG-2 — Empty keyring yields UnknownPublisher.
///
/// GIVEN signed artifact A,
/// WHEN verify_artifact(A, bundle, empty_keyring) runs,
/// THEN Err(VerificationError::UnknownPublisher) is returned.
#[test]
fn atc_sig_2_empty_keyring_unknown_publisher() {
    let kp = IdentityKeyPair::generate();
    let artifact = b"atc-sig-2 payload";
    let bundle = sign_artifact(artifact, &kp);

    let empty_kr = Keyring::new();
    let err = verify_artifact(artifact, &bundle, &empty_kr)
        .expect_err("ATC-SIG-2: verification against empty keyring must fail");

    assert!(
        matches!(err, VerificationError::UnknownPublisher),
        "ATC-SIG-2: expected UnknownPublisher, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// ATC-SIG-3
// ---------------------------------------------------------------------------

/// §16 ATC-SIG-3 — Mutated artifact bytes yield ArtifactHashMismatch.
///
/// GIVEN signed artifact A,
/// WHEN bytes are mutated to A' AND verify_artifact(A', bundle_of_A, keyring) runs,
/// THEN Err(VerificationError::ArtifactHashMismatch) is returned.
///
/// The bundle records BLAKE3(A); re-hashing A' produces a different digest.
#[test]
fn atc_sig_3_mutated_artifact_hash_mismatch() {
    let kp = IdentityKeyPair::generate();
    let original = b"atc-sig-3 original artifact";
    let mutated = b"atc-sig-3 mutated artifact";
    let bundle = sign_artifact(original, &kp);

    let kr = keyring_with(&kp);
    let err = verify_artifact(mutated, &bundle, &kr)
        .expect_err("ATC-SIG-3: verification of mutated bytes must fail");

    assert!(
        matches!(err, VerificationError::ArtifactHashMismatch { .. }),
        "ATC-SIG-3: expected ArtifactHashMismatch, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// ATC-SIG-4
// ---------------------------------------------------------------------------

/// §16 ATC-SIG-4 — Mutated signature bytes yield BadSignature.
///
/// GIVEN signed artifact A,
/// WHEN one byte of bundle.signature is flipped AND verify_artifact(A, bundle', keyring) runs,
/// THEN Err(VerificationError::BadSignature) is returned.
#[test]
fn atc_sig_4_mutated_signature_bad_signature() {
    let kp = IdentityKeyPair::generate();
    let artifact = b"atc-sig-4 correct artifact bytes";
    let mut bundle = sign_artifact(artifact, &kp);

    // Flip first byte of the 64-byte Ed25519 signature.
    bundle.signature[0] ^= 0xff;

    let kr = keyring_with(&kp);
    let err = verify_artifact(artifact, &bundle, &kr)
        .expect_err("ATC-SIG-4: verification with corrupted signature must fail");

    assert!(
        matches!(err, VerificationError::BadSignature),
        "ATC-SIG-4: expected BadSignature, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// ATC-SIG-5
// ---------------------------------------------------------------------------

/// §16 ATC-SIG-5 — Unknown algorithm field yields UnsupportedAlgorithm.
///
/// GIVEN a SignatureBundle with algorithm = "rsa-pkcs1v15" (not "ed25519"),
/// WHEN verify_artifact runs,
/// THEN Err(VerificationError::UnsupportedAlgorithm(_)) is returned.
#[test]
fn atc_sig_5_unsupported_algorithm_rejected() {
    let kp = IdentityKeyPair::generate();
    let artifact = b"atc-sig-5 artifact";
    let mut bundle = sign_artifact(artifact, &kp);

    // Tamper: advertise a different algorithm so the algorithm-check branch fires
    // before the publisher-lookup branch.
    bundle.algorithm = "rsa-pkcs1v15".to_owned();

    let kr = keyring_with(&kp);
    let err = verify_artifact(artifact, &bundle, &kr)
        .expect_err("ATC-SIG-5: unsupported algorithm must be rejected");

    assert!(
        matches!(err, VerificationError::UnsupportedAlgorithm(ref alg) if alg == "rsa-pkcs1v15"),
        "ATC-SIG-5: expected UnsupportedAlgorithm(\"rsa-pkcs1v15\"), got: {err}"
    );
}

// ---------------------------------------------------------------------------
// ATC-REP-1
// ---------------------------------------------------------------------------

/// §16 ATC-REP-1 — Ed25519 signatures over identical BLAKE3 hashes are deterministic.
///
/// GIVEN identical artifact bytes and the same keypair K,
/// WHEN sign_artifact runs twice,
/// THEN bundle_a.signature == bundle_b.signature (Ed25519 is deterministic per RFC 8032)
/// AND bundle_a.artifact_blake3 == bundle_b.artifact_blake3
/// AND bundles MAY differ in created_at (wall-clock timestamp).
///
/// Note: RFC 8032 / dalek Ed25519 is deterministic — same key + same message
/// always produces the same 64-byte signature. The only non-deterministic field
/// is `created_at` (Unix seconds), so two back-to-back calls within the same
/// second produce completely identical bundles; calls across a second boundary
/// will differ only there.
#[test]
fn atc_rep_1_signatures_are_deterministic() {
    let kp = IdentityKeyPair::generate();
    let artifact = b"atc-rep-1 determinism probe";

    let bundle_a = sign_artifact(artifact, &kp);
    let bundle_b = sign_artifact(artifact, &kp);

    assert_eq!(
        bundle_a.signature, bundle_b.signature,
        "ATC-REP-1: Ed25519 signatures must be deterministic for identical inputs"
    );
    assert_eq!(
        bundle_a.artifact_blake3, bundle_b.artifact_blake3,
        "ATC-REP-1: BLAKE3 hash of identical bytes must be identical"
    );
    assert_eq!(
        bundle_a.publisher_fingerprint, bundle_b.publisher_fingerprint,
        "ATC-REP-1: publisher fingerprint must be stable across calls"
    );
    // Verify created_at is the ONLY field that could differ (don't assert equality
    // because a second boundary may fall between the two calls).
    // We do assert it is a plausible Unix timestamp (> 2024-01-01).
    assert!(
        bundle_a.created_at > 1_700_000_000,
        "ATC-REP-1: created_at must be a plausible Unix timestamp"
    );
}
