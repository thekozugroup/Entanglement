//! ATC-MIR-1: a mirror/registry is a CDN for bytes, never a source of trust.

mod common;

use common::*;
use entangle_oci::testing::{MockAuth, MockOptions, MockRegistry};
use entangle_oci::*;
use entangle_signing::{verify_artifact, Keyring, SignatureBundle};

/// Pull from the mock and run the single trust decision.
async fn pull_and_verify(
    mock: &MockRegistry,
    repo_tag: &str,
    keyring: &Keyring,
) -> Result<VerifiedPackage> {
    let pulled = pull_artifact(&client(mock), &reference(mock, repo_tag)).await?;
    verify_package(&pulled.package, keyring)
}

/// ATC-MIR-1. GIVEN a plugin package served by a registry/mirror, WHEN it is
/// verified, THEN the decision depends on the bytes and the publisher keyring
/// only: a registry-served artifact with a wrong publisher signature is
/// rejected even though the registry is "trusted" (authenticated, token-
/// issuing, and holding a valid signed mirror listing), and a correctly signed
/// artifact is accepted from any registry.
#[tokio::test]
async fn atc_mir_1_no_mirror_in_artifact_trust() {
    // Structural: the verifier's whole input is (bytes, publisher keyring).
    // If anyone adds a registry/mirror parameter this stops compiling.
    let _: fn(&[u8], &Keyring) -> Result<VerifiedPackage> = verify_package;

    let publisher = keypair(10);
    let attacker = keypair(11);
    let mirror = keypair(12);
    let trusted = keyring_with(&[&publisher]);
    let wasm = wasm_bytes(4000);

    // A registry the operator has every reason to trust: authenticated, with a
    // properly signed mirror listing for the repository.
    let hostile = MockRegistry::start(MockOptions {
        auth: MockAuth::Bearer {
            token_requires_basic: None,
        },
        cdn: true,
        ..MockOptions::default()
    })
    .await;
    let mut mirror_keys = MirrorKeyring::new();
    mirror_keys.add_public_key(&mirror.public(), "the-mirror");

    // (1) Signed by an unknown key.
    seed_artifact(
        &hostile,
        "acme/tool",
        "evil",
        &signed_package(&attacker, "tool", &wasm),
    );
    // (2) Claims the trusted publisher's id with the publisher's fingerprint and
    // the correct artifact/manifest hashes, but the signature bytes are the
    // attacker's: only the signature check can reject it.
    let mut forged = signed_files(&publisher, "tool", &wasm);
    let attacker_sig = entangle_signing::sign_artifact(&wasm, &forged.manifest, &attacker);
    let mut bundle: SignatureBundle =
        toml::from_str(std::str::from_utf8(&forged.signature).unwrap()).unwrap();
    assert_ne!(bundle.signature, attacker_sig.signature);
    bundle.signature = attacker_sig.signature;
    forged.signature = toml::to_string(&toml::Value::try_from(&bundle).unwrap())
        .unwrap()
        .into_bytes();
    seed_artifact(&hostile, "acme/tool", "forged", &pack(&forged).unwrap());
    // (3) Signed by the *mirror's* key: the mirror can sign listings, never artifacts.
    seed_artifact(
        &hostile,
        "acme/tool",
        "mirror-signed",
        &signed_package(&mirror, "tool", &wasm),
    );
    // (4) The real thing.
    seed_artifact(
        &hostile,
        "acme/tool",
        "good",
        &signed_package(&publisher, "tool", &wasm),
    );

    // Publish a *valid* mirror-signed listing covering all of those tags.
    let c = client(&hostile);
    let r = reference(&hostile, "acme/tool:good");
    let listing = build_listing(&c, &r, 3600, None).await.unwrap();
    publish_listing(&c, &r, &listing, &mirror).await.unwrap();
    let tl = list_tags(&c, &r, &mirror_keys, &ListOptions::default())
        .await
        .unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Verified { .. }
    ));
    assert!(
        tl.tags.contains_key("evil"),
        "the listing vouches for the tags existing"
    );

    for bad in ["evil", "forged", "mirror-signed"] {
        let e = pull_and_verify(&hostile, &format!("acme/tool:{bad}"), &trusted)
            .await
            .expect_err(bad);
        assert!(matches!(e, OciError::Verification(_)), "{bad}: {e}");
        assert!(e.to_string().starts_with("ENTANGLE-E0814"), "{bad}: {e}");
    }
    // The forged one fails on the signature itself, not on a hash or a lookup.
    let e = pull_and_verify(&hostile, "acme/tool:forged", &trusted)
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            OciError::Verification(entangle_signing::VerificationError::BadSignature)
        ),
        "{e}"
    );

    // The good artifact is accepted from this registry...
    let v = pull_and_verify(&hostile, "acme/tool:good", &trusted)
        .await
        .unwrap();
    assert_eq!(v.signer_fingerprint, publisher.fingerprint_hex());

    // ...and from a completely different one (different port, auth mode,
    // anonymous, no listing at all): same bytes, same verdict.
    let other_reg = MockRegistry::start(MockOptions::default()).await;
    seed_artifact(
        &other_reg,
        "somewhere/else",
        "v1",
        &signed_package(&publisher, "tool", &wasm),
    );
    let v2 = pull_and_verify(&other_reg, "somewhere/else:v1", &trusted)
        .await
        .unwrap();
    assert_eq!(v2.plugin_id, v.plugin_id);
    assert_eq!(v2.signer_fingerprint, v.signer_fingerprint);

    // Trusting the registry harder changes nothing: an empty publisher keyring
    // rejects even the good artifact. Registry credentials, mirror keys and
    // listings are not inputs to this decision.
    let e = pull_and_verify(&hostile, "acme/tool:good", &Keyring::new())
        .await
        .unwrap_err();
    assert!(matches!(
        e,
        OciError::Verification(entangle_signing::VerificationError::UnknownPublisher)
    ));
}

/// The pulled-bytes path and the local-file path reach the same verdicts,
/// because the former is a thin wrapper over `verify_artifact`.
#[tokio::test]
async fn atc_mir_1_pulled_bytes_get_the_same_verdict_as_a_local_file() {
    let publisher = keypair(20);
    let attacker = keypair(21);
    let ring = keyring_with(&[&publisher]);

    for (signer, expect_ok) in [(&publisher, true), (&attacker, false)] {
        let files = signed_files(signer, "tool", &wasm_bytes(1500));

        // Local verdict: exactly what the kernel does with a directory.
        let sig_text = std::str::from_utf8(&files.signature).unwrap();
        let bundle: SignatureBundle = toml::from_str(sig_text).unwrap();
        let local = verify_artifact(&files.wasm, &files.manifest, &bundle, &ring).is_ok();

        // Registry verdict.
        let mock = MockRegistry::start(MockOptions::default()).await;
        seed_artifact(&mock, "r/t", "v", &pack(&files).unwrap());
        let remote = pull_and_verify(&mock, "r/t:v", &ring).await.is_ok();

        assert_eq!(local, expect_ok);
        assert_eq!(remote, local, "registry path and local path disagree");
    }
}

/// A key trusted only as a mirror key cannot validate an artifact, and a
/// listing signature cannot be replayed as an artifact signature.
#[test]
fn atc_mir_1_mirror_key_cannot_sign_artifacts() {
    let mirror = keypair(30);
    let mut mirror_keys = MirrorKeyring::new();
    mirror_keys.add_public_key(&mirror.public(), "m");

    // Publisher keyring does not contain it.
    let publishers = keyring_with(&[&keypair(31)]);
    assert!(mirror_keys.overlap_with(&publishers).is_empty());
    let pkg = signed_package(&mirror, "tool", &wasm_bytes(300));
    assert!(matches!(
        verify_package(&pkg, &publishers),
        Err(OciError::Verification(
            entangle_signing::VerificationError::UnknownPublisher
        ))
    ));

    // Even if an operator wrongly put the key in both rings, a signature made
    // for a listing is not an artifact signature: forge a package using the
    // listing signature bytes as the "artifact signature".
    let both = keyring_with(&[&mirror]);
    assert_eq!(
        mirror_keys.overlap_with(&both),
        vec![mirror.fingerprint_hex()]
    );
    let listing = MirrorListing {
        version: 1,
        repository: "r".into(),
        tags: Default::default(),
        generated_at: 1,
        expires_at: 2,
    };
    let (_, sig_json) = sign_listing(&listing, &mirror).unwrap();
    let lsig: ListingSignature = serde_json::from_slice(&sig_json).unwrap();
    let mut files = signed_files(&mirror, "tool", &wasm_bytes(300));
    let mut bundle: SignatureBundle =
        toml::from_str(std::str::from_utf8(&files.signature).unwrap()).unwrap();
    bundle.signature = entangle_signing::Signature::from_hex(&lsig.signature)
        .unwrap()
        .0;
    files.signature = toml::to_string(&bundle).unwrap().into_bytes();
    assert!(matches!(
        verify_package(&pack(&files).unwrap(), &both),
        Err(OciError::Verification(
            entangle_signing::VerificationError::BadSignature
        ))
    ));
}
