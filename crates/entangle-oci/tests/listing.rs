//! ATC-MIR-2: signed mirror listings and their recorded verification.

mod common;

use common::*;
use entangle_oci::testing::{MockOptions, MockRegistry};
use entangle_oci::*;

const NOW: u64 = 1_800_000_000;

async fn setup() -> (MockRegistry, OciClient, Reference) {
    let mock = MockRegistry::start(MockOptions::default()).await;
    let pkg = signed_package(&keypair(1), "tool", &wasm_bytes(200));
    seed_artifact(&mock, "mirror/tool", "1.0.0", &pkg);
    seed_artifact(
        &mock,
        "mirror/tool",
        "1.1.0",
        &signed_package(&keypair(1), "tool", &wasm_bytes(300)),
    );
    let c = client(&mock);
    let r = reference(&mock, "mirror/tool:1.0.0");
    (mock, c, r)
}

fn mirror_keys(kp: &entangle_signing::IdentityKeyPair) -> MirrorKeyring {
    let mut k = MirrorKeyring::new();
    k.add_public_key(&kp.public(), "mirror");
    k
}

fn opts() -> ListOptions {
    ListOptions { now: Some(NOW) }
}

/// Craft a listing artifact by hand (tamper / unsigned / foreign-signed cases).
fn put_listing(mock: &MockRegistry, repo: &str, listing: &[u8], sig: Option<&[u8]>) {
    let empty = mock.put_blob(b"{}");
    let mut layers = vec![(LAYER_TYPE_LISTING, listing)];
    if let Some(s) = sig {
        layers.push((LAYER_TYPE_LISTING_SIG, s));
    }
    let layers: Vec<Descriptor> = layers
        .into_iter()
        .map(|(mt, b)| Descriptor {
            media_type: mt.into(),
            digest: mock.put_blob(b).parse().unwrap(),
            size: b.len() as u64,
            artifact_type: None,
            annotations: None,
        })
        .collect();
    let m = ImageManifest {
        schema_version: 2,
        media_type: MEDIA_TYPE_MANIFEST.into(),
        artifact_type: Some(ARTIFACT_TYPE_LISTING.into()),
        config: Descriptor {
            media_type: MEDIA_TYPE_EMPTY.into(),
            digest: empty.parse().unwrap(),
            size: 2,
            artifact_type: None,
            annotations: None,
        },
        layers,
        annotations: None,
    };
    mock.put_manifest(
        repo,
        LISTING_TAG,
        MEDIA_TYPE_MANIFEST,
        &serde_json::to_vec(&m).unwrap(),
    );
}

fn listing_for(mock: &MockRegistry, repo: &str) -> MirrorListing {
    let mut tags = std::collections::BTreeMap::new();
    for t in ["1.0.0", "1.1.0"] {
        let d = mock
            .manifest_bytes(repo, t)
            .map(|b| Digest::of(&b))
            .unwrap();
        tags.insert(t.to_owned(), d);
    }
    MirrorListing {
        version: 1,
        repository: repo.to_owned(),
        tags,
        generated_at: NOW - 100,
        expires_at: NOW + 3600,
    }
}

/// ATC-MIR-2. GIVEN a listing served by a mirror with a valid mirror-listing
/// signature, WHEN `list_tags()` is called, THEN it returns the listing AND
/// records the signature verification result.
#[tokio::test]
async fn atc_mir_2_mirror_listing_verified() {
    let (mock, c, r) = setup().await;
    let mirror = keypair(50);
    let listing = build_listing(&c, &r, 3600, Some(NOW - 10)).await.unwrap();
    publish_listing(&c, &r, &listing, &mirror).await.unwrap();

    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &opts())
        .await
        .unwrap();
    assert_eq!(
        tl.verification,
        ListingVerification::Verified {
            key_fingerprint: mirror.fingerprint_hex()
        }
    );
    assert_eq!(tl.listing.as_ref(), Some(&listing));
    let names: Vec<_> = tl.tags.keys().cloned().collect();
    assert_eq!(
        names,
        ["1.0.0", "1.1.0"],
        "listing tag itself is not listed"
    );
    for (tag, digest) in &tl.tags {
        let real = Digest::of(&mock.manifest_bytes("mirror/tool", tag).unwrap());
        assert_eq!(
            digest.as_ref(),
            Some(&real),
            "digest for {tag} comes from the signed listing"
        );
    }
}

#[tokio::test]
async fn atc_mir_2_no_listing_or_missing_signature_is_unsigned() {
    let (mock, c, r) = setup().await;
    let mirror = keypair(50);
    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &opts())
        .await
        .unwrap();
    assert_eq!(tl.verification, ListingVerification::Unsigned);
    assert!(tl.listing.is_none());
    assert_eq!(tl.registry_tags.len(), 2);
    assert!(
        tl.tags.values().all(|d| d.is_none()),
        "unauthenticated tags carry no digests"
    );

    let l = serde_json::to_vec(&listing_for(&mock, "mirror/tool")).unwrap();
    put_listing(&mock, "mirror/tool", &l, None);
    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &opts())
        .await
        .unwrap();
    assert_eq!(tl.verification, ListingVerification::Unsigned);
    assert!(tl.tags.values().all(|d| d.is_none()));
}

#[tokio::test]
async fn atc_mir_2_expired_listing_is_flagged_and_not_used_for_digests() {
    let (mock, c, r) = setup().await;
    let mirror = keypair(50);
    let mut l = listing_for(&mock, "mirror/tool");
    l.expires_at = NOW - 1;
    l.generated_at = NOW - 7200;
    publish_listing(&c, &r, &l, &mirror).await.unwrap();

    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &opts())
        .await
        .unwrap();
    assert_eq!(tl.verification, ListingVerification::Expired);
    assert!(tl.tags.values().all(|d| d.is_none()));
    // The same listing is fine before it expires.
    let early = ListOptions {
        now: Some(NOW - 3600),
    };
    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &early)
        .await
        .unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Verified { .. }
    ));
}

#[tokio::test]
async fn atc_mir_2_tampered_listing_is_invalid_even_if_also_expired() {
    let (mock, c, r) = setup().await;
    let mirror = keypair(50);
    let l = listing_for(&mock, "mirror/tool");
    let (bytes, sig) = sign_listing(&l, &mirror).unwrap();

    // Point a tag at a different digest after signing.
    let mut evil = l.clone();
    evil.tags
        .insert("1.0.0".into(), Digest::of(b"something else"));
    let evil_bytes = serde_json::to_vec(&evil).unwrap();
    assert_ne!(bytes, evil_bytes);
    put_listing(&mock, "mirror/tool", &evil_bytes, Some(&sig));

    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &opts())
        .await
        .unwrap();
    assert!(
        matches!(&tl.verification, ListingVerification::Invalid { reason } if reason.contains("does not verify")),
        "{:?}",
        tl.verification
    );
    assert!(tl.listing.is_none());
    assert!(tl.tags.values().all(|d| d.is_none()));

    // Tampered AND past its expiry: still Invalid (signature is checked first).
    let late = ListOptions {
        now: Some(NOW + 10 * 3600),
    };
    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &late)
        .await
        .unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Invalid { .. }
    ));

    // Garbage signature document.
    put_listing(&mock, "mirror/tool", &bytes, Some(b"not json"));
    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &opts())
        .await
        .unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Invalid { .. }
    ));
}

#[tokio::test]
async fn atc_mir_2_listing_signed_by_a_publisher_key_is_invalid() {
    let (mock, c, r) = setup().await;
    let publisher = keypair(1); // the key that signs the plugins, trusted as publisher
    let mirror = keypair(50);
    let l = listing_for(&mock, "mirror/tool");
    publish_listing(&c, &r, &l, &publisher).await.unwrap();

    // Publisher key is in the *publisher* keyring, which list_tags never sees;
    // the mirror keyring has only the mirror key.
    let _publisher_ring = keyring_with(&[&publisher]);
    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &opts())
        .await
        .unwrap();
    match &tl.verification {
        ListingVerification::Invalid { reason } => {
            assert!(reason.contains("not in the mirror keyring"), "{reason}");
            assert!(reason.contains(&publisher.fingerprint_hex()));
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert!(tl.tags.values().all(|d| d.is_none()));

    // An empty mirror keyring rejects even a legitimately signed listing.
    publish_listing(&c, &r, &l, &mirror).await.unwrap();
    let tl = list_tags(&c, &r, &MirrorKeyring::new(), &opts())
        .await
        .unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Invalid { .. }
    ));
}

#[tokio::test]
async fn atc_mir_2_listing_for_another_repository_is_invalid() {
    let (mock, c, r) = setup().await;
    let mirror = keypair(50);
    let mut l = listing_for(&mock, "mirror/tool");
    l.repository = "mirror/other".into();
    publish_listing(&c, &r, &l, &mirror).await.unwrap();
    let tl = list_tags(&c, &r, &mirror_keys(&mirror), &opts())
        .await
        .unwrap();
    assert!(
        matches!(&tl.verification, ListingVerification::Invalid { reason } if reason.contains("not \"mirror/tool\"")),
        "{:?}",
        tl.verification
    );
}

#[tokio::test]
async fn atc_mir_2_listing_artifact_of_the_wrong_type_is_invalid() {
    let (mock, c, r) = setup().await;
    // A plugin artifact parked at the listing tag.
    let pkg = signed_package(&keypair(1), "tool", &wasm_bytes(50));
    seed_artifact(&mock, "mirror/tool", LISTING_TAG, &pkg);
    let tl = list_tags(&c, &r, &mirror_keys(&keypair(50)), &opts())
        .await
        .unwrap();
    assert!(
        matches!(tl.verification, ListingVerification::Invalid { .. }),
        "{:?}",
        tl.verification
    );
}

#[test]
fn mirror_keyring_round_trips_through_its_own_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("mirror-keys.toml");
    let mirror = keypair(50);
    let k = mirror_keys(&mirror);
    k.save(&p).unwrap();
    let back = MirrorKeyring::load(&p).unwrap();
    assert!(back.lookup(&mirror.fingerprint()).is_some());
    assert!(MirrorKeyring::load(&dir.path().join("absent.toml"))
        .unwrap()
        .entries()
        .next()
        .is_none());
}
