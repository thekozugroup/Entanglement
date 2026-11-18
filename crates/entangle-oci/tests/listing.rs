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
    ListOptions {
        now: Some(NOW),
        ..ListOptions::default()
    }
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
        ..ListOptions::default()
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
        ..ListOptions::default()
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

// ---------------------------------------------------------------------------
// Rollback protection
// ---------------------------------------------------------------------------

fn with_state(state: &ListingState) -> ListOptions {
    ListOptions {
        now: Some(NOW),
        state: Some(state.clone()),
        ..ListOptions::default()
    }
}

/// Two correctly signed, unexpired listings: once the newer one has been
/// seen, the older one is refused although its signature and expiry are
/// fine, its digests are not used, and the record is unchanged.
#[tokio::test]
async fn an_older_signed_listing_is_refused_once_a_newer_one_was_seen() {
    let (mock, c, r) = setup().await;
    let mirror = keypair(50);
    let keys = mirror_keys(&mirror);
    let dir = tempfile::tempdir().unwrap();
    let state = ListingState::at(dir.path().join("mirror-listing-state.toml"));
    let scope = c.listing_scope("mirror/tool");

    let mut old = listing_for(&mock, "mirror/tool");
    old.generated_at = NOW - 5000;
    old.tags.remove("1.1.0"); // the old listing predates 1.1.0
    let mut new = listing_for(&mock, "mirror/tool");
    new.generated_at = NOW - 100;

    // First the old one: accepted and recorded (nothing newer is known).
    publish_listing(&c, &r, &old, &mirror).await.unwrap();
    let tl = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Verified { .. }
    ));
    assert_eq!(
        state.newest(&scope).unwrap().unwrap().generated_at,
        NOW - 5000
    );

    // Then the new one: accepted, the record moves forward.
    publish_listing(&c, &r, &new, &mirror).await.unwrap();
    let tl = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Verified { .. }
    ));
    assert!(tl.tags.contains_key("1.1.0"));
    let seen = state.newest(&scope).unwrap().unwrap();
    assert_eq!(seen.generated_at, NOW - 100);
    assert_eq!(seen.key_fingerprint, mirror.fingerprint_hex());

    // The mirror (or someone in front of it) serves the old listing again.
    publish_listing(&c, &r, &old, &mirror).await.unwrap();
    let tl = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert_eq!(
        tl.verification,
        ListingVerification::RolledBack {
            newest_seen: NOW - 100,
            offered: NOW - 5000,
        }
    );
    let text = tl.verification.to_string();
    assert!(text.contains("ENTANGLE-E0820"), "{text}");
    // Its digests are not used; the unauthenticated tag names are shown instead.
    assert!(tl.tags.values().all(|d| d.is_none()));
    assert!(tl.tags.contains_key("1.1.0"), "{:?}", tl.tags);
    assert_eq!(
        state.newest(&scope).unwrap().unwrap().generated_at,
        NOW - 100
    );

    // Without a state file there is no memory, so the old listing verifies:
    // the protection is exactly the recorded state.
    let tl = list_tags(&c, &r, &keys, &opts()).await.unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Verified { .. }
    ));

    // The same newest listing again is fine (equal is not older).
    publish_listing(&c, &r, &new, &mirror).await.unwrap();
    let tl = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Verified { .. }
    ));
}

/// The operator's reset: `accept_older` takes the older listing and makes it
/// the new baseline; `forget` drops the record.
#[tokio::test]
async fn an_operator_can_accept_an_older_listing_or_forget_the_record() {
    let (mock, c, r) = setup().await;
    let mirror = keypair(50);
    let keys = mirror_keys(&mirror);
    let dir = tempfile::tempdir().unwrap();
    let state = ListingState::at(dir.path().join("state.toml"));
    let scope = c.listing_scope("mirror/tool");

    let mut new = listing_for(&mock, "mirror/tool");
    new.generated_at = NOW - 100;
    let mut old = new.clone();
    old.generated_at = NOW - 5000;
    publish_listing(&c, &r, &new, &mirror).await.unwrap();
    list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    publish_listing(&c, &r, &old, &mirror).await.unwrap();
    let refused = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert!(matches!(
        refused.verification,
        ListingVerification::RolledBack { .. }
    ));

    let accept = ListOptions {
        accept_older: true,
        ..with_state(&state)
    };
    let tl = list_tags(&c, &r, &keys, &accept).await.unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Verified { .. }
    ));
    assert_eq!(
        state.newest(&scope).unwrap().unwrap().generated_at,
        NOW - 5000
    );
    // From now on it verifies without the flag.
    let tl = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Verified { .. }
    ));

    assert!(state.forget(&scope).unwrap());
    assert_eq!(state.newest(&scope).unwrap(), None);
}

/// Only a listing that verified can move the baseline: a forged "newer"
/// listing (unknown key), an unsigned one and an expired one leave the
/// record alone, so nobody without a mirror key can lock a client out of
/// the real listing or lower the bar.
#[tokio::test]
async fn unverified_listings_never_touch_the_recorded_state() {
    let (mock, c, r) = setup().await;
    let (mirror, attacker) = (keypair(50), keypair(51));
    let keys = mirror_keys(&mirror);
    let dir = tempfile::tempdir().unwrap();
    let state = ListingState::at(dir.path().join("state.toml"));
    let scope = c.listing_scope("mirror/tool");

    let genuine = listing_for(&mock, "mirror/tool");
    publish_listing(&c, &r, &genuine, &mirror).await.unwrap();
    list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    let baseline = state.newest(&scope).unwrap().unwrap();

    // Far in the future, signed by a key that is not a mirror key.
    let mut forged = genuine.clone();
    forged.generated_at = NOW + 1_000_000;
    forged.expires_at = NOW + 2_000_000;
    publish_listing(&c, &r, &forged, &attacker).await.unwrap();
    let tl = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Invalid { .. }
    ));
    assert_eq!(state.newest(&scope).unwrap().unwrap(), baseline);

    // Unsigned.
    put_listing(
        &mock,
        "mirror/tool",
        &serde_json::to_vec(&forged).unwrap(),
        None,
    );
    let tl = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert_eq!(tl.verification, ListingVerification::Unsigned);
    assert_eq!(state.newest(&scope).unwrap().unwrap(), baseline);

    // Genuine but expired, and older: reported as expired, record untouched.
    let mut expired = genuine.clone();
    expired.generated_at = NOW - 9000;
    expired.expires_at = NOW - 1;
    publish_listing(&c, &r, &expired, &mirror).await.unwrap();
    let tl = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert_eq!(tl.verification, ListingVerification::Expired);
    assert_eq!(state.newest(&scope).unwrap().unwrap(), baseline);

    // The genuine listing still verifies afterwards.
    publish_listing(&c, &r, &genuine, &mirror).await.unwrap();
    let tl = list_tags(&c, &r, &keys, &with_state(&state)).await.unwrap();
    assert!(matches!(
        tl.verification,
        ListingVerification::Verified { .. }
    ));
}

/// A damaged state file fails the listing loudly instead of silently
/// dropping the protection.
#[tokio::test]
async fn a_damaged_state_file_fails_closed() {
    let (mock, c, r) = setup().await;
    let mirror = keypair(50);
    publish_listing(&c, &r, &listing_for(&mock, "mirror/tool"), &mirror)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    std::fs::write(&path, "this is not the state file").unwrap();
    let e = list_tags(
        &c,
        &r,
        &mirror_keys(&mirror),
        &with_state(&ListingState::at(&path)),
    )
    .await
    .unwrap_err();
    assert!(e.to_string().starts_with("ENTANGLE-E0821"), "{e}");
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
