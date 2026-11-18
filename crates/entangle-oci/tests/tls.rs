//! Real TLS between the client and an in-process server.
//!
//! The mock registry presents a `localhost` certificate issued by a CA that
//! is generated in memory for the test. The client is given that CA as an
//! extra trust anchor through the `testing`-feature-only `test_roots` field;
//! certificate verification is otherwise exactly the production code path
//! (rustls + webpki: chain, validity, host name). There is no option that
//! turns verification off, and the tests below show the handshake failing
//! when the anchor is missing or the name does not match.

mod common;

use common::*;
use entangle_oci::testing::{MockOptions, MockRegistry, TestCa};
use entangle_oci::*;

async fn tls_mock() -> (MockRegistry, TestCa) {
    let ca = TestCa::generate();
    let mock = MockRegistry::start(MockOptions {
        tls: Some(ca.clone()),
        ..MockOptions::default()
    })
    .await;
    (mock, ca)
}

fn fast(mut cfg: ClientConfig) -> ClientConfig {
    cfg.retry.base_delay = std::time::Duration::from_millis(1);
    cfg.retry.max_delay = std::time::Duration::from_millis(5);
    cfg.timeout = std::time::Duration::from_secs(10);
    cfg
}

fn trusting(ca: &TestCa) -> ClientConfig {
    fast(ClientConfig {
        test_roots: vec![ca.root()],
        ..ClientConfig::default()
    })
}

/// The OCI client completes a real TLS 1.3/1.2 handshake with the registry,
/// pulls an artifact over it, and the package verifies: the whole pull path
/// (manifest, blob, digest checks) runs through rustls.
#[tokio::test]
async fn oci_pull_over_a_real_tls_handshake() {
    let (mock, ca) = tls_mock().await;
    let publisher = keypair(1);
    let pkg = signed_package(&publisher, "tool", &wasm_bytes(5000));
    seed_artifact(&mock, "acme/tool", "1.0.0", &pkg);

    assert!(mock.origin().starts_with("https://localhost:"));
    let client = OciClient::with_base_url(&mock.origin(), trusting(&ca)).unwrap();
    assert_eq!(client.base_url().scheme(), "https");
    let reference = Reference::parse("oci://registry.invalid/acme/tool:1.0.0").unwrap();
    let pulled = pull_artifact(&client, &reference).await.unwrap();
    assert_eq!(pulled.package, pkg);
    let verified = verify_package(&pulled.package, &keyring_with(&[&publisher])).unwrap();
    assert!(verified.plugin_id.ends_with("/tool@0.1.0"));
    // The requests really arrived through the TLS listener.
    assert!(mock
        .requests_to("registry")
        .iter()
        .any(|r| r.path.contains("/v2/acme/tool/manifests/1.0.0")));

    // Pushing and listing work over the same transport.
    let mirror = keypair(50);
    let mut keys = MirrorKeyring::new();
    keys.add_public_key(&mirror.public(), "mirror");
    let listing = build_listing(&client, &reference, 3600, None)
        .await
        .unwrap();
    publish_listing(&client, &reference, &listing, &mirror)
        .await
        .unwrap();
    let tl = list_tags(&client, &reference, &keys, &ListOptions::default())
        .await
        .unwrap();
    assert!(
        matches!(tl.verification, ListingVerification::Verified { .. }),
        "{:?}",
        tl.verification
    );
}

/// Without the test CA as a trust anchor the handshake is refused: the
/// production trust store does not know the throw-away CA, and nothing is
/// fetched.
#[tokio::test]
async fn an_untrusted_server_certificate_fails_the_handshake() {
    let (mock, _ca) = tls_mock().await;
    seed_artifact(
        &mock,
        "acme/tool",
        "1.0.0",
        &signed_package(&keypair(1), "tool", &wasm_bytes(100)),
    );
    let client = OciClient::with_base_url(&mock.origin(), fast(ClientConfig::default())).unwrap();
    let reference = Reference::parse("oci://registry.invalid/acme/tool:1.0.0").unwrap();
    let e = pull_artifact(&client, &reference).await.unwrap_err();
    assert!(matches!(e, OciError::Transport { .. }), "{e}");
    let text = e.to_string();
    assert!(text.starts_with("ENTANGLE-E0802"), "{text}");
    assert!(text.contains("TLS"), "{text}");
    assert!(
        mock.requests().is_empty(),
        "no HTTP request may be sent before the server is authenticated"
    );

    // A different CA is no better than none.
    let other = TestCa::generate();
    let client = OciClient::with_base_url(&mock.origin(), trusting(&other)).unwrap();
    let e = pull_artifact(&client, &reference).await.unwrap_err();
    assert!(e.to_string().contains("TLS"), "{e}");
    assert!(mock.requests().is_empty());
}

/// Trusting the CA is not enough: the certificate must be for the name that
/// was dialled. The test certificate covers `localhost` only, so the same
/// server reached as `127.0.0.1` is refused.
#[tokio::test]
async fn a_certificate_for_another_name_is_refused() {
    let (mock, ca) = tls_mock().await;
    let by_ip = mock.origin().replace("localhost", "127.0.0.1");
    let client = OciClient::with_base_url(&by_ip, trusting(&ca)).unwrap();
    let reference = Reference::parse("oci://registry.invalid/acme/tool:1.0.0").unwrap();
    let e = pull_artifact(&client, &reference).await.unwrap_err();
    assert!(matches!(e, OciError::Transport { .. }), "{e}");
    assert!(e.to_string().contains("TLS"), "{e}");
    assert!(mock.requests().is_empty());
}

/// A plain-HTTP client pointed at the TLS port gets nowhere, and an HTTPS
/// response is never followed down to plain HTTP.
#[tokio::test]
async fn https_is_not_downgraded_by_a_redirect() {
    let (mock, ca) = tls_mock().await;
    let plain = MockRegistry::start(MockOptions::default()).await;
    let pkg = signed_package(&keypair(1), "tool", &wasm_bytes(300));
    let manifest_digest = seed_artifact(&mock, "acme/tool", "1.0.0", &pkg);
    seed_artifact(&plain, "acme/tool", "1.0.0", &pkg);
    let _ = manifest_digest;
    // The TLS registry redirects the blob to a plain-HTTP loopback server.
    let layer = format!("sha256:{}", {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&pkg))
    });
    mock.redirect_blob_to(
        &layer,
        &format!("http://{}/v2/acme/tool/blobs/{layer}", plain.registry()),
    );
    let client = OciClient::with_base_url(&mock.origin(), trusting(&ca)).unwrap();
    let reference = Reference::parse("oci://registry.invalid/acme/tool:1.0.0").unwrap();
    let e = pull_artifact(&client, &reference).await.unwrap_err();
    assert!(matches!(e, OciError::Redirect(_)), "{e}");
    assert!(e.to_string().starts_with("ENTANGLE-E0810"), "{e}");
    assert!(
        plain.requests().is_empty(),
        "the cleartext server must not be contacted"
    );
}

/// A mirror mounted under a path prefix (`https://host/oci`).
#[tokio::test]
async fn a_registry_under_a_path_prefix_is_reachable_through_with_base_url() {
    let ca = TestCa::generate();
    let mock = MockRegistry::start(MockOptions {
        tls: Some(ca.clone()),
        path_prefix: Some("/oci".into()),
        ..MockOptions::default()
    })
    .await;
    let pkg = signed_package(&keypair(1), "tool", &wasm_bytes(300));
    seed_artifact(&mock, "acme/tool", "1.0.0", &pkg);
    let reference = Reference::parse("oci://registry.invalid/acme/tool:1.0.0").unwrap();

    let client =
        OciClient::with_base_url(&format!("{}/oci", mock.origin()), trusting(&ca)).unwrap();
    assert_eq!(
        pull_artifact(&client, &reference).await.unwrap().package,
        pkg
    );
    assert!(client
        .listing_scope("acme/tool")
        .ends_with("/oci/acme/tool"));

    // Without the prefix the registry API is not there.
    let bare = OciClient::with_base_url(&mock.origin(), trusting(&ca)).unwrap();
    let e = pull_artifact(&bare, &reference).await.unwrap_err();
    assert!(matches!(e, OciError::Status { status: 404, .. }), "{e}");
}

#[test]
fn mirror_base_urls_are_vetted() {
    let cfg = ClientConfig::default;
    assert!(OciClient::with_base_url("https://mirror.example.org", cfg()).is_ok());
    assert!(OciClient::with_base_url("https://mirror.example.org/oci/", cfg()).is_ok());
    assert!(OciClient::with_base_url("http://127.0.0.1:5000", cfg()).is_ok());
    for (bad, code) in [
        ("http://mirror.example.org", "ENTANGLE-E0825"),
        ("ftp://mirror.example.org", "ENTANGLE-E0825"),
        ("https://user:secret@mirror.example.org", "ENTANGLE-E0825"),
        ("https://mirror.example.org/oci?x=1", "ENTANGLE-E0825"),
        ("mirror.example.org", "ENTANGLE-E0825"),
    ] {
        let e = OciClient::with_base_url(bad, cfg())
            .err()
            .expect(bad)
            .to_string();
        assert!(e.starts_with(code), "{bad}: {e}");
        assert!(!e.contains("secret"), "{e}");
        // No hint at a flag `entangle mirror set` does not have.
        assert!(!e.contains("--insecure-registry"), "{bad}: {e}");
    }
}
