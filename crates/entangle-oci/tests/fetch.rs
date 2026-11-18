//! Plain-HTTPS downloads (spec §3.6 path B): `fetch_url` and the detached
//! archive signature, against an in-process web server with a real TLS
//! handshake (test CA injected through the `testing`-only `test_roots`).

mod common;

use common::*;
use entangle_oci::testing::{MockOptions, MockRegistry, TestCa};
use entangle_oci::*;
use url::Url;

async fn tls_server() -> (MockRegistry, FetchOptions) {
    let ca = TestCa::generate();
    let mock = MockRegistry::start(MockOptions {
        tls: Some(ca.clone()),
        ..MockOptions::default()
    })
    .await;
    let opts = FetchOptions {
        test_roots: vec![ca.root()],
        timeout: std::time::Duration::from_secs(10),
        ..FetchOptions::default()
    };
    (mock, opts)
}

fn url(mock: &MockRegistry, path: &str) -> Url {
    Url::parse(&format!("{}{path}", mock.origin())).unwrap()
}

/// The happy path, as an installer runs it: fetch the signature, fetch the
/// archive, check the detached signature on the raw bytes, and only then
/// open the package.
#[tokio::test]
async fn archive_and_detached_signature_are_fetched_over_tls_and_verify() {
    let (mock, opts) = tls_server().await;
    let publisher = keypair(1);
    let pkg = signed_package(&publisher, "tool", &wasm_bytes(4000));
    let sig = sign_archive(&pkg, &publisher).unwrap();
    mock.put_file("/dl/tool-0.1.0.tar.zst", &pkg);
    mock.put_file("/dl/tool-0.1.0.tar.zst.sig", &sig);

    let u = url(&mock, "/dl/tool-0.1.0.tar.zst");
    assert_eq!(u.scheme(), "https");
    let got_sig = fetch_url(&signature_url(&u), "detached signature", &opts)
        .await
        .unwrap();
    let got = fetch_url(&u, "package archive", &opts).await.unwrap();
    assert_eq!(got, pkg);
    let ring = keyring_with(&[&publisher]);
    let signer = verify_archive_signature(&got, &got_sig, &ring).unwrap();
    assert_eq!(signer, publisher.fingerprint_hex());
    assert_eq!(
        verify_package(&got, &ring).unwrap().signer_fingerprint,
        signer
    );
    // No credentials were sent.
    assert!(mock.requests().iter().all(|r| r.authorization.is_none()));
}

#[tokio::test]
async fn an_untrusted_certificate_is_refused_before_any_request() {
    let (mock, _) = tls_server().await;
    mock.put_file("/x.tar.zst", b"data");
    let opts = FetchOptions {
        timeout: std::time::Duration::from_secs(10),
        ..FetchOptions::default()
    };
    let e = fetch_url(&url(&mock, "/x.tar.zst"), "package archive", &opts)
        .await
        .unwrap_err();
    assert!(e.to_string().starts_with("ENTANGLE-E0802"), "{e}");
    assert!(mock.requests().is_empty());
}

/// A redirect may change host or path, never the scheme.
#[tokio::test]
async fn redirects_are_followed_only_within_the_same_scheme() {
    let (mock, opts) = tls_server().await;
    let plain = MockRegistry::start(MockOptions::default()).await;
    mock.put_file("/real.tar.zst", b"the bytes");
    plain.put_file("/real.tar.zst", b"cleartext bytes");

    // https -> https (same server, another path): followed.
    mock.redirect_file("/latest.tar.zst", "/real.tar.zst");
    let got = fetch_url(&url(&mock, "/latest.tar.zst"), "package archive", &opts)
        .await
        .unwrap();
    assert_eq!(got, b"the bytes");

    // https -> http: refused, and the cleartext server is never contacted.
    mock.redirect_file(
        "/downgrade.tar.zst",
        &format!("{}/real.tar.zst", plain.origin()),
    );
    let e = fetch_url(&url(&mock, "/downgrade.tar.zst"), "package archive", &opts)
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::Redirect(_)), "{e}");
    assert!(e.to_string().contains("may not change the scheme"), "{e}");
    assert!(plain.requests().is_empty());

    // http (loopback) -> https: refused as well.
    plain.redirect_file("/up.tar.zst", &format!("{}/real.tar.zst", mock.origin()));
    let before = mock.requests().len();
    let e = fetch_url(&url(&plain, "/up.tar.zst"), "package archive", &opts)
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::Redirect(_)), "{e}");
    assert_eq!(mock.requests().len(), before);

    // A redirect loop ends.
    mock.redirect_file("/loop.tar.zst", "/loop.tar.zst");
    let e = fetch_url(&url(&mock, "/loop.tar.zst"), "package archive", &opts)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("redirects"), "{e}");
}

#[tokio::test]
async fn the_size_cap_applies_to_announced_and_to_streamed_bodies() {
    let (mock, mut opts) = tls_server().await;
    opts.max_bytes = 100_000;

    // Announced: refused from the header, nothing is read.
    mock.claim_file_length("/big.tar.zst", 50_000_000);
    let e = fetch_url(&url(&mock, "/big.tar.zst"), "package archive", &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            OciError::TooLarge {
                size: 50_000_000,
                limit: 100_000,
                ..
            }
        ),
        "{e}"
    );

    // Not announced (chunked): cut off shortly after the cap, long before
    // the server is done.
    mock.serve_endless_file("/endless.tar.zst", 64 * 1024 * 1024);
    let e = fetch_url(&url(&mock, "/endless.tar.zst"), "package archive", &opts)
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::TooLarge { .. }), "{e}");
    assert!(e.to_string().starts_with("ENTANGLE-E0808"), "{e}");

    // Exactly at the cap is fine.
    mock.put_file("/fits.tar.zst", &vec![7u8; 100_000]);
    assert_eq!(
        fetch_url(&url(&mock, "/fits.tar.zst"), "package archive", &opts)
            .await
            .unwrap()
            .len(),
        100_000
    );
}

#[tokio::test]
async fn a_missing_file_is_a_status_error_and_plain_http_is_loopback_only() {
    let (mock, opts) = tls_server().await;
    let e = fetch_url(
        &url(&mock, "/absent.tar.zst.sig"),
        "detached signature",
        &opts,
    )
    .await
    .unwrap_err();
    assert!(matches!(e, OciError::Status { status: 404, .. }), "{e}");

    // Loopback plain HTTP works (that is what local test servers are).
    let plain = MockRegistry::start(MockOptions::default()).await;
    plain.put_file("/x.tar.zst", b"ok");
    assert_eq!(
        fetch_url(&url(&plain, "/x.tar.zst"), "package archive", &opts)
            .await
            .unwrap(),
        b"ok"
    );
    // Anything else in the clear is refused without connecting.
    let e = fetch_url(
        &Url::parse("http://203.0.113.9/x.tar.zst").unwrap(),
        "package archive",
        &opts,
    )
    .await
    .unwrap_err();
    assert!(e.to_string().starts_with("ENTANGLE-E0822"), "{e}");
}
