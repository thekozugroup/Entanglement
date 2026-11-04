//! Client behaviour against the in-process mock registry.

mod common;

use common::*;
use entangle_oci::testing::{MockAuth, MockOptions, MockRegistry};
use entangle_oci::*;

async fn plain() -> MockRegistry {
    MockRegistry::start(MockOptions::default()).await
}

fn code(e: &OciError) -> String {
    e.to_string().chars().take(14).collect()
}

#[tokio::test]
async fn pull_happy_path() {
    let mock = plain().await;
    let kp = keypair(1);
    let pkg = signed_package(&kp, "hello", &wasm_bytes(2000));
    let mdigest = seed_artifact(&mock, "acme/hello", "1.0.0", &pkg);

    let r = reference(&mock, "acme/hello:1.0.0");
    let pulled = pull_artifact(&client(&mock), &r).await.unwrap();
    assert_eq!(pulled.package, pkg);
    assert_eq!(pulled.manifest_digest.as_str(), mdigest);

    // By digest as well.
    let rd = reference(&mock, &format!("acme/hello@{mdigest}"));
    assert_eq!(
        pull_artifact(&client(&mock), &rd).await.unwrap().package,
        pkg
    );
}

#[tokio::test]
async fn digest_mismatch_is_rejected() {
    let mock = plain().await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(500));
    seed_artifact(&mock, "r/p", "t", &pkg);
    // Same length, different content: size passes, hash must not.
    let layer = format!("sha256:{}", hex::encode(sha2_of(&pkg)));
    let mut evil = pkg.clone();
    evil[10] ^= 0xFF;
    mock.tamper_blob(&layer, evil);

    let e = pull_artifact(&client(&mock), &reference(&mock, "r/p:t"))
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::DigestMismatch { .. }), "{e}");
    assert_eq!(code(&e), "ENTANGLE-E0807");
}

fn sha2_of(b: &[u8]) -> [u8; 32] {
    let d = Digest::of(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(d.hex()).unwrap());
    out
}

#[tokio::test]
async fn manifest_not_matching_its_digest_is_rejected() {
    let mock = plain().await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(100));
    let d = seed_artifact(&mock, "r/p", "t", &pkg);
    mock.corrupt_manifest("r/p", &d, MEDIA_TYPE_MANIFEST, b"{\"schemaVersion\":2}");
    let e = pull_artifact(&client(&mock), &reference(&mock, &format!("r/p@{d}")))
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::DigestMismatch { .. }), "{e}");
}

#[tokio::test]
async fn oversized_descriptor_is_rejected_before_any_blob_request() {
    let mock = plain().await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(5000));
    seed_artifact(&mock, "r/p", "t", &pkg);
    let cfg = ClientConfig {
        max_blob_bytes: 100,
        ..ClientConfig::default()
    };
    let e = pull_artifact(&client_with(&mock, cfg), &reference(&mock, "r/p:t"))
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::TooLarge { .. }), "{e}");
    assert_eq!(code(&e), "ENTANGLE-E0808");
    let blob_gets = mock
        .requests()
        .iter()
        .filter(|r| r.method == "GET" && r.path.contains("/blobs/"))
        .count();
    assert_eq!(
        blob_gets, 0,
        "no blob bytes may be requested once the descriptor is over the cap"
    );
}

#[tokio::test]
async fn lying_registry_streaming_too_much_is_cut_off() {
    let mock = plain().await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(300));
    seed_artifact(&mock, "r/p", "t", &pkg);
    let layer = Digest::of(&pkg);
    // Descriptor says ~400 bytes; the registry streams 512 MiB with no length.
    let total: u64 = 512 * 1024 * 1024;
    mock.serve_endless(layer.as_str(), total);

    let e = pull_artifact(&client(&mock), &reference(&mock, "r/p:t"))
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::SizeMismatch { .. }), "{e}");
    assert_eq!(code(&e), "ENTANGLE-E0809");
    assert!(
        mock.bytes_streamed() < total / 4,
        "client kept reading: {} of {total} bytes sent",
        mock.bytes_streamed()
    );
}

#[tokio::test]
async fn content_length_disagreeing_with_descriptor_is_rejected() {
    let mock = plain().await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(300));
    seed_artifact(&mock, "r/p", "t", &pkg);
    mock.tamper_blob(Digest::of(&pkg).as_str(), vec![7u8; pkg.len() + 50]);
    let e = pull_artifact(&client(&mock), &reference(&mock, "r/p:t"))
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::SizeMismatch { .. }), "{e}");
}

#[tokio::test]
async fn redirect_does_not_leak_authorization() {
    let mock = MockRegistry::start(MockOptions {
        auth: MockAuth::Basic {
            username: "alice".into(),
            password: "s3cret".into(),
        },
        cdn: true,
        tag_page_size: None,
    })
    .await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(3000));
    seed_artifact(&mock, "r/p", "t", &pkg);
    let cfg = ClientConfig {
        credential: Some(Credential::Basic {
            username: "alice".into(),
            password: Secret::new("s3cret"),
        }),
        ..ClientConfig::default()
    };
    let pulled = pull_artifact(&client_with(&mock, cfg), &reference(&mock, "r/p:t"))
        .await
        .unwrap();
    assert_eq!(pulled.package, pkg);

    let cdn = mock.requests_to("cdn");
    assert!(
        !cdn.is_empty(),
        "blob must have been fetched from the CDN listener"
    );
    assert!(
        cdn.iter().all(|r| r.authorization.is_none()),
        "Authorization leaked to the CDN: {cdn:?}"
    );
    let reg_auth = mock
        .requests_to("registry")
        .iter()
        .filter(|r| r.authorization.is_some())
        .count();
    assert!(
        reg_auth > 0,
        "registry requests should have been authenticated"
    );
}

#[tokio::test]
async fn bearer_token_flow_anonymous_and_credentialed() {
    // Anonymous token endpoint.
    let mock = MockRegistry::start(MockOptions {
        auth: MockAuth::Bearer {
            token_requires_basic: None,
        },
        ..MockOptions::default()
    })
    .await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(100));
    seed_artifact(&mock, "r/p", "t", &pkg);
    let pulled = pull_artifact(&client(&mock), &reference(&mock, "r/p:t"))
        .await
        .unwrap();
    assert_eq!(pulled.package, pkg);
    let reqs = mock.requests();
    assert!(
        reqs.iter().any(|r| r.path.starts_with("/token?")),
        "token endpoint not used"
    );
    assert!(
        reqs.iter().any(|r| r
            .authorization
            .as_deref()
            .is_some_and(|a| a.starts_with("Bearer tok-"))),
        "bearer token never presented"
    );

    // Token endpoint wants Basic credentials.
    let mock = MockRegistry::start(MockOptions {
        auth: MockAuth::Bearer {
            token_requires_basic: Some(("bob".into(), "pw".into())),
        },
        ..MockOptions::default()
    })
    .await;
    seed_artifact(&mock, "r/p", "t", &pkg);
    let e = pull_artifact(&client(&mock), &reference(&mock, "r/p:t"))
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::Auth { .. }), "{e}");
    assert_eq!(code(&e), "ENTANGLE-E0804");

    let cfg = ClientConfig {
        credential: Some(Credential::Basic {
            username: "bob".into(),
            password: Secret::new("pw"),
        }),
        ..ClientConfig::default()
    };
    let pulled = pull_artifact(&client_with(&mock, cfg), &reference(&mock, "r/p:t"))
        .await
        .unwrap();
    assert_eq!(pulled.package, pkg);
}

#[tokio::test]
async fn basic_challenge_without_credential_is_a_clear_error() {
    let mock = MockRegistry::start(MockOptions {
        auth: MockAuth::Basic {
            username: "a".into(),
            password: "b".into(),
        },
        ..MockOptions::default()
    })
    .await;
    let e = pull_artifact(&client(&mock), &reference(&mock, "r/p:t"))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("ENTANGLE_OCI_USERNAME"), "{e}");
}

#[tokio::test]
async fn wrong_media_types_are_rejected() {
    let mock = plain().await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(100));

    // 1. Docker schema-2 content type on the manifest.
    seed_artifact(&mock, "a/b", "t", &pkg);
    mock.override_manifest_content_type(
        "a/b",
        "application/vnd.docker.distribution.manifest.v2+json",
    );
    let e = pull_artifact(&client(&mock), &reference(&mock, "a/b:t"))
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::WrongMediaType { .. }), "{e}");

    // 2. Right manifest type, wrong artifactType (a mirror listing is not a plugin).
    let mock2 = plain().await;
    let layer = mock2.put_blob(&pkg);
    let empty = mock2.put_blob(b"{}");
    let m = |artifact: &str, layer_type: &str| {
        serde_json::to_vec(&ImageManifest {
            schema_version: 2,
            media_type: MEDIA_TYPE_MANIFEST.into(),
            artifact_type: Some(artifact.into()),
            config: Descriptor {
                media_type: MEDIA_TYPE_EMPTY.into(),
                digest: empty.parse().unwrap(),
                size: 2,
                artifact_type: None,
                annotations: None,
            },
            layers: vec![Descriptor {
                media_type: layer_type.into(),
                digest: layer.parse().unwrap(),
                size: pkg.len() as u64,
                artifact_type: None,
                annotations: None,
            }],
            annotations: None,
        })
        .unwrap()
    };
    mock2.put_manifest(
        "a/b",
        "wrongtype",
        MEDIA_TYPE_MANIFEST,
        &m("application/vnd.example.other", LAYER_TYPE_PLUGIN),
    );
    let e = pull_artifact(&client(&mock2), &reference(&mock2, "a/b:wrongtype"))
        .await
        .unwrap_err();
    assert!(
        matches!(e, OciError::WrongMediaType { ref what, .. } if what == "artifactType"),
        "{e}"
    );

    // 3. Right artifactType, wrong layer media type (e.g. a plain gzip tarball).
    mock2.put_manifest(
        "a/b",
        "wronglayer",
        MEDIA_TYPE_MANIFEST,
        &m(
            ARTIFACT_TYPE_PLUGIN,
            "application/vnd.oci.image.layer.v1.tar+gzip",
        ),
    );
    let e = pull_artifact(&client(&mock2), &reference(&mock2, "a/b:wronglayer"))
        .await
        .unwrap_err();
    assert!(
        matches!(e, OciError::WrongMediaType { ref what, .. } if what == "plugin layer"),
        "{e}"
    );
    assert_eq!(code(&e), "ENTANGLE-E0806");
}

#[tokio::test]
async fn publish_pull_round_trip_is_byte_identical_monolithic_and_chunked() {
    for (chunk, expect_patches) in [(64 * 1024 * 1024, false), (1000, true)] {
        let mock = MockRegistry::start(MockOptions {
            auth: MockAuth::Bearer {
                token_requires_basic: None,
            },
            ..MockOptions::default()
        })
        .await;
        let kp = keypair(9);
        let pkg = signed_package(&kp, "roundtrip", &wasm_bytes(20_000));
        let cfg = ClientConfig {
            chunk_size: chunk,
            ..ClientConfig::default()
        };
        let c = client_with(&mock, cfg);
        let r = reference(&mock, "acme/roundtrip:2.0.0");
        let pushed = push_artifact(&c, &r, &pkg).await.unwrap();

        let patches = mock
            .requests()
            .iter()
            .filter(|q| q.method == "PATCH")
            .count();
        assert_eq!(
            patches > 1,
            expect_patches,
            "chunk={chunk} patches={patches}"
        );

        let pulled = pull_artifact(&client(&mock), &r).await.unwrap();
        assert_eq!(
            pulled.package, pkg,
            "package bytes must survive publish->pull unchanged"
        );
        assert_eq!(pulled.manifest_digest, pushed.manifest_digest);
        assert_eq!(pulled.layer_digest, pushed.layer_digest);

        // Pullable by the returned digest reference too, and still verifies.
        let again = pull_artifact(&client(&mock), &pushed.by_digest)
            .await
            .unwrap();
        assert_eq!(again.package, pkg);
        let v = verify_package(&again.package, &keyring_with(&[&kp])).unwrap();
        assert_eq!(v.signer_fingerprint, kp.fingerprint_hex());

        // Re-publishing skips blobs the registry already has.
        let posts_before = mock
            .requests()
            .iter()
            .filter(|q| q.method == "POST")
            .count();
        push_artifact(&c, &r, &pkg).await.unwrap();
        let posts_after = mock
            .requests()
            .iter()
            .filter(|q| q.method == "POST")
            .count();
        assert_eq!(
            posts_before, posts_after,
            "existing blobs must not be re-uploaded"
        );
    }
}

#[tokio::test]
async fn publish_refuses_a_digest_reference_and_non_packages() {
    let mock = plain().await;
    let c = client(&mock);
    let pkg = signed_package(&keypair(1), "x", &wasm_bytes(10));
    let d = format!("oci://{}/a/b@sha256:{}", mock.registry(), "0".repeat(64));
    let e = push_artifact(&c, &Reference::parse(&d).unwrap(), &pkg)
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::Unsupported(_)), "{e}");
    let e = push_artifact(&c, &reference(&mock, "a/b:t"), b"junk")
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::InvalidPackage(_)), "{e}");
}

#[tokio::test]
async fn retries_429_and_5xx_with_backoff_but_not_404() {
    let mock = plain().await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(100));
    seed_artifact(&mock, "r/p", "t", &pkg);

    mock.fail_next("/manifests/t", &[503, 429, 500]);
    let pulled = pull_artifact(&client(&mock), &reference(&mock, "r/p:t"))
        .await
        .unwrap();
    assert_eq!(pulled.package, pkg);
    let manifest_gets = mock
        .requests()
        .iter()
        .filter(|r| r.path.contains("/manifests/t"))
        .count();
    assert_eq!(manifest_gets, 4);

    // Persistent failure gives up.
    mock.fail_next("/manifests/t", &[502; 4]);
    let e = pull_artifact(&client(&mock), &reference(&mock, "r/p:t"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            OciError::RetriesExhausted {
                status: 502,
                attempts: 4,
                ..
            }
        ),
        "{e}"
    );

    // 404 is final: exactly one request.
    let before = mock.requests().len();
    let e = pull_artifact(&client(&mock), &reference(&mock, "r/missing:t"))
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::Status { status: 404, .. }), "{e}");
    assert_eq!(mock.requests().len() - before, 1);
}

#[tokio::test]
async fn index_is_resolved_to_the_single_plugin_manifest() {
    let mock = plain().await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(100));
    let child = seed_artifact(&mock, "r/p", "child", &pkg);
    let idx = |artifact_type: &str| {
        format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"{MEDIA_TYPE_INDEX}\",\"manifests\":[\
             {{\"mediaType\":\"{MEDIA_TYPE_MANIFEST}\",\"digest\":\"{child}\",\"size\":1,\
             \"artifactType\":\"{artifact_type}\"}}]}}"
        )
    };
    mock.put_manifest(
        "r/p",
        "idx",
        MEDIA_TYPE_INDEX,
        idx(ARTIFACT_TYPE_PLUGIN).as_bytes(),
    );
    let pulled = pull_artifact(&client(&mock), &reference(&mock, "r/p:idx"))
        .await
        .unwrap();
    assert_eq!(pulled.package, pkg);

    mock.put_manifest(
        "r/p",
        "idx2",
        MEDIA_TYPE_INDEX,
        idx("application/other").as_bytes(),
    );
    let e = pull_artifact(&client(&mock), &reference(&mock, "r/p:idx2"))
        .await
        .unwrap_err();
    assert!(matches!(e, OciError::Unsupported(_)), "{e}");
}

#[tokio::test]
async fn tag_listing_follows_pagination() {
    let mock = MockRegistry::start(MockOptions {
        tag_page_size: Some(2),
        ..MockOptions::default()
    })
    .await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(10));
    for t in ["a", "b", "c", "d", "e"] {
        seed_artifact(&mock, "r/p", t, &pkg);
    }
    let mut tags = client(&mock).list_tag_names("r/p").await.unwrap();
    tags.sort();
    assert_eq!(tags, ["a", "b", "c", "d", "e"]);
}

#[tokio::test]
async fn env_credentials_for_another_registry_are_never_sent_and_do_not_break_anonymous_pulls() {
    // A public registry using the anonymous token flow.
    let mock = MockRegistry::start(MockOptions {
        auth: MockAuth::Bearer {
            token_requires_basic: None,
        },
        ..MockOptions::default()
    })
    .await;
    let pkg = signed_package(&keypair(1), "hello", &wasm_bytes(100));
    seed_artifact(&mock, "r/p", "t", &pkg);

    // CI exported a token for its internal registry, then installs from here.
    let env = |k: &str| match k {
        "ENTANGLE_OCI_TOKEN" => Some("internal-ci-token".to_owned()),
        "ENTANGLE_OCI_REGISTRY" => Some("registry.internal:5000".to_owned()),
        _ => None,
    };
    let credential = Credential::resolve_with(&mock.registry(), None, env).unwrap();
    let cfg = ClientConfig {
        credential,
        ..ClientConfig::default()
    };
    let pulled = pull_artifact(&client_with(&mock, cfg), &reference(&mock, "r/p:t"))
        .await
        .unwrap();
    assert_eq!(pulled.package, pkg);
    let leaked: Vec<_> = mock
        .requests()
        .into_iter()
        .filter(|r| {
            r.authorization
                .as_deref()
                .is_some_and(|a| a.contains("internal-ci-token"))
        })
        .collect();
    assert!(
        leaked.is_empty(),
        "token for another registry was sent: {leaked:?}"
    );
}

#[tokio::test]
async fn every_post_put_and_patch_carries_content_length_even_when_empty() {
    // Front ends such as Google's answer 411 to a POST/PUT without
    // Content-Length; the upload-session POST and the chunked-finalize PUT
    // have empty bodies, which hyper would otherwise send with no length.
    for chunk in [64 * 1024 * 1024, 1000] {
        let mock = plain().await;
        let pkg = signed_package(&keypair(3), "lengths", &wasm_bytes(5000));
        let cfg = ClientConfig {
            chunk_size: chunk,
            ..ClientConfig::default()
        };
        push_artifact(
            &client_with(&mock, cfg),
            &reference(&mock, "acme/lengths:1"),
            &pkg,
        )
        .await
        .unwrap();
        let writes: Vec<_> = mock
            .requests()
            .into_iter()
            .filter(|r| matches!(r.method.as_str(), "POST" | "PUT" | "PATCH"))
            .collect();
        assert!(
            writes.iter().any(|r| r.method == "POST"),
            "chunk={chunk}: {writes:?}"
        );
        let missing: Vec<_> = writes
            .iter()
            .filter(|r| r.content_length.is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "chunk={chunk}: requests without Content-Length: {missing:?}"
        );
        let empty_post = writes
            .iter()
            .find(|r| r.method == "POST")
            .and_then(|r| r.content_length.as_deref());
        assert_eq!(empty_post, Some("0"), "chunk={chunk}");
    }
}

#[tokio::test]
async fn chunked_upload_honours_the_registrys_minimum_chunk_length() {
    // (registry minimum, expected PATCH count): a minimum above the client's
    // 1000-byte chunk size raises it; one above the blob means one PUT.
    for (min, expect_patches) in [(5000usize, true), (1 << 20, false)] {
        let mock = plain().await;
        mock.set_chunk_min_length(min);
        let pkg = signed_package(&keypair(4), "minchunk", &wasm_bytes(20_000));
        let cfg = ClientConfig {
            chunk_size: 1000,
            ..ClientConfig::default()
        };
        let r = reference(&mock, "acme/minchunk:1");
        push_artifact(&client_with(&mock, cfg), &r, &pkg)
            .await
            .unwrap_or_else(|e| panic!("min={min}: {e}"));
        let patches: Vec<usize> = mock
            .requests()
            .iter()
            .filter(|q| q.method == "PATCH")
            .map(|q| q.content_length.as_deref().unwrap().parse().unwrap())
            .collect();
        assert_eq!(
            !patches.is_empty(),
            expect_patches,
            "min={min}: {patches:?}"
        );
        if let Some((_last, before)) = patches.split_last() {
            assert!(
                before.iter().all(|n| *n >= min),
                "min={min}: non-final chunks {patches:?}"
            );
        }
        assert_eq!(
            pull_artifact(&client(&mock), &r).await.unwrap().package,
            pkg
        );
    }
}

#[tokio::test]
async fn failed_chunk_is_resumed_from_what_the_registry_holds() {
    // A ~20 KB package in 1000-byte chunks; only the layer is big enough to
    // be chunked, so every PATCH belongs to it.
    let pkg = signed_package(&keypair(5), "resume", &wasm_bytes(20_000));
    let chunks = pkg.len().div_ceil(1000);
    // `stored`: the registry kept the chunk and only the answer was lost
    // (a proxy's 504 after the backend appended it), so it must not be sent
    // again; otherwise it must be.
    for (stored, want_patches) in [(true, chunks), (false, chunks + 1)] {
        let mock = plain().await;
        mock.fail_method("PATCH", "/blobs/uploads/", &[504], stored);
        let cfg = ClientConfig {
            chunk_size: 1000,
            ..ClientConfig::default()
        };
        let r = reference(&mock, "acme/resume:1");
        push_artifact(&client_with(&mock, cfg), &r, &pkg)
            .await
            .unwrap_or_else(|e| panic!("stored={stored}: {e}"));
        let patches = mock
            .requests()
            .iter()
            .filter(|q| q.method == "PATCH")
            .count();
        assert_eq!(patches, want_patches, "stored={stored}");
        assert_eq!(
            pull_artifact(&client(&mock), &r).await.unwrap().package,
            pkg,
            "stored={stored}"
        );
    }
}
