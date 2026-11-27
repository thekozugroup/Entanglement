use super::*;

#[tokio::test]
async fn tier_change_waits_for_readiness_probe() {
    use entangle_runtime::KernelConfig;
    use entangle_signing::Keyring;
    use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = backend.local_addr().unwrap();
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap());
    let adapter = Arc::new(
        Inference::new(
            &InferenceConfig {
                endpoint: format!("http://{addr}/v1/chat/completions"),
                model: "worker-model".into(),
                token_env: None,
            },
            &IdentityKeyPair::generate(),
            kernel.clone(),
        )
        .unwrap(),
    );
    let probe = tokio::spawn({
        let adapter = adapter.clone();
        async move { adapter.streaming_plugins().await }
    });
    let (mut connection, _) = timeout(HEALTH_TIMEOUT, backend.accept())
        .await
        .unwrap()
        .unwrap();

    let lower = kernel.reserve_tier_change(Tier::Sandboxed);
    tokio::pin!(lower);
    tokio::select! {
        biased;
        _ = &mut lower => panic!("tier reduction can commit while the readiness request is active"),
        _ = tokio::task::yield_now() => {}
    }

    let data = r#"{"data":[{"id":"worker-model"}]}"#;
    connection
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{data}",
                data.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(probe.await.unwrap(), vec![adapter.id().clone()]);
    lower
        .await
        .unwrap()
        .apply(Default::default(), || Ok(()))
        .await
        .unwrap();
    assert!(adapter.streaming_plugins().await.is_empty());
}

#[test]
fn provider_restricts_loopback_and_supported_api_paths() {
    let config = |endpoint: &str| InferenceConfig {
        endpoint: endpoint.into(),
        model: "worker-model".into(),
        token_env: None,
    };
    for endpoint in [
        "http://127.0.0.1:8080/v1/chat/completions",
        "http://[::1]:8080/v1/completions",
    ] {
        assert!(Provider::new(&config(endpoint)).is_ok(), "{endpoint}");
    }
    for endpoint in [
        "https://127.0.0.1/v1/chat/completions",
        "http://localhost/v1/chat/completions",
        "http://192.0.2.1/v1/chat/completions",
        "http://[::]/v1/completions",
        "http://127.0.0.1:0/v1/chat/completions",
        "http://127.0.0.1:65536/v1/chat/completions",
        "http://user:pass@127.0.0.1/v1/chat/completions",
        "http://127.0.0.1/v1/chat/completions?model=x",
        "http://127.0.0.1/v1/chat/completions#x",
        "http://127.0.0.1/admin",
    ] {
        assert!(Provider::new(&config(endpoint)).is_err(), "{endpoint}");
    }
}

#[test]
fn frames_utf8_crlf_comments_and_multiline_data() {
    let mut sse = Sse::default();
    let wire = "\u{feff}: heart beat\r\ndata: {\"choices\":\r\ndata: [{\"index\":0,\"text\":\"🐈\"}]}\r\n\r\ndata:[DONE]\r\r";
    let mut events = wire.bytes().filter_map(|byte| sse.feed(byte).unwrap());
    let payload: Frame = serde_json::from_slice(&events.next().unwrap()).unwrap();
    assert_eq!(payload.choices[0].text.as_deref(), Some("🐈"));
    assert_eq!(events.next().unwrap(), b"[DONE]");
    assert!(events.next().is_none());
}

#[test]
fn rejects_oversized_sse_lines_and_events() {
    let mut sse = Sse::default();
    for _ in 0..MAX_SSE_EVENT_BYTES {
        assert!(sse.feed(b'x').is_ok());
    }
    assert!(sse.feed(b'x').is_err());

    let mut sse = Sse::default();
    for _ in 0..MAX_SSE_EVENT_BYTES / 2 {
        for byte in b"data:x\n" {
            sse.feed(*byte).unwrap();
        }
    }
    for byte in b"data:x" {
        sse.feed(*byte).unwrap();
    }
    assert!(sse.feed(b'\n').is_err());
}

#[test]
fn prompts_cannot_select_endpoints_models_or_credentials() {
    assert!(crate::config::RuntimeConfig::default().inference.is_none());
    assert!(serde_json::from_value::<Input>(
        json!({"prompt":"hi","max_tokens":12,"model":"other"})
    )
    .is_err());
    assert!(serde_json::from_value::<Input>(
        json!({"prompt":"hi","max_tokens":12,"endpoint":"http://127.0.0.1/admin"})
    )
    .is_err());
    assert!(serde_json::from_value::<Input>(
        json!({"prompt":"hi","max_tokens":12,"token":"anything"})
    )
    .is_err());
    for input in [
        json!({"prompt":"","max_tokens":12}),
        json!({"prompt":"hi","max_tokens":4097}),
        json!({"prompt":"hi","max_tokens":12,"temperature":2.1}),
    ] {
        assert!(serde_json::from_value::<Input>(input)
            .unwrap()
            .validate()
            .is_err());
    }
}
