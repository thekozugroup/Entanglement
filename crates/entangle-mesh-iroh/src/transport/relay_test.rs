use std::num::NonZeroU16;
use std::time::Duration;

use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use iroh::endpoint::{presets, PortmapperConfig};
use iroh::{Endpoint, EndpointAddr, NetReportConfig, RelayConfig, RelayMode, RelayUrl, SecretKey};

use super::{secret_seed, MeshConn, MeshIrohConfig};
use crate::ALPN_SCHEDULER;

async fn relay_endpoint(key: &IdentityKeyPair, url: &RelayUrl) -> Endpoint {
    // Iroh chooses a home relay from latency measurements. With QAD and
    // direct IP disabled, enable its HTTP probe to this loopback server.
    let mut probes = NetReportConfig::minimal();
    probes.https_probes = true;
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&secret_seed(key).unwrap()))
        .alpns(vec![ALPN_SCHEDULER.to_vec()])
        .relay_mode(RelayMode::Custom(
            RelayConfig::new(url.clone(), None).into(),
        ))
        .clear_ip_transports()
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(probes)
        .bind()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(12), endpoint.online())
        .await
        .expect("endpoint must attach to the configured loopback relay");
    assert!(endpoint.bound_sockets().is_empty());
    endpoint
}

fn assert_peer(conn: &MeshConn, key: &IdentityKeyPair) {
    let public = *key.public().as_bytes();
    assert_eq!(conn.remote_public_key(), public);
    assert_eq!(
        conn.remote_peer_id(),
        PeerId::from_public_key_bytes(&public)
    );
}

#[tokio::test]
#[ignore = "requires a loopback iroh-relay server, see docs/testing/local-relay.md"]
async fn authenticated_request_crosses_local_relay() {
    let port: NonZeroU16 = std::env::var("ENTANGLE_TEST_RELAY_PORT")
        .expect("set ENTANGLE_TEST_RELAY_PORT to the running relay's loopback TCP port")
        .parse()
        .expect("expected a nonzero TCP port");
    let relay: RelayUrl = format!("http://127.0.0.1:{port}").parse().unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        let client_key = IdentityKeyPair::generate();
        let server_key = IdentityKeyPair::generate();
        let (client, server) = tokio::join!(
            relay_endpoint(&client_key, &relay),
            relay_endpoint(&server_key, &relay),
        );
        let config = MeshIrohConfig::loopback();
        let target = EndpointAddr::new(server.id()).with_relay_url(relay.clone());
        let (outbound, inbound) = tokio::join!(client.connect(target, ALPN_SCHEDULER), async {
            server.accept().await.unwrap().await.unwrap()
        },);
        let outbound = MeshConn::wrap(outbound.unwrap(), &config);
        let inbound = MeshConn::wrap(inbound, &config);
        assert_peer(&outbound, &server_key);
        assert_peer(&inbound, &client_key);

        let request = b"local relay request\x00";
        let response = b"local relay reply\xff";
        let (reply, ()) = tokio::join!(outbound.request(request), async {
            let received = inbound.accept_request().await.unwrap().unwrap();
            assert_eq!(received.payload(), request);
            received.respond(response).await.unwrap();
        });
        assert_eq!(reply.unwrap(), response);
        let expected = iroh::TransportAddr::Relay(relay);
        for conn in [&outbound, &inbound] {
            let paths = conn.inner.paths();
            assert!(paths.iter().any(|path| path.is_selected()));
            assert!(paths.iter().all(|path| path.remote_addr() == &expected));
        }
        outbound.close();
        tokio::join!(client.close(), server.close());
    })
    .await
    .expect("local relay attach, exchange and shutdown must finish within 30s");
}
