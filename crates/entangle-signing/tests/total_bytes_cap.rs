//! §16.3 BRG-6. Real signed independent endpoint grants and a durable receiver.
use biscuit_auth::PrivateKey;
use entangle_biscuits::{attenuate_biscuit, make_bridge_attenuation, mint, ClaimSet};
use entangle_signing::{BridgeReceiver, RelayError};
use entangle_types::peer_id::PeerId;
use std::{
    sync::{Arc, Barrier},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

fn peer(n: u8) -> PeerId {
    PeerId::from_public_key_bytes(&[n; 32])
}
fn token(key: &PrivateKey, dest: PeerId, rate: u64, total: u64) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let base = mint(
        key,
        &ClaimSet::new().issued_to(peer(1)).capability("mesh.relay"),
    )
    .unwrap();
    attenuate_biscuit(
        &base,
        &key.public(),
        &make_bridge_attenuation(dest, rate, total, now + 300),
    )
    .unwrap()
}

#[test]
fn exact_boundary_survives_restart_and_further_attenuation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.toml");
    let (origin, local) = (PrivateKey::new(), PrivateKey::new());
    let dest = PeerId::from_public_key_bytes(&local.public().to_bytes().try_into().unwrap());
    let a = token(&origin, dest, 2048, 1024);
    let b = token(&local, dest, 2048, 2048);
    BridgeReceiver::initialize(&path).unwrap();
    let receiver = BridgeReceiver::open(&path, dest, local.public()).unwrap();
    let session = receiver
        .authorize(&origin.public(), peer(1), &a, &b)
        .unwrap();
    let mut sink = Vec::new();
    receiver.receive(&session, &[7; 1024], &mut sink).unwrap();
    assert_eq!(sink, vec![7; 1024]);

    let receiver = BridgeReceiver::open(&path, dest, local.public()).unwrap();
    let child =
        attenuate_biscuit(&a, &origin.public(), &ClaimSet::new().rate_limit_bps(1024)).unwrap();
    let session = receiver
        .authorize(&origin.public(), peer(1), &child, &b)
        .unwrap();
    assert!(matches!(
        receiver.receive(&session, b"x", &mut sink),
        Err(RelayError::BridgeBudgetExhausted)
    ));
    assert_eq!(sink.len(), 1024);
    assert!(BridgeReceiver::initialize(&path).is_err());
    assert!(receiver
        .authorize(&origin.public(), peer(3), &a, &b)
        .is_err());
    assert!(receiver
        .authorize(&origin.public(), peer(1), &b, &b)
        .is_err());
    std::fs::write(&path, b"damaged ledger").unwrap();
    assert!(receiver.receive(&session, b"x", &mut sink).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(receiver.receive(&session, b"x", &mut sink).is_err());
}

#[test]
fn concurrent_receivers_deliver_exactly_the_available_budget() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.toml");
    let (origin, local) = (PrivateKey::new(), PrivateKey::new());
    let dest = PeerId::from_public_key_bytes(&local.public().to_bytes().try_into().unwrap());
    let a = token(&origin, dest, 4096, 4096);
    let b = token(&local, dest, 4096, 1024);
    BridgeReceiver::initialize(&path).unwrap();
    let receiver = BridgeReceiver::open(&path, dest, local.public()).unwrap();
    let session = Arc::new(
        receiver
            .authorize(&origin.public(), peer(1), &a, &b)
            .unwrap(),
    );
    let gate = Arc::new(Barrier::new(8));
    let mut joins = Vec::new();
    for _ in 0..8 {
        let receiver = BridgeReceiver::open(&path, dest, local.public()).unwrap();
        let gate = Arc::clone(&gate);
        let session = Arc::clone(&session);
        joins.push(thread::spawn(move || {
            let mut sink = Vec::new();
            gate.wait();
            match receiver.receive(&session, &[1; 256], &mut sink) {
                Ok(()) => assert_eq!(sink.len(), 256),
                Err(RelayError::BridgeBudgetExhausted) => assert!(sink.is_empty()),
                other => panic!("unexpected receiver outcome: {other:?}"),
            }
            sink.len()
        }));
    }
    assert_eq!(
        joins.into_iter().map(|t| t.join().unwrap()).sum::<usize>(),
        1024
    );
}

#[test]
fn either_rate_limit_blocks_before_delivery_and_keeps_the_previous_balance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.toml");
    let (origin, local) = (PrivateKey::new(), PrivateKey::new());
    let dest = PeerId::from_public_key_bytes(&local.public().to_bytes().try_into().unwrap());
    BridgeReceiver::initialize(&path).unwrap();
    let receiver = BridgeReceiver::open(&path, dest, local.public()).unwrap();
    let session = receiver
        .authorize(
            &origin.public(),
            peer(1),
            &token(&origin, dest, 1024, 1),
            &token(&local, dest, 0, 1024),
        )
        .unwrap();
    let mut sink = Vec::new();
    assert!(matches!(
        receiver.receive(&session, b"x", &mut sink),
        Err(RelayError::RateLimited)
    ));
    assert!(sink.is_empty());
}
