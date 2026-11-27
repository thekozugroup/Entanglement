//! §6.4 and §16.3. Verify sealed, externally stored signed bridge vectors.
use biscuit_auth::{PrivateKey, PublicKey};
use entangle_biscuits::{attenuate_biscuit, mint, ClaimSet};
use entangle_signing::{verify_bridge, BridgeCap, RelayAuthorizationError};
use entangle_types::peer_id::PeerId;

const NOW: i64 = 1_000_000;
const VALID: &[u8] = include_bytes!("../testdata/bridge-vectors/valid-bridge.bsk");

fn peer(n: u8) -> PeerId {
    PeerId::from_public_key_bytes(&[n; 32])
}
fn issuer() -> PublicKey {
    PublicKey::from_pem(include_str!(
        "../testdata/bridge-vectors/issuer-public.pem.txt"
    ))
    .unwrap()
}
fn verify(bytes: &[u8]) -> Result<BridgeCap, RelayAuthorizationError> {
    verify_bridge(bytes, &issuer(), peer(1), peer(2), NOW)
}
#[test]
fn valid_bridge_accepted() {
    let cap = verify(VALID).unwrap();
    assert_eq!(cap.bridge(), peer(1));
    assert_eq!(cap.facts().dest_pin, peer(2));
    assert_eq!(cap.facts().rate_limit_bps, 1 << 20);
    assert_eq!(cap.facts().total_bytes_cap, 1 << 30);
    assert_eq!(cap.facts().expires, NOW + 1000);
    assert!(cap.authorize_at(NOW + 499).is_ok());
    assert!(matches!(
        cap.authorize_at(NOW + 500),
        Err(RelayAuthorizationError::Biscuit(_))
    ));
}
macro_rules! reject {
    ($name:ident, $file:literal, $variant:ident, $code:literal) => {
        #[test]
        fn $name() {
            let err = verify(include_bytes!(concat!(
                "../testdata/bridge-vectors/",
                $file
            )))
            .unwrap_err();
            assert!(matches!(err, RelayAuthorizationError::$variant));
            assert!(err.to_string().starts_with($code));
        }
    };
}
reject!(
    missing_rate_limit_rejected,
    "missing-rate-limit.bsk",
    Rate,
    "ENTANGLE-E0118"
);
reject!(
    wrong_dest_rejected,
    "wrong-dest.bsk",
    Destination,
    "ENTANGLE-E0119"
);
reject!(
    expired_ttl_rejected,
    "expired-ttl.bsk",
    Expiry,
    "ENTANGLE-E0120"
);
reject!(
    missing_total_bytes_cap_rejected,
    "missing-total-bytes-cap.bsk",
    LifetimeBytes,
    "ENTANGLE-E0122"
);
reject!(
    no_bridge_marker_rejected,
    "no-bridge-marker.bsk",
    Marker,
    "ENTANGLE-E0121"
);

#[test]
fn all_five_signed_attenuations_are_required() {
    let root = PrivateKey::new();
    let base = mint(
        &root,
        &ClaimSet::new().capability("mesh.relay").issued_to(peer(1)),
    )
    .unwrap();
    for mask in 0..32 {
        let mut claims = ClaimSet::new();
        if mask & 1 != 0 {
            claims = claims.dest_pin(peer(2));
        }
        if mask & 2 != 0 {
            claims = claims.rate_limit_bps(1 << 20);
        }
        if mask & 4 != 0 {
            claims = claims.total_bytes_cap(1 << 30);
        }
        if mask & 8 != 0 {
            claims = claims.expires(NOW + 3600);
        }
        if mask & 16 != 0 {
            claims = claims.bridge_marker();
        }
        let token = attenuate_biscuit(&base, &root.public(), &claims).unwrap();
        assert_eq!(
            verify_bridge(&token, &root.public(), peer(1), peer(2), NOW).is_ok(),
            mask == 31,
            "mask {mask:05b}"
        );
    }
}

#[test]
fn ceiling_and_holder_boundaries() {
    let root = PrivateKey::new();
    let base = mint(
        &root,
        &ClaimSet::new().capability("mesh.relay").issued_to(peer(1)),
    )
    .unwrap();
    for (rate, bytes, expiry, err) in [
        ((1 << 20) + 1, 1 << 30, NOW + 3600, "E0118"),
        (1 << 20, (1 << 30) + 1, NOW + 3600, "E0122"),
        (1 << 20, 1 << 30, NOW + 3601, "E0120"),
        (1 << 20, 1 << 30, NOW, "E0120"),
    ] {
        let claims = entangle_biscuits::make_bridge_attenuation(peer(2), rate, bytes, expiry);
        let token = attenuate_biscuit(&base, &root.public(), &claims).unwrap();
        assert!(verify_bridge(&token, &root.public(), peer(1), peer(2), NOW)
            .unwrap_err()
            .to_string()
            .contains(err));
    }
    assert!(verify_bridge(VALID, &root.public(), peer(1), peer(2), NOW).is_err());
    assert!(verify_bridge(VALID, &issuer(), peer(3), peer(2), NOW).is_err());
}

#[test]
fn canonical_ed25519_destination_resolves_to_paired_node_identity() {
    let key = PrivateKey::new();
    let recipient = PrivateKey::new().public();
    let dest = PeerId::from_public_key_bytes(&recipient.to_bytes().try_into().unwrap());
    let token=biscuit_auth::Biscuit::builder().code(format!(
        "peer(\"{}\"); capability(\"mesh.relay\"); bridge_cap(true); relay_dest_node(\"ed25519:{}\"); relay_rate_max(1); relay_total_bytes_max(10); expires({});",
        peer(1),recipient.to_bytes_hex(),NOW+300
    )).unwrap().build(&key).unwrap().to_vec().unwrap();
    assert_eq!(
        verify_bridge(&token, &key.public(), peer(1), dest, NOW)
            .unwrap()
            .facts()
            .dest_pin,
        dest
    );
}
