//! Peer descriptors and the operator-facing "long address" format.

use std::net::SocketAddr;

use entangle_types::peer_id::PeerId;

use crate::error::MeshIrohError;

/// A dialable peer: cryptographic identity plus reachability hints.
///
/// # Why the raw public key is carried
///
/// [`PeerId`] is `BLAKE3(pubkey)[..16]` — a *fingerprint*, and therefore not
/// invertible. QUIC needs the actual 32-byte Ed25519 public key to
/// authenticate the peer, so a descriptor that carried only the `PeerId`
/// could be compared but never dialled. Both are kept, and `peer_id` is
/// always derived from `public_key` (see [`IrohPeer::new`]) so they cannot
/// disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrohPeer {
    /// Entanglement peer id, derived from `public_key`.
    pub peer_id: PeerId,
    /// The peer's raw Ed25519 public key — also its iroh `EndpointId`.
    pub public_key: [u8; 32],
    /// Last-known reachable address.
    pub addr: SocketAddr,
    /// Further address hints (other interfaces, previously seen paths).
    pub extra_addrs: Vec<SocketAddr>,
}

impl IrohPeer {
    /// Build a descriptor from a public key and a reachability hint.
    pub fn new(public_key: [u8; 32], addr: SocketAddr) -> Self {
        Self {
            peer_id: PeerId::from_public_key_bytes(&public_key),
            public_key,
            addr,
            extra_addrs: Vec::new(),
        }
    }

    /// Add another address hint. All hints are raced when dialling.
    #[must_use]
    pub fn with_addr(mut self, addr: SocketAddr) -> Self {
        if addr != self.addr && !self.extra_addrs.contains(&addr) {
            self.extra_addrs.push(addr);
        }
        self
    }

    /// All reachability hints, primary first.
    pub fn addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        std::iter::once(self.addr).chain(self.extra_addrs.iter().copied())
    }

    /// Render as `<pubkey-hex>@<host>:<port>` using the primary address.
    pub fn to_node_addr(&self) -> String {
        format_node_addr(&self.public_key, self.addr)
    }
}

/// Render a `<pubkey-hex>@<host>:<port>` long address.
///
/// Exact inverse of [`parse_node_addr`].
pub fn format_node_addr(public_key: &[u8; 32], addr: SocketAddr) -> String {
    format!("{}@{}", hex::encode(public_key), addr)
}

/// Parse a `<pubkey_hex>@<host>:<port>` reference into an [`IrohPeer`].
///
/// This is the operator-facing form printed by `entangle mesh peers` and
/// accepted by `entangle mesh trust <node-addr>`. Spec §6.1 calls it the
/// "long address" — it bundles the cryptographic identity (the full Ed25519
/// public key, which is also the iroh `EndpointId`) with a reachability hint.
pub fn parse_node_addr(s: &str) -> Result<IrohPeer, MeshIrohError> {
    let (id_hex, addr_str) = s
        .split_once('@')
        .ok_or(MeshIrohError::BadNodeAddr("missing '@' separator"))?;
    if id_hex.len() != 64 {
        return Err(MeshIrohError::BadNodeAddr(
            "peer id hex must be 64 chars (32 bytes)",
        ));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in id_hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| MeshIrohError::BadNodeAddr("non-ASCII in peer id"))?;
        bytes[i] = u8::from_str_radix(pair, 16)
            .map_err(|_| MeshIrohError::BadNodeAddr("invalid hex digit in peer id"))?;
    }
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|_| MeshIrohError::BadNodeAddr("addr must be host:port"))?;
    Ok(IrohPeer::new(bytes, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_descriptor_round_trips_equality() {
        let a = IrohPeer::new([1; 32], "127.0.0.1:1000".parse().unwrap());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn peer_id_is_derived_from_public_key() {
        let peer = IrohPeer::new([9; 32], "127.0.0.1:1".parse().unwrap());
        assert_eq!(peer.peer_id, PeerId::from_public_key_bytes(&[9; 32]));
    }

    #[test]
    fn parse_node_addr_round_trips_well_formed() {
        let hex = "a".repeat(64);
        let s = format!("{hex}@10.0.0.1:7777");
        let peer = parse_node_addr(&s).expect("parse must succeed");
        assert_eq!(peer.addr.port(), 7777);
        assert_eq!(peer.public_key, [0xaa; 32], "every nibble 'a' = byte 0xaa");
        assert_eq!(
            peer.peer_id,
            PeerId::from_public_key_bytes(&[0xaa; 32]),
            "peer id must be the BLAKE3-16 of the parsed key"
        );
    }

    #[test]
    fn format_and_parse_are_inverses() {
        let key = [0x3c; 32];
        let addr: SocketAddr = "192.168.1.9:41641".parse().unwrap();
        let rendered = format_node_addr(&key, addr);
        let parsed = parse_node_addr(&rendered).expect("must round-trip");
        assert_eq!(parsed.public_key, key);
        assert_eq!(parsed.addr, addr);
        assert_eq!(parsed.to_node_addr(), rendered);
    }

    #[test]
    fn ipv6_long_address_round_trips() {
        let key = [0x11; 32];
        let addr: SocketAddr = "[::1]:4242".parse().unwrap();
        let parsed = parse_node_addr(&format_node_addr(&key, addr)).expect("must round-trip");
        assert_eq!(parsed.addr, addr);
    }

    #[test]
    fn extra_addrs_are_deduped_and_ordered() {
        let base: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let other: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let peer = IrohPeer::new([2; 32], base)
            .with_addr(other)
            .with_addr(other)
            .with_addr(base);
        assert_eq!(peer.addrs().collect::<Vec<_>>(), vec![base, other]);
    }

    #[test]
    fn parse_node_addr_rejects_missing_at() {
        let err = parse_node_addr("abcdef").expect_err("must error");
        assert!(matches!(err, MeshIrohError::BadNodeAddr(_)));
        assert!(err.to_string().contains("ENTANGLE-E0631"));
    }

    #[test]
    fn parse_node_addr_rejects_short_hex() {
        let err = parse_node_addr("abcd@127.0.0.1:1").expect_err("must error");
        assert!(matches!(err, MeshIrohError::BadNodeAddr(_)));
    }

    #[test]
    fn parse_node_addr_rejects_bad_addr() {
        let hex = "0".repeat(64);
        let err = parse_node_addr(&format!("{hex}@not-an-addr")).expect_err("must error");
        assert!(matches!(err, MeshIrohError::BadNodeAddr(_)));
    }

    #[test]
    fn parse_node_addr_rejects_non_hex() {
        let err =
            parse_node_addr(&format!("{}@127.0.0.1:1", "z".repeat(64))).expect_err("must error");
        assert!(matches!(err, MeshIrohError::BadNodeAddr(_)));
    }
}
