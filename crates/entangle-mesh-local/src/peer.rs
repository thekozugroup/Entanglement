//! Peer descriptor types for the `mesh.local` discovery layer.

use entangle_types::peer_id::PeerId;
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

/// Hardware capability advertisement encoded in mDNS TXT records.
///
/// All fields are best-effort; a missing value is represented by `0` or
/// `None`.  Populated by `detect_hardware()` in the daemon and carried in
/// [`LocalPeer`] so the scheduler can pre-filter workers without an extra
/// round trip (spec §6.1 + §7).
#[derive(Clone, Debug)]
pub struct HardwareAdvert {
    /// Number of logical CPU cores (fractional allowed).
    pub cpu_cores: f32,
    /// Total host memory in bytes; `0` = unknown.
    pub memory_bytes: u64,
    /// GPU backend, if one is present.
    pub gpu_backend: Option<entangle_types::resource::GpuBackend>,
    /// GPU VRAM in bytes; `0` = no GPU or unknown.
    pub gpu_vram_bytes: u64,
    /// Estimated egress network bandwidth in bits per second; `0` = unknown.
    pub network_bandwidth_bps: u64,
    /// NPU vendor string if a neural accelerator is detected; `None` = no NPU.
    ///
    /// Phase 1: always `None` — see `entangle_bin::npu::detect()`.
    pub npu_vendor: Option<String>,
}

/// Local peer descriptor — what we publish about ourselves on mDNS.
#[derive(Clone, Debug)]
pub struct LocalPeer {
    /// Ed25519 fingerprint, BLAKE3-16.
    pub peer_id: PeerId,
    /// Human-friendly hostname; user-overridable.
    pub display_name: String,
    /// ENet/QUIC port; placeholder until Phase 2.
    pub port: u16,
    /// `env!("CARGO_PKG_VERSION")` of entangled.
    pub version: String,
    /// Hardware advertisement for the scheduler's worker pool.
    pub hardware: Option<HardwareAdvert>,
}

/// What a node has to publish for a discovering peer to be able to *dial* it.
///
/// # Why this is not optional in practice
///
/// [`PeerId`] is `BLAKE3(pubkey)[..16]` — a one-way fingerprint. The QUIC
/// transport (`entangle-mesh-iroh`) authenticates a peer by its raw 32-byte
/// Ed25519 public key, which is also its iroh `EndpointId`, and that key
/// cannot be recovered from a `PeerId`. A discovery record carrying only the
/// `peer_id` is therefore *comparable but not dialable*: it can tell you a
/// device is on the link, and nothing more.
///
/// Attaching this advert to a [`Discovery`](crate::Discovery) publishes the
/// public key and the transport port in the mDNS TXT record, which is what
/// turns a sighting into something the pairing flow can connect to.
///
/// The key is public by design (it is the peer's identity, printed by
/// `entangle mesh peers` and embedded in every long address), so advertising
/// it discloses nothing that dialing the node would not already reveal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportAdvert {
    /// Raw Ed25519 public key — the peer's iroh `EndpointId`.
    pub public_key: [u8; 32],
    /// UDP port the QUIC transport is bound to.
    pub mesh_port: u16,
}

impl TransportAdvert {
    /// Build an advert from a public key and the transport's bound port.
    pub const fn new(public_key: [u8; 32], mesh_port: u16) -> Self {
        Self {
            public_key,
            mesh_port,
        }
    }

    /// The [`PeerId`] this key derives to.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public_key_bytes(&self.public_key)
    }
}

/// Peer-seen record from mDNS browse.
///
/// Everything in here except `last_seen` comes from an **untrusted** remote
/// announcement: strings are sanitized and bounded on parse, and `public_key`
/// is only populated when it decoded to exactly 32 bytes *and* derived to the
/// announced `peer_id`.
#[derive(Clone, Debug)]
pub struct PeerSeen {
    /// Ed25519 fingerprint, BLAKE3-16.
    pub peer_id: PeerId,
    /// Human-friendly display name from the TXT record.
    pub display_name: String,
    /// All resolved addresses for this peer.
    pub addresses: Vec<IpAddr>,
    /// Announced port.
    pub port: u16,
    /// Entangled crate version the peer is running.
    pub version: String,
    /// Hardware advertisement parsed from TXT records, if present.
    pub hardware: Option<HardwareAdvert>,
    /// Raw Ed25519 public key from the `public_key` TXT record, if the peer
    /// advertised one that is well-formed and consistent with `peer_id`.
    ///
    /// `None` means "sighted but not dialable" — see [`TransportAdvert`].
    pub public_key: Option<[u8; 32]>,
    /// QUIC transport port from the `mesh_port` TXT record, if advertised.
    pub mesh_port: Option<u16>,
    /// Wall-clock time of the most recent mDNS resolution.
    pub last_seen: SystemTime,
}

impl PeerSeen {
    /// Socket addresses to try when dialing this peer's mesh transport.
    ///
    /// Uses the advertised `mesh_port` when present and falls back to the
    /// service port otherwise. Empty when the peer resolved to no addresses.
    pub fn dial_targets(&self) -> Vec<SocketAddr> {
        let port = self.mesh_port.unwrap_or(self.port);
        self.addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect()
    }

    /// True when this sighting carries everything needed to dial the peer:
    /// a public key and at least one address.
    pub fn is_dialable(&self) -> bool {
        self.public_key.is_some() && !self.addresses.is_empty()
    }
}
