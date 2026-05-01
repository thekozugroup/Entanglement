//! Peer descriptor types for the `mesh.local` discovery layer.

use entangle_types::peer_id::PeerId;
use std::net::IpAddr;
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

/// Peer-seen record from mDNS browse.
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
    /// Wall-clock time of the most recent mDNS resolution.
    pub last_seen: SystemTime,
}
