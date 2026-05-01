//! Typed capability claim builder and parser.
//!
//! Each [`Claim`] maps 1-to-1 to one Datalog fact in the biscuit body.

use entangle_types::peer_id::PeerId;

/// A single Datalog fact embedded in a biscuit authority or attenuation block.
///
/// The canonical serialization (see [`Claim::as_datalog`]) uses biscuit-auth's
/// text format so the string can be passed directly to the builder's `.fact()`
/// method.
#[allow(missing_docs)] // variant fields are self-documenting via the enum variant doc
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    /// `peer({hex})` — issued to this peer (allowlist check). Field: the peer's ID.
    IssuedTo { peer_id: PeerId },
    /// `capability({string})` — the capability surface name (e.g. `"compute.gpu"`). Field: surface name.
    Capability { surface: String },
    /// `expires({unix_secs})` — absolute expiry as a Unix timestamp (seconds). Field: Unix epoch.
    Expires { unix_secs: i64 },
    /// `dest_pin({hex})` — bridge attenuation: only relay for this destination peer. Field: peer ID.
    DestPin { peer_id: PeerId },
    /// `rate_limit_bps({n})` — bridge attenuation: max bytes per second. Field: bps value.
    RateLimitBps { bps: u64 },
    /// `total_bytes_cap({n})` — bridge attenuation: max total bytes. Field: byte count.
    TotalBytesCap { bytes: u64 },
    /// `bridge(true)` — marks this token as a bridge cap (spec §6.4 invariant).
    BridgeMarker,
}

impl Claim {
    /// Serialize this claim to the canonical Datalog fact string for inclusion
    /// in a biscuit block.
    ///
    /// The returned string does **not** end with a semicolon; biscuit-auth's
    /// parser accepts bare facts.
    pub fn as_datalog(&self) -> String {
        match self {
            Claim::IssuedTo { peer_id } => format!("peer(\"{}\")", peer_id.to_hex()),
            Claim::Capability { surface } => format!("capability(\"{}\")", escape(surface)),
            Claim::Expires { unix_secs } => format!("expires({unix_secs})"),
            Claim::DestPin { peer_id } => format!("dest_pin(\"{}\")", peer_id.to_hex()),
            Claim::RateLimitBps { bps } => format!("rate_limit_bps({bps})"),
            Claim::TotalBytesCap { bytes } => format!("total_bytes_cap({bytes})"),
            Claim::BridgeMarker => "bridge(true)".into(),
        }
    }
}

/// Escape backslashes and double-quotes for biscuit Datalog string literals.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// An ordered collection of [`Claim`]s that form the payload of a biscuit block.
#[derive(Default, Clone, Debug)]
pub struct ClaimSet {
    /// The individual claims.
    pub claims: Vec<Claim>,
}

impl ClaimSet {
    /// Create an empty `ClaimSet`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an [`IssuedTo`](Claim::IssuedTo) claim.
    pub fn issued_to(mut self, peer_id: PeerId) -> Self {
        self.claims.push(Claim::IssuedTo { peer_id });
        self
    }

    /// Append a [`Capability`](Claim::Capability) claim.
    pub fn capability(mut self, surface: impl Into<String>) -> Self {
        self.claims.push(Claim::Capability {
            surface: surface.into(),
        });
        self
    }

    /// Append an [`Expires`](Claim::Expires) claim.
    pub fn expires(mut self, unix_secs: i64) -> Self {
        self.claims.push(Claim::Expires { unix_secs });
        self
    }

    /// Append a [`DestPin`](Claim::DestPin) claim.
    pub fn dest_pin(mut self, peer_id: PeerId) -> Self {
        self.claims.push(Claim::DestPin { peer_id });
        self
    }

    /// Append a [`RateLimitBps`](Claim::RateLimitBps) claim.
    pub fn rate_limit_bps(mut self, bps: u64) -> Self {
        self.claims.push(Claim::RateLimitBps { bps });
        self
    }

    /// Append a [`TotalBytesCap`](Claim::TotalBytesCap) claim.
    pub fn total_bytes_cap(mut self, bytes: u64) -> Self {
        self.claims.push(Claim::TotalBytesCap { bytes });
        self
    }

    /// Append a [`BridgeMarker`](Claim::BridgeMarker) claim.
    pub fn bridge_marker(mut self) -> Self {
        self.claims.push(Claim::BridgeMarker);
        self
    }

    /// Extend this `ClaimSet` with additional claims from an iterator.
    pub fn extend(mut self, claims: impl IntoIterator<Item = Claim>) -> Self {
        for c in claims {
            self.claims.push(c);
        }
        self
    }
}
