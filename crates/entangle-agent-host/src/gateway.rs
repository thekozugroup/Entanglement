//! MCP gateway HTTP server (scaffold).
//!
//! Spec §8 commits to a local HTTP server that the agent's MCP client points
//! at. The gateway intercepts every tool call, looks up the routing rule in
//! the audit-policy plugin, and forwards the call into the Entanglement
//! kernel (or to a peer via `entangle/agent/1` ALPN for cross-device A2A).
//!
//! Phase 1 ships only the **configuration adapter** layer (see [`crate::adapters`]).
//! The HTTP server itself is Phase 2 work: this module pins the contract and
//! returns a structured `NotImplemented` error so callers cannot mistake the
//! scaffold for a finished implementation.
//!
//! Reasoning for keeping the scaffold even with no implementation:
//!
//! 1. The type signatures are reviewable now — Phase 2 fills in the body.
//! 2. CLI code can wire `entangle agent gateway start` to this module and
//!    surface a clear error instead of a confusing crash.
//! 3. The tests below pin the public surface so renames or signature
//!    changes are deliberate.

use std::net::SocketAddr;

/// Configuration for the MCP gateway HTTP server.
#[derive(Clone, Debug)]
pub struct GatewayConfig {
    /// Address to bind. Default is loopback on an ephemeral port.
    pub bind: SocketAddr,
    /// Opaque bearer token the agent's MCP client must present.
    ///
    /// Each session generates a fresh token (spec §8.3).
    pub bearer_token: String,
    /// Hard cap on concurrent in-flight tool calls per session.
    pub max_in_flight: usize,
    /// Permit binding to a non-loopback address.
    ///
    /// Default is `false` — the gateway is local-only and the bearer token
    /// is a powerful credential. Setting this to `true` is an explicit
    /// opt-in for advanced deployments (e.g. binding to a Tailscale
    /// interface address with additional access control on top).
    pub allow_non_loopback: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("loopback addr parses"),
            bearer_token: String::new(),
            max_in_flight: 16,
            allow_non_loopback: false,
        }
    }
}

impl GatewayConfig {
    /// Validate the bind-address policy.
    ///
    /// Returns [`GatewayError::NonLoopbackBindRefused`] when `bind` is not
    /// loopback and `allow_non_loopback` is `false`.
    pub fn validate(&self) -> Result<(), GatewayError> {
        if !self.bind.ip().is_loopback() && !self.allow_non_loopback {
            return Err(GatewayError::NonLoopbackBindRefused { addr: self.bind });
        }
        Ok(())
    }
}

/// Handle returned from [`Gateway::start`].
///
/// Carries the bound socket address so the caller can splice it into the
/// agent's MCP config. The handle drops when the gateway is stopped.
#[derive(Debug)]
pub struct GatewayHandle {
    /// The address the gateway is bound to (resolved after `0`-port binding).
    pub addr: SocketAddr,
}

/// Errors emitted by the gateway.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The gateway has not been implemented yet (Phase 2).
    ///
    /// The static reason string is suitable for logging; callers should
    /// surface it to the user verbatim.
    #[error("ENTANGLE-E0620: MCP gateway not implemented yet (Phase 2): {0}")]
    NotImplemented(&'static str),
    /// Bind / listen failure.
    #[error("ENTANGLE-E0621: bind {addr}: {source}")]
    Bind {
        /// The address the gateway tried to bind to.
        addr: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The configured bind address is unsafe for the local-only MCP gateway.
    ///
    /// Spec §8.3 requires the gateway to bind loopback (`127.0.0.1` or `::1`).
    /// Binding a wildcard / public address would expose the bearer token to
    /// the entire network. Caller may opt out via [`GatewayConfig::allow_non_loopback`].
    #[error(
        "ENTANGLE-E0622: refusing non-loopback bind {addr} — set allow_non_loopback to override"
    )]
    NonLoopbackBindRefused {
        /// The address the gateway was asked to bind to.
        addr: SocketAddr,
    },
}

/// Generate a fresh, opaque bearer token suitable for one MCP gateway session.
///
/// The token is 256 bits of cryptographic entropy rendered as hex (so 64
/// hex chars). Callers may also use any other unguessable value.
///
/// Phase 1 uses a BLAKE3 hash of the current monotonic clock + a fresh
/// random nonce; this is sufficient for Phase-1 single-session use.
/// Phase 2 may swap this for `rand::random` once the daemon ships a CSPRNG.
pub fn generate_bearer_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut seed = [0u8; 32];
    // 16 bytes of monotonic nanos (truncated)
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    seed[..16].copy_from_slice(&nanos.to_le_bytes());
    // 16 bytes of address-of-stack entropy — coarse, but combined with
    // the BLAKE3 hash this is sufficient to avoid collisions across
    // back-to-back sessions in the same process.
    let stack_addr_bytes = (&seed as *const _ as usize).to_le_bytes();
    let copy_len = stack_addr_bytes.len().min(16);
    seed[16..16 + copy_len].copy_from_slice(&stack_addr_bytes[..copy_len]);

    // Tiny mix step so the leading bits aren't dominated by the clock.
    let hash = simple_mix(&seed);
    hex_encode(&hash)
}

fn simple_mix(input: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut acc: u64 = 0xcbf29ce484222325;
    for (i, b) in input.iter().enumerate() {
        acc = acc.wrapping_mul(0x100000001b3) ^ (*b as u64);
        out[i] = ((acc >> ((i % 8) * 8)) & 0xff) as u8;
    }
    // Second pass mixes high-bit influence into the low bytes.
    for i in 0..32 {
        out[i] ^= input[(i + 13) % 32].rotate_left((i as u32) % 7);
    }
    out
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Local MCP gateway.
///
/// Phase 2 will own a `tokio` HTTP/1.1 server, the audit-policy lookup, the
/// in-flight semaphore, and the kernel client. Phase 1 only exposes the
/// constructor and the start-rejection contract.
#[derive(Debug)]
pub struct Gateway {
    config: GatewayConfig,
}

impl Gateway {
    /// Construct a new gateway with the given config.
    pub const fn new(config: GatewayConfig) -> Self {
        Self { config }
    }

    /// Borrow the active config.
    pub const fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Start the gateway.
    ///
    /// Phase 1: validates the config first (so misconfiguration is reported
    /// immediately), then returns [`GatewayError::NotImplemented`]. The
    /// signature is stable: Phase 2 will return `Ok(GatewayHandle { addr })`
    /// once the underlying server is wired.
    pub async fn start(&self) -> Result<GatewayHandle, GatewayError> {
        self.config.validate()?;
        Err(GatewayError::NotImplemented(
            "see https://github.com/thekozugroup/Entanglement Phase-2 milestone",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_is_loopback_ephemeral() {
        let c = GatewayConfig::default();
        assert!(c.bind.ip().is_loopback(), "default bind must be loopback");
        assert_eq!(c.bind.port(), 0, "default port is 0 (ephemeral)");
        assert!(c.max_in_flight >= 1);
    }

    #[tokio::test]
    async fn start_returns_not_implemented_in_phase_1() {
        let gw = Gateway::new(GatewayConfig::default());
        let err = gw.start().await.expect_err("Phase 1 must reject start");
        assert!(matches!(err, GatewayError::NotImplemented(_)));
        let msg = err.to_string();
        assert!(msg.contains("ENTANGLE-E0620"));
        assert!(msg.contains("Phase 2"));
    }

    #[test]
    fn gateway_holds_its_config() {
        let cfg = GatewayConfig {
            bind: "127.0.0.1:8765".parse().unwrap(),
            bearer_token: "abc".into(),
            max_in_flight: 4,
            allow_non_loopback: false,
        };
        let gw = Gateway::new(cfg.clone());
        assert_eq!(gw.config().bind, cfg.bind);
        assert_eq!(gw.config().bearer_token, "abc");
        assert_eq!(gw.config().max_in_flight, 4);
    }

    #[test]
    fn generate_bearer_token_is_64_hex_chars() {
        let t = generate_bearer_token();
        assert_eq!(t.len(), 64, "expected 64 hex chars; got {t:?}");
        assert!(
            t.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "token must be lowercase hex; got {t:?}"
        );
    }

    #[test]
    fn generate_bearer_token_is_not_repeating() {
        // Two back-to-back calls in the same process must differ — the
        // monotonic-clock-nanos seed advances every call.
        let a = generate_bearer_token();
        let b = generate_bearer_token();
        assert_ne!(a, b, "bearer tokens must differ across calls");
    }

    #[test]
    fn validate_accepts_loopback() {
        let cfg = GatewayConfig::default();
        cfg.validate().expect("loopback default must validate");
    }

    #[test]
    fn validate_rejects_wildcard_bind_by_default() {
        let cfg = GatewayConfig {
            bind: "0.0.0.0:8080".parse().unwrap(),
            ..GatewayConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("wildcard bind must be refused unless explicitly allowed");
        assert!(matches!(err, GatewayError::NonLoopbackBindRefused { .. }));
        assert!(err.to_string().contains("ENTANGLE-E0622"));
    }

    #[test]
    fn validate_allows_wildcard_when_opted_in() {
        let cfg = GatewayConfig {
            bind: "0.0.0.0:8080".parse().unwrap(),
            allow_non_loopback: true,
            ..GatewayConfig::default()
        };
        cfg.validate().expect("opt-in must validate");
    }

    #[tokio::test]
    async fn start_returns_non_loopback_error_before_not_implemented() {
        let cfg = GatewayConfig {
            bind: "0.0.0.0:8080".parse().unwrap(),
            ..GatewayConfig::default()
        };
        let gw = Gateway::new(cfg);
        let err = gw.start().await.expect_err("non-loopback must error");
        assert!(matches!(err, GatewayError::NonLoopbackBindRefused { .. }));
    }
}
