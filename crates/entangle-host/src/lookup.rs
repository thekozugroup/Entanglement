//! The guest's `wasi:sockets/ip-name-lookup`, answered by the host from the
//! plugin's grants instead of the system resolver.
//!
//! wasmtime-wasi's own implementation hands every name the guest asks for
//! to the daemon's resolver once lookups are enabled at all. That would let
//! any `net.*` grant send arbitrary queries — `<data>.attacker.example` —
//! through the system resolver to upstream name servers (a WAN channel even
//! for a `net.lan`-only plugin, or one whose `net.wan` the operator denied),
//! and its answers need not match the addresses the socket rules accept.
//! [`crate::engine::HostEngine`] therefore replaces the interface with this
//! one, which answers:
//!
//! - an **IP literal** (`10.0.0.5`, `fd00::1`, `[fd00::1]`) with itself — no
//!   query is made; whether it may be connected to is the socket rules'
//!   business;
//! - an **allowlisted `net.wan` host name** (case-insensitive, an optional
//!   trailing dot) with exactly the addresses it was pinned to when the
//!   instance was created ([`crate::capability::PinnedName`]), so the guest
//!   connects to the addresses the rules accept even when the system
//!   resolver would now answer differently (round-robin, short TTLs);
//! - **every other name** with `name-unresolvable`, without asking anyone.
//!
//! With no `net.*` grant every lookup fails (`permanent-resolver-failure`),
//! as before. Lookups also stop when the grants behind them are revoked: an
//! allowlisted name needs a live `net.wan` grant, an IP literal any live
//! network grant.

use crate::capability::PinnedName;
use crate::state::HostState;
use std::net::IpAddr;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::bindings::sockets::ip_name_lookup::{
    Host, HostResolveAddressStream, ResolveAddressStream,
};
use wasmtime_wasi::p2::bindings::sockets::network::{self, ErrorCode, IpAddress, Network};
use wasmtime_wasi::p2::{DynPollable, SocketError};
use wasmtime_wasi::sockets::WasiSocketsView;

/// What a guest's name lookups may return (see the module docs).
#[derive(Debug, Clone, Default)]
pub(crate) struct NameLookup {
    /// Any `net.*` grant: lookups are answered at all.
    pub(crate) enabled: bool,
    /// The `net.wan` allowlist's names and their pinned addresses.
    pub(crate) pinned: Vec<PinnedName>,
    /// Liveness of the grants behind the lookups; `None` when the instance
    /// has no broker (then the grants it was built from stand).
    pub(crate) live: Option<crate::capability::NetLiveness>,
}

/// The lowercase form of a DNS name without its trailing dot, or `None`
/// when `name` is not a plausible host name.
fn normalise(name: &str) -> Option<String> {
    let n = name.strip_suffix('.').unwrap_or(name);
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    ok.then(|| n.to_ascii_lowercase())
}

/// An IP literal, with or without the brackets of an IPv6 URL host.
fn literal(name: &str) -> Option<IpAddr> {
    let bare = name
        .strip_prefix('[')
        .and_then(|n| n.strip_suffix(']'))
        .unwrap_or(name);
    bare.parse().ok()
}

impl NameLookup {
    /// The addresses `name` resolves to for this instance.
    pub(crate) fn answer(&self, name: &str) -> Result<Vec<IpAddr>, ErrorCode> {
        if !self.enabled {
            return Err(ErrorCode::PermanentResolverFailure);
        }
        if let Some(ip) = literal(name) {
            return match &self.live {
                Some(live) if !live.any_live() => Err(ErrorCode::PermanentResolverFailure),
                _ => Ok(vec![ip]),
            };
        }
        let Some(name) = normalise(name) else {
            return Err(ErrorCode::InvalidArgument);
        };
        let pinned = self.pinned.iter().find(|p| p.name == name);
        match (pinned, &self.live) {
            (Some(_), Some(live)) if !live.wan_live() => Err(ErrorCode::NameUnresolvable),
            (Some(p), _) if !p.addrs.is_empty() => Ok(p.addrs.clone()),
            _ => Err(ErrorCode::NameUnresolvable),
        }
    }
}

// `ip-name-lookup`'s host trait converts its errors through the
// `wasi:sockets/network` host trait; delegate that to wasmtime-wasi's own
// implementation (this impl links nothing).
impl network::Host for HostState {
    fn convert_error_code(&mut self, error: SocketError) -> wasmtime::Result<ErrorCode> {
        network::Host::convert_error_code(&mut self.sockets(), error)
    }

    fn network_error_code(
        &mut self,
        err: Resource<wasmtime::Error>,
    ) -> wasmtime::Result<Option<ErrorCode>> {
        network::Host::network_error_code(&mut self.sockets(), err)
    }
}

impl network::HostNetwork for HostState {
    fn drop(&mut self, this: Resource<Network>) -> wasmtime::Result<()> {
        network::HostNetwork::drop(&mut self.sockets(), this)
    }
}

impl Host for HostState {
    fn resolve_addresses(
        &mut self,
        network: Resource<Network>,
        name: String,
    ) -> Result<Resource<ResolveAddressStream>, SocketError> {
        // A valid network handle is still required, as in wasmtime-wasi.
        self.table.get(&network)?;
        let addrs = match self.lookup.answer(&name) {
            Ok(addrs) => addrs,
            Err(code) => {
                tracing::debug!(plugin = %self.plugin_id, name = %name, error = ?code, "guest name lookup refused");
                return Err(code.into());
            }
        };
        let addrs: Vec<IpAddress> = addrs.into_iter().map(IpAddress::from).collect();
        let stream = ResolveAddressStream::Done(Ok(addrs.into_iter()));
        Ok(self.table.push(stream)?)
    }
}

impl HostResolveAddressStream for HostState {
    fn resolve_next_address(
        &mut self,
        resource: Resource<ResolveAddressStream>,
    ) -> Result<Option<IpAddress>, SocketError> {
        match self.table.get_mut(&resource)? {
            ResolveAddressStream::Done(Ok(addrs)) => Ok(addrs.next()),
            ResolveAddressStream::Done(slot @ Err(_)) => {
                match std::mem::replace(slot, Ok(Vec::new().into_iter())) {
                    Err(e) => Err(e),
                    Ok(_) => Ok(None),
                }
            }
            // Never created here: every answer is known when the stream is.
            ResolveAddressStream::Waiting(_) => Err(ErrorCode::WouldBlock.into()),
        }
    }

    fn subscribe(
        &mut self,
        resource: Resource<ResolveAddressStream>,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        wasmtime_wasi::p2::subscribe(&mut self.table, resource)
    }

    fn drop(&mut self, resource: Resource<ResolveAddressStream>) -> wasmtime::Result<()> {
        self.table.delete(resource)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_normalised_and_literals_recognised() {
        assert_eq!(normalise("API.Example.com.").as_deref(), Some("api.example.com"));
        assert_eq!(normalise("a..b"), None);
        assert_eq!(normalise(""), None);
        assert_eq!(normalise("a b"), None);
        assert_eq!(literal("[fd00::1]"), Some("fd00::1".parse().unwrap()));
        assert_eq!(literal("10.0.0.5"), Some("10.0.0.5".parse().unwrap()));
        assert_eq!(literal("example.com"), None);
    }

    #[test]
    fn only_pinned_names_and_literals_are_answered() {
        let lookup = NameLookup {
            enabled: true,
            pinned: vec![PinnedName {
                name: "api.example.com".into(),
                addrs: vec!["8.8.8.8".parse().unwrap()],
            }],
            live: None,
        };
        assert_eq!(
            lookup.answer("Api.Example.Com."),
            Ok(vec!["8.8.8.8".parse().unwrap()])
        );
        assert_eq!(lookup.answer("10.1.2.3"), Ok(vec!["10.1.2.3".parse().unwrap()]));
        assert_eq!(lookup.answer("other.example.com"), Err(ErrorCode::NameUnresolvable));
        let off = NameLookup::default();
        assert_eq!(off.answer("10.1.2.3"), Err(ErrorCode::PermanentResolverFailure));
    }
}
