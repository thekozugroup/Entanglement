//! Network rules a wasm plugin's `net.*` grants realise (`wasi:sockets`).
//!
//! The wasm host enforces them through wasmtime-wasi's `socket_addr_check`,
//! which sees every address a guest binds, connects or sends to:
//!
//! - **`net.lan`** — destinations whose address is on the LAN:
//!   RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), IPv4 link-local
//!   (`169.254/16`), IPv6 unique-local (`fc00::/7`), IPv6 link-local
//!   (`fe80::/10`) and the deprecated site-local `fec0::/10`. **Loopback is
//!   not LAN**: a plugin never reaches the daemon's own services
//!   (`127.0.0.0/8`, `::1`) through a network grant.
//! - **`net.wan`** — destinations in the grant's allowlist only. Hostnames
//!   are resolved by the host when the instance is created (see
//!   [`crate::capability`]) and the instance may connect to exactly those
//!   addresses, on the listed port (or any port when the entry has none).
//!   An allowlisted name that resolves to a LAN, loopback or other
//!   non-public address is **not** reachable through `net.wan` (that is
//!   what DNS rebinding / SSRF would exploit); reaching LAN hosts needs
//!   `net.lan`.
//! - Everything else is refused: unspecified, multicast, broadcast,
//!   CGNAT (`100.64/10`), documentation and other special-purpose ranges.
//!   IPv4-mapped (`::ffff:a.b.c.d`) and NAT64 (`64:ff9b::/96`) IPv6
//!   addresses are judged by the IPv4 address they carry, so they cannot
//!   smuggle a loopback or LAN destination past the rules.
//!
//! Plugins are clients: a TCP `bind` (listening) is always refused; a UDP
//! socket may bind only an ephemeral port on the unspecified address, which
//! WASI requires before sending.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use wasmtime_wasi::sockets::SocketAddrUse;

/// How the network rules classify a destination address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrClass {
    /// `127.0.0.0/8`, `::1`. Never reachable through a network grant.
    Loopback,
    /// RFC 1918, link-local, unique-local: reachable with `net.lan`.
    Lan,
    /// Globally routable unicast: reachable with `net.wan` when allowlisted.
    Wan,
    /// Unspecified, multicast, broadcast, CGNAT, documentation and other
    /// special-purpose ranges: never reachable.
    Other,
}

/// The function the rules use to classify an address. Production always
/// uses [`classify`]; see
/// [`CapabilityContext::with_address_classifier`](crate::capability::CapabilityContext::with_address_classifier).
pub type Classifier = fn(IpAddr) -> AddrClass;

/// Strip IPv4-mapped (`::ffff:a.b.c.d`) and NAT64 (`64:ff9b::a.b.c.d`)
/// IPv6 addresses down to the IPv4 address they carry.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let s = v6.segments();
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [a, b] = s[6].to_be_bytes();
                let [c, d] = s[7].to_be_bytes();
                return IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            }
            IpAddr::V6(v6)
        }
        v4 => v4,
    }
}

/// The production address classification (see the module docs).
pub fn classify(ip: IpAddr) -> AddrClass {
    match canonical(ip) {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    if ip.is_loopback() {
        return AddrClass::Loopback;
    }
    const LAN: &[([u8; 4], u32)] = &[
        ([10, 0, 0, 0], 8),
        ([172, 16, 0, 0], 12),
        ([192, 168, 0, 0], 16),
        ([169, 254, 0, 0], 16),
    ];
    if LAN.iter().any(|(n, p)| in_v4(ip, *n, *p)) {
        return AddrClass::Lan;
    }
    const SPECIAL: &[([u8; 4], u32)] = &[
        ([0, 0, 0, 0], 8),       // "this network", unspecified
        ([100, 64, 0, 0], 10),   // CGNAT shared address space
        ([192, 0, 0, 0], 24),    // IETF protocol assignments
        ([192, 0, 2, 0], 24),    // TEST-NET-1
        ([198, 18, 0, 0], 15),   // benchmarking
        ([198, 51, 100, 0], 24), // TEST-NET-2
        ([203, 0, 113, 0], 24),  // TEST-NET-3
        ([224, 0, 0, 0], 4),     // multicast
        ([240, 0, 0, 0], 4),     // reserved + broadcast
    ];
    if SPECIAL.iter().any(|(n, p)| in_v4(ip, *n, *p)) {
        return AddrClass::Other;
    }
    AddrClass::Wan
}

fn in_v6(ip: Ipv6Addr, net: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    if ip.is_loopback() {
        return AddrClass::Loopback;
    }
    if ip.is_unspecified() {
        return AddrClass::Other;
    }
    const LAN: &[(Ipv6Addr, u32)] = &[
        (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7), // unique local
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10), // link-local
        (Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10), // site-local (deprecated)
    ];
    if LAN.iter().any(|(n, p)| in_v6(ip, *n, *p)) {
        return AddrClass::Lan;
    }
    const SPECIAL: &[(Ipv6Addr, u32)] = &[
        (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 96), // IPv4-compatible (deprecated)
        (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64), // discard-only
        (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32), // documentation
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8), // multicast
    ];
    if SPECIAL.iter().any(|(n, p)| in_v6(ip, *n, *p)) {
        return AddrClass::Other;
    }
    AddrClass::Wan
}

/// One resolved `net.wan` allowlist entry: an exact address and an optional
/// port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WanTarget {
    /// The allowed address (canonical form, see [`canonical`]).
    pub ip: IpAddr,
    /// The allowed port; `None` allows every port.
    pub port: Option<u16>,
}

/// The socket rules realised from a plugin's `net.*` grants.
#[derive(Debug, Clone)]
pub struct NetRules {
    /// `net.lan` granted.
    pub lan: bool,
    /// `net.wan` granted (even if no allowlisted name resolved).
    pub wan: bool,
    /// The resolved `net.wan` allowlist.
    pub wan_targets: Vec<WanTarget>,
    /// Address classification; [`classify`] outside tests.
    pub classify: Classifier,
}

impl Default for NetRules {
    fn default() -> Self {
        Self {
            lan: false,
            wan: false,
            wan_targets: Vec::new(),
            classify,
        }
    }
}

/// Which grant justified an allowed socket address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// Allowed by `net.lan`.
    Lan,
    /// Allowed by `net.wan`.
    Wan,
    /// A local ephemeral UDP bind, needed by either grant.
    LocalBind,
}

impl NetRules {
    /// `true` when any network grant exists: TCP, UDP and DNS are enabled
    /// only then.
    pub fn any(&self) -> bool {
        self.lan || self.wan
    }

    /// Decide one socket use. `Some(via)` names the grant that allows it;
    /// `None` refuses it.
    pub fn check(&self, addr: SocketAddr, use_: SocketAddrUse) -> Option<Via> {
        if !self.any() {
            return None;
        }
        match use_ {
            // Plugins are clients: no listening sockets.
            SocketAddrUse::TcpBind => None,
            // WASI requires an explicit UDP bind before sending; allow only
            // an ephemeral port on the unspecified address.
            SocketAddrUse::UdpBind => {
                (addr.ip().is_unspecified() && addr.port() == 0).then_some(Via::LocalBind)
            }
            SocketAddrUse::TcpConnect
            | SocketAddrUse::UdpConnect
            | SocketAddrUse::UdpOutgoingDatagram => {
                if addr.port() == 0 {
                    return None;
                }
                let ip = canonical(addr.ip());
                match (self.classify)(ip) {
                    AddrClass::Lan if self.lan => Some(Via::Lan),
                    AddrClass::Wan if self.wan => self
                        .wan_targets
                        .iter()
                        .any(|t| t.ip == ip && t.port.is_none_or(|p| p == addr.port()))
                        .then_some(Via::Wan),
                    _ => None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classification_table() {
        let cases: &[(&str, AddrClass)] = &[
            ("127.0.0.1", AddrClass::Loopback),
            ("127.255.255.254", AddrClass::Loopback),
            ("::1", AddrClass::Loopback),
            ("::ffff:127.0.0.1", AddrClass::Loopback),
            ("64:ff9b::7f00:1", AddrClass::Loopback),
            ("10.0.0.1", AddrClass::Lan),
            ("10.255.255.255", AddrClass::Lan),
            ("172.16.0.1", AddrClass::Lan),
            ("172.31.255.254", AddrClass::Lan),
            ("192.168.1.10", AddrClass::Lan),
            ("169.254.10.10", AddrClass::Lan),
            ("fd12:3456::1", AddrClass::Lan),
            ("fc00::1", AddrClass::Lan),
            ("fe80::1", AddrClass::Lan),
            ("::ffff:192.168.1.10", AddrClass::Lan),
            ("64:ff9b::a00:1", AddrClass::Lan),
            ("172.15.255.255", AddrClass::Wan),
            ("172.32.0.1", AddrClass::Wan),
            ("8.8.8.8", AddrClass::Wan),
            ("1.1.1.1", AddrClass::Wan),
            ("2606:4700:4700::1111", AddrClass::Wan),
            ("::ffff:8.8.8.8", AddrClass::Wan),
            ("0.0.0.0", AddrClass::Other),
            ("::", AddrClass::Other),
            ("100.64.0.1", AddrClass::Other),
            ("100.100.100.100", AddrClass::Other),
            ("203.0.113.5", AddrClass::Other),
            ("198.51.100.5", AddrClass::Other),
            ("192.0.2.5", AddrClass::Other),
            ("224.0.0.251", AddrClass::Other),
            ("255.255.255.255", AddrClass::Other),
            ("ff02::fb", AddrClass::Other),
            ("2001:db8::1", AddrClass::Other),
            ("::10.0.0.1", AddrClass::Other),
        ];
        for (addr, want) in cases {
            assert_eq!(classify(ip(addr)), *want, "{addr}");
        }
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn no_grant_refuses_everything() {
        let r = NetRules::default();
        for (a, u) in [
            ("10.0.0.1:80", SocketAddrUse::TcpConnect),
            ("0.0.0.0:0", SocketAddrUse::UdpBind),
            ("8.8.8.8:53", SocketAddrUse::UdpOutgoingDatagram),
        ] {
            assert_eq!(r.check(sa(a), u), None, "{a}");
        }
    }

    #[test]
    fn lan_grant_allows_lan_only_and_never_loopback() {
        let r = NetRules {
            lan: true,
            ..NetRules::default()
        };
        let connect = SocketAddrUse::TcpConnect;
        assert_eq!(r.check(sa("192.168.1.2:22"), connect), Some(Via::Lan));
        assert_eq!(r.check(sa("[fe80::1]:22"), connect), Some(Via::Lan));
        assert_eq!(
            r.check(sa("10.1.2.3:53"), SocketAddrUse::UdpOutgoingDatagram),
            Some(Via::Lan)
        );
        for a in [
            "127.0.0.1:80",
            "[::1]:80",
            "[::ffff:127.0.0.1]:80",
            "8.8.8.8:53",
            "203.0.113.1:80",
            "100.100.100.100:53",
            "192.168.1.2:0",
        ] {
            assert_eq!(r.check(sa(a), connect), None, "{a}");
        }
        // Clients only.
        assert_eq!(r.check(sa("0.0.0.0:8080"), SocketAddrUse::TcpBind), None);
        assert_eq!(r.check(sa("0.0.0.0:0"), SocketAddrUse::TcpBind), None);
        assert_eq!(
            r.check(sa("0.0.0.0:0"), SocketAddrUse::UdpBind),
            Some(Via::LocalBind)
        );
        assert_eq!(r.check(sa("0.0.0.0:5353"), SocketAddrUse::UdpBind), None);
        assert_eq!(r.check(sa("192.168.1.9:0"), SocketAddrUse::UdpBind), None);
    }

    #[test]
    fn wan_grant_allows_exactly_the_allowlist() {
        let r = NetRules {
            wan: true,
            wan_targets: vec![
                WanTarget {
                    ip: ip("8.8.8.8"),
                    port: Some(443),
                },
                WanTarget {
                    ip: ip("2606:4700:4700::1111"),
                    port: None,
                },
            ],
            ..NetRules::default()
        };
        let c = SocketAddrUse::TcpConnect;
        assert_eq!(r.check(sa("8.8.8.8:443"), c), Some(Via::Wan));
        assert_eq!(r.check(sa("[::ffff:8.8.8.8]:443"), c), Some(Via::Wan));
        assert_eq!(r.check(sa("8.8.8.8:80"), c), None);
        assert_eq!(r.check(sa("8.8.4.4:443"), c), None);
        assert_eq!(r.check(sa("[2606:4700:4700::1111]:853"), c), Some(Via::Wan));
        // No LAN through a WAN grant, even if (hypothetically) allowlisted.
        let r = NetRules {
            wan: true,
            wan_targets: vec![WanTarget {
                ip: ip("10.0.0.5"),
                port: None,
            }],
            ..NetRules::default()
        };
        assert_eq!(r.check(sa("10.0.0.5:443"), c), None);
    }
}
