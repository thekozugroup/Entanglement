//! Capability kinds and their minimum required tier.
//!
//! Each variant maps to a surface in the Entanglement capability namespace:
//! `compute.cpu`, `compute.gpu`, `compute.npu`, `storage.local`,
//! `storage.share.<name>`, `net.lan`, `net.wan`, `mesh.peer`,
//! `agent.invoke`, `host.docker-socket`, plus an open-ended `Custom` variant.
//!
//! # §4.3 Tier ↔ capability binding
//! Every capability implies a minimum tier. A plugin manifest that declares a
//! capability but a tier lower than the implied minimum is rejected with
//! `ENTANGLE-E0042`.

use crate::tier::Tier;

/// Scope of a local-storage capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageScope {
    /// Isolated to the plugin's own data directory.
    Plugin,
    /// Shared across plugins that declare the same scope.
    Shared,
}

/// Access mode for plugin-local storage (`storage.local { mode = "ro" | "rw" }`).
///
/// Defaults to [`StorageMode::Rw`]: a plugin's own data directory is
/// writable unless the manifest narrows it.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum StorageMode {
    /// Read-only access.
    Ro,
    /// Read-write access.
    #[default]
    Rw,
}

/// Access mode for a shared-storage capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShareMode {
    /// Read-only access.
    Ro,
    /// Read-write access.
    Rw,
    /// Read-write access scoped to the requesting plugin's namespace.
    RwScoped,
}

/// Returns `true` if `s` is a valid `storage.share.<name>` name:
/// `^[a-z0-9][a-z0-9_-]{0,62}$`.
///
/// A share name becomes exactly one directory under the daemon's
/// `<data>/shares` (and the suffix of `ENTANGLE_SHARE_<NAME>`), so it must be
/// a single plain path component: no separator, no `.`/`..`, never empty or
/// absolute. Otherwise `"storage.share./"` would name the filesystem root and
/// `"storage.share.../.."` the daemon's own configuration directory.
pub fn is_valid_share_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// One entry of a `net.wan` allowlist: `host[:port]`.
///
/// `host` is a DNS name (lowercased; labels of `[a-z0-9-]`), an IPv4
/// literal, an IPv6 literal (bracketed when a port follows:
/// `[2001:db8::1]:443`), or a wildcard: `*` (any host) or `*.<dns name>`
/// (any subdomain). Without a port, every port of that host is allowed.
/// Wildcards are a tier-4 authority (§4.2) — see
/// [`CapabilityKind::min_tier`].
///
/// Serialises as its `host[:port]` string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetHost {
    host: String,
    port: Option<u16>,
}

/// A `net.wan` allowlist entry that is not `host[:port]`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid host entry {input:?}: {reason}")]
pub struct NetHostError {
    /// The rejected entry.
    pub input: String,
    /// Why it was rejected.
    pub reason: String,
}

impl NetHost {
    /// The wildcard entry `*`: any host, any port.
    pub fn any() -> Self {
        Self {
            host: "*".to_owned(),
            port: None,
        }
    }

    /// The host part: a lowercase DNS name, an IP literal (IPv6 without
    /// brackets), `*` or `*.<dns name>`.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, or `None` for every port.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// `true` for `*` and `*.<dns name>` entries.
    pub fn is_wildcard(&self) -> bool {
        self.host.starts_with('*')
    }

    /// The host as an IP address, when it is an IP literal.
    pub fn ip(&self) -> Option<std::net::IpAddr> {
        self.host.parse().ok()
    }

    /// `true` when this entry allows `port`.
    pub fn allows_port(&self, port: u16) -> bool {
        self.port.is_none_or(|p| p == port)
    }
}

/// `true` for a DNS name of LDH labels (`[a-z0-9-]`, 1–63 characters, no
/// leading or trailing `-`), at most 253 characters, no empty label.
fn is_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

impl std::str::FromStr for NetHost {
    type Err = NetHostError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let err = |reason: &str| NetHostError {
            input: input.to_owned(),
            reason: reason.to_owned(),
        };
        let parse_port = |p: &str| -> Result<u16, NetHostError> {
            match p.parse::<u16>() {
                Ok(0) | Err(_) => Err(err("port must be a number in 1..=65535")),
                Ok(n) => Ok(n),
            }
        };
        // `[v6]` or `[v6]:port`.
        if let Some(rest) = input.strip_prefix('[') {
            let (addr, after) = rest
                .split_once(']')
                .ok_or_else(|| err("unterminated `[` in IPv6 literal"))?;
            let v6: std::net::Ipv6Addr = addr
                .parse()
                .map_err(|_| err("bracketed host must be an IPv6 address"))?;
            let port = match after {
                "" => None,
                p => Some(parse_port(
                    p.strip_prefix(':')
                        .ok_or_else(|| err("expected `:port` after `]`"))?,
                )?),
            };
            return Ok(Self {
                host: v6.to_string(),
                port,
            });
        }
        // A bare IPv6 address (several `:`) carries no port.
        if let Ok(v6) = input.parse::<std::net::Ipv6Addr>() {
            return Ok(Self {
                host: v6.to_string(),
                port: None,
            });
        }
        let (host, port) = match input.split_once(':') {
            Some((h, p)) => (h, Some(parse_port(p)?)),
            None => (input, None),
        };
        if host.is_empty() {
            return Err(err("empty host"));
        }
        if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
            return Ok(Self {
                host: v4.to_string(),
                port,
            });
        }
        let lower = host.to_ascii_lowercase();
        let valid = match lower.strip_prefix('*') {
            Some("") => true,
            Some(rest) => rest.strip_prefix('.').is_some_and(is_dns_name),
            None => is_dns_name(&lower),
        };
        if !valid {
            return Err(err(
                "host must be a DNS name, an IP address, `*`, or `*.<dns name>`",
            ));
        }
        Ok(Self { host: lower, port })
    }
}

impl std::fmt::Display for NetHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.host.contains(':'), self.port) {
            (true, Some(p)) => write!(f, "[{}]:{p}", self.host),
            (true, None) => write!(f, "[{}]", self.host),
            (false, Some(p)) => write!(f, "{}:{p}", self.host),
            (false, None) => f.write_str(&self.host),
        }
    }
}

impl serde::Serialize for NetHost {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for NetHost {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// All capability surfaces available in the Entanglement architecture.
///
/// # §4.3 Tier ↔ capability binding
/// Call [`CapabilityKind::min_tier`] to retrieve the minimum tier a plugin
/// must declare in order to be granted this capability.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CapabilityKind {
    /// `compute.cpu` — use host CPU cores.
    ComputeCpu,
    /// `compute.gpu` — use a host GPU via Metal, CUDA, Vulkan, or ROCm.
    ComputeGpu,
    /// `compute.npu` — use a dedicated neural processing unit.
    ComputeNpu,
    /// `storage.local` — access the local filesystem within a defined scope.
    StorageLocal {
        /// Whether access is plugin-private or shared.
        scope: StorageScope,
        /// Read-only or read-write.
        #[serde(default)]
        mode: StorageMode,
    },
    /// `storage.share.<name>` — access a named shared volume.
    StorageShare {
        /// The volume name; see [`is_valid_share_name`] (enforced when a
        /// manifest is validated and again before a native scope is derived).
        name: String,
        /// Read/write mode.
        mode: ShareMode,
    },
    /// `net.lan` — open connections to LAN hosts.
    NetLan,
    /// `net.wan` — open connections to the WAN/internet hosts in `hosts`.
    ///
    /// A [wildcard](NetHost::is_wildcard) entry (or a manifest that lists no
    /// hosts at all, which validation turns into `*`) raises the minimum tier
    /// to [`Tier::Privileged`] (§4.2: "WAN egress wildcards" are tier 4).
    NetWan {
        /// The allowlist; see [`NetHost`].
        hosts: Vec<NetHost>,
    },
    /// `mesh.peer` — send messages to other peers in the Entanglement mesh.
    MeshPeer,
    /// `agent.invoke` — invoke another agent or plugin.
    AgentInvoke,
    /// `host.docker-socket` — bind-mount and use `/var/run/docker.sock`.
    HostDockerSocket,
    /// An open-ended capability not covered by the standard set.
    Custom(String),
}

impl CapabilityKind {
    /// Returns the minimum [`Tier`] a plugin must declare to be granted this capability.
    ///
    /// # §4.3 Tier ↔ capability binding
    /// | Capability            | Min tier       |
    /// |-----------------------|----------------|
    /// | `ComputeCpu`          | `Sandboxed` (2)|
    /// | `ComputeGpu`          | `Networked` (3)|
    /// | `ComputeNpu`          | `Networked` (3)|
    /// | `StorageLocal(Plugin)`| `Pure` (1)     |
    /// | `StorageLocal(Shared)`| `Sandboxed` (2)|
    /// | `StorageShare`        | `Privileged` (4)|
    /// | `NetLan`              | `Networked` (3)|
    /// | `NetWan` (named hosts)| `Networked` (3)|
    /// | `NetWan` (wildcard)   | `Privileged` (4)|
    /// | `MeshPeer`            | `Privileged` (4)|
    /// | `AgentInvoke`         | `Sandboxed` (2)|
    /// | `HostDockerSocket`    | `Native` (5)   |
    /// | `Custom`              | `Pure` (1)     |
    pub fn min_tier(&self) -> Tier {
        match self {
            CapabilityKind::ComputeCpu => Tier::Sandboxed,
            CapabilityKind::ComputeGpu => Tier::Networked,
            CapabilityKind::ComputeNpu => Tier::Networked,
            CapabilityKind::StorageLocal { scope, .. } => match scope {
                StorageScope::Plugin => Tier::Pure,
                StorageScope::Shared => Tier::Sandboxed,
            },
            CapabilityKind::StorageShare { .. } => Tier::Privileged,
            CapabilityKind::NetLan => Tier::Networked,
            CapabilityKind::NetWan { hosts } => {
                if hosts.iter().any(NetHost::is_wildcard) {
                    Tier::Privileged
                } else {
                    Tier::Networked
                }
            }
            CapabilityKind::MeshPeer => Tier::Privileged,
            CapabilityKind::AgentInvoke => Tier::Sandboxed,
            CapabilityKind::HostDockerSocket => Tier::Native,
            CapabilityKind::Custom(_) => Tier::Pure,
        }
    }

    /// The manifest key that declares this capability: `compute.cpu`,
    /// `storage.local`, `storage.share.<name>`, `net.wan`, `custom.<x>`, ...
    ///
    /// Parameters (scope, mode, hosts) are not part of the key; a manifest
    /// declares each key at most once, so the key names exactly one declared
    /// capability. This is what `capability.fetch(kind, name)` resolves to and
    /// what operator policy patterns (`[security] deny_capabilities`) match.
    pub fn key(&self) -> std::borrow::Cow<'static, str> {
        use std::borrow::Cow;
        match self {
            CapabilityKind::StorageShare { name, .. } => {
                Cow::Owned(format!("storage.share.{name}"))
            }
            CapabilityKind::Custom(s) if s.starts_with("custom.") => Cow::Owned(s.clone()),
            CapabilityKind::Custom(s) => Cow::Owned(format!("custom.{s}")),
            other => Cow::Borrowed(other.family()),
        }
    }

    /// The fixed-cardinality family name: [`CapabilityKind::key`] without
    /// the share name or custom suffix (`storage.share`, `custom`). Used as a
    /// metric label, where a plugin must not be able to mint new values.
    pub fn family(&self) -> &'static str {
        match self {
            CapabilityKind::ComputeCpu => "compute.cpu",
            CapabilityKind::ComputeGpu => "compute.gpu",
            CapabilityKind::ComputeNpu => "compute.npu",
            CapabilityKind::StorageLocal { .. } => "storage.local",
            CapabilityKind::StorageShare { .. } => "storage.share",
            CapabilityKind::NetLan => "net.lan",
            CapabilityKind::NetWan { .. } => "net.wan",
            CapabilityKind::MeshPeer => "mesh.peer",
            CapabilityKind::AgentInvoke => "agent.invoke",
            CapabilityKind::HostDockerSocket => "host.docker-socket",
            CapabilityKind::Custom(_) => "custom",
        }
    }

    /// Human-readable parameters, e.g. `scope=plugin mode=ro` or
    /// `hosts=api.example.com:443`; empty for parameterless capabilities.
    pub fn params(&self) -> String {
        match self {
            CapabilityKind::StorageLocal { scope, mode } => {
                let scope = match scope {
                    StorageScope::Plugin => "plugin",
                    StorageScope::Shared => "shared",
                };
                let mode = match mode {
                    StorageMode::Ro => "ro",
                    StorageMode::Rw => "rw",
                };
                format!("scope={scope} mode={mode}")
            }
            CapabilityKind::StorageShare { mode, .. } => {
                let mode = match mode {
                    ShareMode::Ro => "ro",
                    ShareMode::Rw => "rw",
                    ShareMode::RwScoped => "rw-scoped",
                };
                format!("mode={mode}")
            }
            CapabilityKind::NetWan { hosts } => {
                let hosts: Vec<String> = hosts.iter().map(ToString::to_string).collect();
                format!("hosts={}", hosts.join(","))
            }
            _ => String::new(),
        }
    }

    /// Standard capability-surface variants in canonical order.
    ///
    /// Useful for `entangle perms list` and documentation pages that enumerate
    /// every well-known capability. Does **not** include the `Custom(_)`
    /// variant or parameterised variants (`StorageLocal`, `StorageShare`,
    /// `NetWan`).
    pub fn standard_variants() -> &'static [CapabilityKind] {
        const VARIANTS: &[CapabilityKind] = &[
            CapabilityKind::ComputeCpu,
            CapabilityKind::ComputeGpu,
            CapabilityKind::ComputeNpu,
            CapabilityKind::NetLan,
            CapabilityKind::MeshPeer,
            CapabilityKind::AgentInvoke,
            CapabilityKind::HostDockerSocket,
        ];
        VARIANTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_variants_round_trips_min_tier() {
        let all = CapabilityKind::standard_variants();
        assert!(all.len() >= 7, "missing standard variants: {all:?}");
        for v in all {
            // every variant has a known min_tier
            let _ = v.min_tier();
        }
    }

    #[test]
    fn standard_variants_includes_docker_socket_native_tier() {
        let docker = CapabilityKind::standard_variants()
            .iter()
            .find(|v| matches!(v, CapabilityKind::HostDockerSocket))
            .expect("HostDockerSocket must be in standard_variants");
        assert_eq!(docker.min_tier(), Tier::Native);
    }

    #[test]
    fn share_names_are_one_plain_path_component() {
        for ok in [
            "photos",
            "a",
            "0",
            "my-share",
            "my_share",
            "s3",
            &"a".repeat(63),
        ] {
            assert!(is_valid_share_name(ok), "{ok:?}");
        }
        for bad in [
            "",
            "/",
            "/etc",
            ".",
            "..",
            "../..",
            "a/b",
            "a\\b",
            "-a",
            "_a",
            "Photos",
            "a b",
            "a.b",
            "é",
            &"a".repeat(64),
        ] {
            assert!(!is_valid_share_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn host_docker_socket_requires_native() {
        assert_eq!(CapabilityKind::HostDockerSocket.min_tier(), Tier::Native);
    }

    #[test]
    fn compute_cpu_requires_sandboxed() {
        assert_eq!(CapabilityKind::ComputeCpu.min_tier(), Tier::Sandboxed);
    }

    #[test]
    fn compute_gpu_requires_networked() {
        assert_eq!(CapabilityKind::ComputeGpu.min_tier(), Tier::Networked);
    }

    #[test]
    fn storage_local_plugin_requires_pure() {
        assert_eq!(
            CapabilityKind::StorageLocal {
                scope: StorageScope::Plugin,
                mode: StorageMode::Ro,
            }
            .min_tier(),
            Tier::Pure
        );
    }

    #[test]
    fn storage_local_shared_requires_sandboxed() {
        assert_eq!(
            CapabilityKind::StorageLocal {
                scope: StorageScope::Shared,
                mode: StorageMode::Rw,
            }
            .min_tier(),
            Tier::Sandboxed
        );
    }

    #[test]
    fn net_wan_requires_networked() {
        let named = CapabilityKind::NetWan {
            hosts: vec!["api.example.com:443".parse().unwrap()],
        };
        assert_eq!(named.min_tier(), Tier::Networked);
    }

    /// §4.2: WAN egress wildcards are a tier-4 authority, so a wildcard
    /// anywhere in the allowlist raises the implied tier.
    #[test]
    fn net_wan_wildcard_requires_privileged() {
        for wild in ["*", "*.example.com", "*:443"] {
            let cap = CapabilityKind::NetWan {
                hosts: vec![
                    "api.example.com:443".parse().unwrap(),
                    wild.parse().unwrap(),
                ],
            };
            assert_eq!(cap.min_tier(), Tier::Privileged, "{wild}");
        }
    }

    #[test]
    fn keys_and_families() {
        let share = CapabilityKind::StorageShare {
            name: "photos".into(),
            mode: ShareMode::Ro,
        };
        assert_eq!(share.key(), "storage.share.photos");
        assert_eq!(share.family(), "storage.share");
        assert_eq!(CapabilityKind::Custom("custom.x".into()).key(), "custom.x");
        assert_eq!(CapabilityKind::Custom("x".into()).key(), "custom.x");
        assert_eq!(CapabilityKind::Custom("x".into()).family(), "custom");
        assert_eq!(CapabilityKind::NetWan { hosts: vec![] }.key(), "net.wan");
        let local = CapabilityKind::StorageLocal {
            scope: StorageScope::Plugin,
            mode: StorageMode::Ro,
        };
        assert_eq!(local.key(), "storage.local");
        assert_eq!(local.params(), "scope=plugin mode=ro");
    }

    #[test]
    fn net_host_parses_host_port_forms() {
        let ok: &[(&str, &str, Option<u16>)] = &[
            ("api.example.com:443", "api.example.com", Some(443)),
            ("API.Example.COM", "api.example.com", None),
            ("example.org", "example.org", None),
            ("localhost:8080", "localhost", Some(8080)),
            ("203.0.113.7:80", "203.0.113.7", Some(80)),
            ("203.0.113.7", "203.0.113.7", None),
            ("[2001:db8::1]:443", "2001:db8::1", Some(443)),
            ("[2001:db8::1]", "2001:db8::1", None),
            ("2001:db8::1", "2001:db8::1", None),
            ("*", "*", None),
            ("*.example.com:443", "*.example.com", Some(443)),
            ("*:443", "*", Some(443)),
            ("xn--bcher-kva.example", "xn--bcher-kva.example", None),
        ];
        for (input, host, port) in ok {
            let h: NetHost = input.parse().unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(h.host(), *host, "{input}");
            assert_eq!(h.port(), *port, "{input}");
            // Display round-trips.
            let again: NetHost = h.to_string().parse().unwrap();
            assert_eq!(again, h, "{input}");
        }
        assert!("*".parse::<NetHost>().unwrap().is_wildcard());
        assert!("*.example.com".parse::<NetHost>().unwrap().is_wildcard());
        assert!(!"example.com".parse::<NetHost>().unwrap().is_wildcard());
        assert_eq!(
            "[2001:db8::1]:443".parse::<NetHost>().unwrap().ip(),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn net_host_rejects_malformed_entries() {
        for bad in [
            "",
            ":443",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:http",
            "http://example.com",
            "example.com/path",
            "user@example.com",
            "exa mple.com",
            "-example.com",
            "example-.com",
            "example..com",
            ".example.com",
            "example.com.",
            "a*.example.com",
            "*example.com",
            "ex*ample.com",
            "**",
            "*.*.example.com",
            "[2001:db8::1",
            "[not-an-ip]:80",
            "[203.0.113.7]:80",
            "under_score.example",
            &format!("{}.com", "a".repeat(64)),
        ] {
            assert!(bad.parse::<NetHost>().is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn mesh_peer_requires_privileged() {
        assert_eq!(CapabilityKind::MeshPeer.min_tier(), Tier::Privileged);
    }

    #[test]
    fn custom_requires_pure() {
        assert_eq!(CapabilityKind::Custom("x".into()).min_tier(), Tier::Pure);
    }
}
