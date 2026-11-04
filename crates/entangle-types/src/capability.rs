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
    /// `net.wan` — open connections to WAN/internet hosts.
    NetWan,
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
    /// | `NetWan`              | `Networked` (3)|
    /// | `MeshPeer`            | `Privileged` (4)|
    /// | `AgentInvoke`         | `Sandboxed` (2)|
    /// | `HostDockerSocket`    | `Native` (5)   |
    /// | `Custom`              | `Pure` (1)     |
    pub fn min_tier(&self) -> Tier {
        match self {
            CapabilityKind::ComputeCpu => Tier::Sandboxed,
            CapabilityKind::ComputeGpu => Tier::Networked,
            CapabilityKind::ComputeNpu => Tier::Networked,
            CapabilityKind::StorageLocal { scope } => match scope {
                StorageScope::Plugin => Tier::Pure,
                StorageScope::Shared => Tier::Sandboxed,
            },
            CapabilityKind::StorageShare { .. } => Tier::Privileged,
            CapabilityKind::NetLan => Tier::Networked,
            CapabilityKind::NetWan => Tier::Networked,
            CapabilityKind::MeshPeer => Tier::Privileged,
            CapabilityKind::AgentInvoke => Tier::Sandboxed,
            CapabilityKind::HostDockerSocket => Tier::Native,
            CapabilityKind::Custom(_) => Tier::Pure,
        }
    }

    /// Standard capability-surface variants in canonical order.
    ///
    /// Useful for `entangle perms list` and documentation pages that enumerate
    /// every well-known capability. Does **not** include the `Custom(_)`
    /// variant or parameterised variants (`StorageLocal`, `StorageShare`).
    pub fn standard_variants() -> &'static [CapabilityKind] {
        const VARIANTS: &[CapabilityKind] = &[
            CapabilityKind::ComputeCpu,
            CapabilityKind::ComputeGpu,
            CapabilityKind::ComputeNpu,
            CapabilityKind::NetLan,
            CapabilityKind::NetWan,
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
                scope: StorageScope::Plugin
            }
            .min_tier(),
            Tier::Pure
        );
    }

    #[test]
    fn storage_local_shared_requires_sandboxed() {
        assert_eq!(
            CapabilityKind::StorageLocal {
                scope: StorageScope::Shared
            }
            .min_tier(),
            Tier::Sandboxed
        );
    }

    #[test]
    fn net_wan_requires_networked() {
        assert_eq!(CapabilityKind::NetWan.min_tier(), Tier::Networked);
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
