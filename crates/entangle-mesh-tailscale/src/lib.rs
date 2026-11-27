//! Read-only discovery through the operator's Tailscale installation.
//!
//! Each status request queries the local daemon via `tailscale status --json`.
//! Nodes describe tailnet reachability. Pairing and capability checks establish
//! Entanglement identity and authorization independently.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use entangle_types::peer_id::PeerId;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

const STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_STATUS_BYTES: usize = 16 * 1024 * 1024;

/// Operator policy for layering Entanglement's own ACLs on top of the tailnet.
/// Discovery only reports addresses, regardless of the selected policy.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum AclMode {
    /// Entanglement enforces its own peer allowlist on top of Tailscale ACLs.
    #[default]
    EntangleOnTop,
    /// Delegate network reachability policy to Tailscale.
    TrustTailnet,
}

/// Configuration for tailnet discovery.
#[derive(Clone, Debug, Default)]
pub struct MeshTailscaleConfig {
    /// Path to the `tailscale` CLI. Empty = use `$PATH`.
    pub tailscale_cli: String,
    /// ACL layering policy.
    pub acl_mode: AclMode,
}

impl MeshTailscaleConfig {
    /// Resolve the configured CLI path, falling back to the OS's command lookup.
    pub fn resolve_cli(&self) -> &str {
        if self.tailscale_cli.is_empty() {
            "tailscale"
        } else {
            self.tailscale_cli.as_str()
        }
    }
}

/// Failures querying or interpreting local Tailscale status.
#[derive(Debug, thiserror::Error)]
pub enum MeshTailscaleError {
    /// The selected executable could not be found.
    #[error("ENTANGLE-E0641: tailscale CLI executable not found")]
    NotInstalled,
    /// The process could not start or its result could not be read.
    #[error("unable to run tailscale status: {0}")]
    Io(#[source] io::Error),
    /// The CLI returned a failure status.
    #[error("tailscale status failed with {0}")]
    CommandFailed(ExitStatus),
    /// The CLI failed to finish within the time budget.
    #[error("tailscale status timed out")]
    Timeout,
    /// The CLI exceeded the output size limit.
    #[error("tailscale status exceeded the {MAX_STATUS_BYTES}-byte limit")]
    OutputTooLarge,
    /// Status output was invalid.
    #[error("invalid tailscale status JSON: {0}")]
    InvalidStatus(#[from] serde_json::Error),
    /// The daemon has no active tailnet connection.
    #[error("tailscale is unavailable (backend state {0})")]
    Inactive(String),
}

/// An Entanglement peer associated with a MagicDNS hostname after pairing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailscalePeer {
    /// Entanglement peer id (Ed25519 public-key bytes).
    pub peer_id: PeerId,
    /// MagicDNS hostname (e.g. `bob-desktop.tail-scale.ts.net`).
    pub magic_dns: String,
}

/// A visible Tailscale node. It can be offline or run no Entanglement service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TailnetNode {
    /// Tailscale's stable node ID, scoped to this tailnet.
    pub node_id: String,
    /// Hostname reported by the remote device.
    pub hostname: String,
    /// MagicDNS hostname without its trailing dot, or empty if unavailable.
    pub magic_dns: String,
    /// IP addresses assigned by the tailnet.
    pub ips: Vec<IpAddr>,
    /// The local daemon's last reported online flag for this node.
    pub online: bool,
}

/// Snapshot of the local Tailscale backend and the peers visible to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TailnetStatus {
    /// Tailscale's backend state (for example `Running` or `NeedsLogin`).
    pub backend_state: String,
    /// Local node online flag reported by Tailscale.
    pub local_online: bool,
    /// Local addresses assigned by the tailnet.
    pub local_ips: Vec<IpAddr>,
    /// MagicDNS suffix, or empty if unavailable.
    pub dns_suffix: String,
    /// Remote nodes in deterministic order, including offline nodes.
    pub peers: Vec<TailnetNode>,
}

/// Whether an address is in Tailscale's standard IPv4 or IPv6 node range.
pub fn is_tailnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            a == 100 && (64..128).contains(&b)
        }
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

impl TailnetStatus {
    /// Whether the local backend reports a running, online node.
    pub fn is_running(&self) -> bool {
        self.backend_state == "Running" && self.local_online
    }
}

#[derive(Deserialize, Default)]
struct CliNode {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "HostName", default)]
    hostname: String,
    #[serde(rename = "DNSName", default)]
    dns_name: String,
    #[serde(rename = "TailscaleIPs")]
    ips: Option<Vec<IpAddr>>,
    #[serde(rename = "Online", default)]
    online: bool,
}

#[derive(Deserialize)]
struct CliTailnet {
    #[serde(rename = "MagicDNSSuffix")]
    dns_suffix: Option<String>,
}

#[derive(Deserialize)]
struct CliStatus {
    #[serde(rename = "BackendState")]
    backend_state: String,
    #[serde(rename = "Self")]
    local: Option<CliNode>,
    #[serde(rename = "TailscaleIPs")]
    ips: Option<Vec<IpAddr>>,
    #[serde(rename = "MagicDNSSuffix", default)]
    dns_suffix: String,
    #[serde(rename = "CurrentTailnet")]
    current_tailnet: Option<CliTailnet>,
    #[serde(rename = "Peer")]
    peers: Option<BTreeMap<String, CliNode>>,
}

fn parse_status(bytes: &[u8]) -> Result<TailnetStatus, MeshTailscaleError> {
    let raw: CliStatus = serde_json::from_slice(bytes)?;
    let local = raw.local.unwrap_or_default();
    let peers = raw
        .peers
        .unwrap_or_default()
        .into_values()
        .filter(|peer| !peer.id.is_empty() && peer.id != local.id)
        .map(|peer| TailnetNode {
            node_id: peer.id,
            hostname: peer.hostname,
            magic_dns: peer.dns_name.trim_end_matches('.').to_owned(),
            ips: peer.ips.unwrap_or_default(),
            online: peer.online,
        })
        .collect();
    Ok(TailnetStatus {
        backend_state: raw.backend_state,
        local_online: local.online,
        local_ips: raw.ips.or(local.ips).unwrap_or_default(),
        dns_suffix: raw
            .current_tailnet
            .and_then(|tailnet| tailnet.dns_suffix)
            .unwrap_or(raw.dns_suffix)
            .trim_end_matches('.')
            .to_owned(),
        peers,
    })
}

/// Handle for taking snapshots on demand.
#[derive(Debug, Default)]
pub struct MeshTailscale {
    config: MeshTailscaleConfig,
}

impl MeshTailscale {
    /// Construct a handle for the configured local CLI.
    pub const fn new(config: MeshTailscaleConfig) -> Self {
        Self { config }
    }

    /// Borrow the active config.
    pub const fn config(&self) -> &MeshTailscaleConfig {
        &self.config
    }

    /// Query the local daemon once. Stopped or signed-out backends can be
    /// inspected if the CLI provides their status.
    pub async fn status(&self) -> Result<TailnetStatus, MeshTailscaleError> {
        let mut child = Command::new(self.config.resolve_cli())
            .args(["status", "--json"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => MeshTailscaleError::NotInstalled,
                _ => MeshTailscaleError::Io(e),
            })?;
        let stdout = child.stdout.take().expect("requested piped stdout");
        let read_and_wait = async {
            let mut bytes = Vec::new();
            stdout
                .take(MAX_STATUS_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(MeshTailscaleError::Io)?;
            if bytes.len() > MAX_STATUS_BYTES {
                return Err(MeshTailscaleError::OutputTooLarge);
            }
            let status = child.wait().await.map_err(MeshTailscaleError::Io)?;
            if !status.success() {
                return Err(MeshTailscaleError::CommandFailed(status));
            }
            parse_status(&bytes)
        };
        tokio::time::timeout(STATUS_TIMEOUT, read_and_wait)
            .await
            .map_err(|_| MeshTailscaleError::Timeout)?
    }

    /// Verify that the configured CLI can reach an active tailnet.
    pub async fn start(&self) -> Result<(), MeshTailscaleError> {
        let status = self.status().await?;
        if status.is_running() {
            Ok(())
        } else {
            Err(MeshTailscaleError::Inactive(status.backend_state))
        }
    }
}

#[cfg(test)]
mod tests;
