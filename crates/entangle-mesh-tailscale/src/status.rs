//! `tailscale status --json` parsing, CLI invocation and state classification.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::error::MeshTailscaleError;

/// One node (this host or a peer) from the status JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TailnetNode {
    /// `Online` flag.
    pub online: bool,
    /// MagicDNS name without the trailing dot (e.g. `bob.tail1234.ts.net`).
    pub dns_name: String,
    /// Tailnet IPs (unparsable entries are dropped).
    pub ips: Vec<IpAddr>,
    /// OS host name.
    pub host_name: String,
}

/// Parsed `tailscale status --json`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TailscaleStatus {
    /// `BackendState` (`Running`, `Stopped`, `NeedsLogin`, `NoState`, ...).
    pub backend_state: String,
    /// The `Self` node, when present.
    pub self_node: Option<TailnetNode>,
    /// Peers, ordered by DNS name.
    pub peers: Vec<TailnetNode>,
    /// `Version` of the local `tailscaled` (e.g. `1.76.1-t0123abcd`); empty
    /// when absent.
    pub version: String,
    /// `CurrentTailnet.Name` (e.g. `corp.ts.net`), when reported.
    pub tailnet_name: Option<String>,
    /// `CurrentTailnet.MagicDNSEnabled`, when reported.
    pub magic_dns_enabled: Option<bool>,
    /// Distinct `LoginName`s in the `User` map, sorted. More than one means
    /// the tailnet is shared with other accounts (spec §9.1.1).
    pub users: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct RawNode {
    online: Option<bool>,
    #[serde(rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Option<Vec<String>>,
    host_name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct RawStatus {
    backend_state: Option<String>,
    #[serde(rename = "Self")]
    self_node: Option<RawNode>,
    peer: Option<BTreeMap<String, RawNode>>,
    version: Option<String>,
    current_tailnet: Option<RawTailnet>,
    user: Option<BTreeMap<String, RawUser>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct RawTailnet {
    name: Option<String>,
    #[serde(rename = "MagicDNSEnabled")]
    magic_dns_enabled: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct RawUser {
    login_name: Option<String>,
}

impl From<RawNode> for TailnetNode {
    fn from(r: RawNode) -> Self {
        Self {
            online: r.online.unwrap_or(false),
            dns_name: r
                .dns_name
                .unwrap_or_default()
                .trim_end_matches('.')
                .to_owned(),
            ips: r
                .tailscale_ips
                .unwrap_or_default()
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            host_name: r.host_name.unwrap_or_default(),
        }
    }
}

impl TailscaleStatus {
    /// Parse status JSON. Unknown fields and `null`s are tolerated.
    pub fn parse(json: &str) -> Result<Self, MeshTailscaleError> {
        let raw: RawStatus = serde_json::from_str(json)
            .map_err(|e| MeshTailscaleError::Status(format!("invalid status JSON: {e}")))?;
        let mut peers: Vec<TailnetNode> = raw
            .peer
            .unwrap_or_default()
            .into_values()
            .map(Into::into)
            .collect();
        peers.sort_by(|a, b| a.dns_name.cmp(&b.dns_name));
        let mut users: Vec<String> = raw
            .user
            .unwrap_or_default()
            .into_values()
            .filter_map(|u| u.login_name)
            .filter(|n| !n.is_empty())
            .collect();
        users.sort();
        users.dedup();
        let (tailnet_name, magic_dns_enabled) = match raw.current_tailnet {
            Some(t) => (t.name.filter(|n| !n.is_empty()), t.magic_dns_enabled),
            None => (None, None),
        };
        Ok(Self {
            backend_state: raw.backend_state.unwrap_or_default(),
            self_node: raw.self_node.map(Into::into),
            peers,
            version: raw.version.unwrap_or_default(),
            tailnet_name,
            magic_dns_enabled,
            users,
        })
    }

    /// The daemon version parsed from [`Self::version`], if well-formed.
    pub fn parsed_version(&self) -> Option<crate::TailscaleVersion> {
        crate::TailscaleVersion::parse(&self.version)
    }

    /// Classify per the §6.1.1 table (the `Uninstalled` case is decided by
    /// the caller, since it is about the binary and not the JSON).
    pub fn classify(&self) -> TailnetState {
        if self.backend_state != "Running" {
            let reason = if self.backend_state.is_empty() {
                "NoState".to_owned()
            } else {
                self.backend_state.clone()
            };
            return TailnetState::Stopped { reason };
        }
        match &self.self_node {
            Some(n) if n.online => TailnetState::Active,
            Some(_) => TailnetState::Stopped {
                reason: "Self offline".into(),
            },
            None => TailnetState::Stopped {
                reason: "no Self node".into(),
            },
        }
    }

    /// Online peers that have at least one tailnet IP.
    pub fn online_peers(&self) -> impl Iterator<Item = &TailnetNode> {
        self.peers.iter().filter(|p| p.online && !p.ips.is_empty())
    }
}

/// The three liveness states of §6.1.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TailnetState {
    /// `tailnet-active`.
    Active,
    /// `tailnet-installed-but-stopped`.
    Stopped {
        /// Backend state or failure text (e.g. `NeedsLogin`).
        reason: String,
    },
    /// `tailnet-uninstalled`.
    Uninstalled,
}

impl TailnetState {
    /// Metric/log label: `active`, `stopped` or `uninstalled`.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stopped { .. } => "stopped",
            Self::Uninstalled => "uninstalled",
        }
    }

    /// The stop reason, if any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Stopped { reason } => Some(reason),
            _ => None,
        }
    }
}

impl std::fmt::Display for TailnetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped { reason } => write!(f, "stopped ({reason})"),
            other => f.write_str(other.label()),
        }
    }
}

/// The result of one poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// Classified state.
    pub state: TailnetState,
    /// Parsed status when the CLI produced one.
    pub status: Option<TailscaleStatus>,
}

/// Something that can be polled for the tailnet state (injectable for tests).
#[async_trait::async_trait]
pub trait StatusSource: Send + Sync {
    /// Take one observation. Never fails: failures are classified.
    async fn observe(&self) -> Observation;
}

/// Where `tailscaled` puts its local API socket by default on this platform.
pub fn default_daemon_sockets() -> Vec<PathBuf> {
    let paths: &[&str] = if cfg!(target_os = "linux") {
        &[
            "/var/run/tailscale/tailscaled.sock",
            "/run/tailscale/tailscaled.sock",
        ]
    } else if cfg!(target_os = "macos") {
        &["/var/run/tailscaled.socket"]
    } else if cfg!(windows) {
        &[r"\\.\pipe\ProtectedPrefix\Administrators\Tailscale\tailscaled"]
    } else {
        &["/var/run/tailscale/tailscaled.sock"]
    };
    paths.iter().map(PathBuf::from).collect()
}

/// [`StatusSource`] that shells out to the `tailscale` CLI.
#[derive(Clone, Debug)]
pub struct CliStatusSource {
    cli: String,
    timeout: Duration,
    daemon_sockets: Vec<PathBuf>,
}

impl CliStatusSource {
    /// Use `cli` (a path or a bare command name).
    pub fn new(cli: impl Into<String>) -> Self {
        Self {
            cli: cli.into(),
            timeout: Duration::from_secs(10),
            daemon_sockets: default_daemon_sockets(),
        }
    }

    /// Look for `tailscaled`'s socket at `path` instead of the platform
    /// default (see [`default_daemon_sockets`]).
    #[must_use]
    pub fn with_daemon_socket(mut self, path: impl AsRef<Path>) -> Self {
        self.daemon_sockets = vec![path.as_ref().to_path_buf()];
        self
    }

    /// Override the per-command timeout (default 10 s).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn run(&self, args: &[&str]) -> Result<std::process::Output, std::io::Error> {
        let mut cmd = tokio::process::Command::new(&self.cli);
        cmd.args(args)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null());
        match tokio::time::timeout(self.timeout, cmd.output()).await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("`{} {}` timed out", self.cli, args.join(" ")),
            )),
        }
    }

    /// Run `status --json` once.
    ///
    /// `Err(NotInstalled)` when the binary cannot be spawned because it does
    /// not exist; other failures are [`MeshTailscaleError::Status`].
    pub async fn fetch_status(&self) -> Result<TailscaleStatus, MeshTailscaleError> {
        let out = self
            .run(&["status", "--json"])
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => MeshTailscaleError::NotInstalled,
                _ => MeshTailscaleError::Status(e.to_string()),
            })?;
        // `tailscale status --json` prints JSON even for Stopped/NeedsLogin
        // (sometimes with a non-zero exit), so prefer parsing stdout.
        if let Ok(s) = std::str::from_utf8(&out.stdout) {
            if !s.trim().is_empty() {
                if let Ok(st) = TailscaleStatus::parse(s) {
                    return Ok(st);
                }
            }
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(MeshTailscaleError::Status(format!(
            "`{} status --json` exited with {}: {}",
            self.cli,
            out.status,
            stderr.trim()
        )))
    }
}

impl CliStatusSource {
    /// The command this source runs (a path or a bare name looked up on
    /// `$PATH`).
    pub fn cli(&self) -> &str {
        &self.cli
    }

    /// Run `tailscale version` and parse its first line.
    ///
    /// `Err(NotInstalled)` when the binary does not exist,
    /// [`MeshTailscaleError::Status`] when it fails or prints no version.
    pub async fn fetch_version(&self) -> Result<crate::TailscaleVersion, MeshTailscaleError> {
        let out = self.run(&["version"]).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => MeshTailscaleError::NotInstalled,
            _ => MeshTailscaleError::Status(e.to_string()),
        })?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() {
            return Err(MeshTailscaleError::Status(format!(
                "`{} version` exited with {}: {}",
                self.cli,
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        crate::TailscaleVersion::parse(&stdout).ok_or_else(|| {
            MeshTailscaleError::Status(format!(
                "`{} version` printed no version: {:?}",
                self.cli,
                stdout.lines().next().unwrap_or("")
            ))
        })
    }

    /// Run `tailscale switch --list` and parse the profiles. A CLI too old
    /// to have `switch` fails with [`MeshTailscaleError::Status`].
    pub async fn list_profiles(
        &self,
    ) -> Result<Vec<crate::TailscaleProfile>, MeshTailscaleError> {
        let out = self
            .run(&["switch", "--list"])
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => MeshTailscaleError::NotInstalled,
                _ => MeshTailscaleError::Status(e.to_string()),
            })?;
        if !out.status.success() {
            return Err(MeshTailscaleError::Status(format!(
                "`{} switch --list` exited with {}: {}",
                self.cli,
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(crate::version::parse_profiles(&String::from_utf8_lossy(
            &out.stdout,
        )))
    }

    /// The CLI could not be spawned because it does not exist. Spec §6.1.1:
    /// that is `uninstalled` only if `tailscaled`'s socket is absent too;
    /// with the socket present the daemon is installed (and maybe running)
    /// and only the CLI is out of reach, e.g. not on the service's `$PATH`.
    fn cli_not_found(&self) -> Observation {
        let socket = self.daemon_sockets.iter().find(|p| p.exists());
        let state = match socket {
            Some(p) => TailnetState::Stopped {
                reason: format!(
                    "tailscale CLI `{}` not found (set [mesh.tailscale] tailscale-cli), \
                     but tailscaled's socket exists at {}",
                    self.cli,
                    p.display()
                ),
            },
            None => TailnetState::Uninstalled,
        };
        Observation {
            state,
            status: None,
        }
    }
}

#[async_trait::async_trait]
impl StatusSource for CliStatusSource {
    async fn observe(&self) -> Observation {
        match self.fetch_status().await {
            Ok(status) => Observation {
                state: status.classify(),
                status: Some(status),
            },
            Err(MeshTailscaleError::NotInstalled) => self.cli_not_found(),
            Err(err) => {
                // Status failed although the binary spawned: distinguish
                // "installed but daemon down" from other failures via `version`.
                let reason = match self.run(&["version"]).await {
                    Ok(o) if o.status.success() => format!("daemon unreachable: {err}"),
                    Ok(_) => format!("cli unhealthy: {err}"),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return self.cli_not_found();
                    }
                    Err(e) => format!("cannot run cli: {e}"),
                };
                Observation {
                    state: TailnetState::Stopped { reason },
                    status: None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIVE: &str = r#"{
      "Version": "1.76.1-t123",
      "SomethingNew": {"a": [1,2,3]},
      "BackendState": "Running",
      "Self": {"ID": "n1", "HostName": "alpha", "DNSName": "alpha.tail1234.ts.net.",
               "Online": true, "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"], "Extra": null},
      "Peer": {
        "nodekey:bb": {"HostName": "bravo", "DNSName": "bravo.tail1234.ts.net.", "Online": true,
                       "TailscaleIPs": ["100.64.0.2"]},
        "nodekey:aa": {"HostName": "charlie", "DNSName": "a-charlie.tail1234.ts.net.", "Online": false,
                       "TailscaleIPs": ["100.64.0.3"]},
        "nodekey:cc": {"HostName": "delta", "DNSName": "delta.tail1234.ts.net.", "Online": true,
                       "TailscaleIPs": null}
      }
    }"#;

    #[test]
    fn version_tailnet_and_users_are_parsed() {
        let json = r#"{"Version":"1.76.1-t123","BackendState":"Running",
          "CurrentTailnet":{"Name":"corp.ts.net","MagicDNSSuffix":"tail1.ts.net","MagicDNSEnabled":true},
          "User":{"1":{"ID":1,"LoginName":"bob@corp"},"2":{"ID":2,"LoginName":"alice@corp"},
                  "3":{"ID":3,"LoginName":"alice@corp"},"4":{"ID":4}}}"#;
        let st = TailscaleStatus::parse(json).unwrap();
        assert_eq!(
            st.parsed_version(),
            Some(crate::TailscaleVersion::new(1, 76, 1))
        );
        assert_eq!(st.tailnet_name.as_deref(), Some("corp.ts.net"));
        assert_eq!(st.magic_dns_enabled, Some(true));
        assert_eq!(st.users, ["alice@corp", "bob@corp"]);
        let bare = TailscaleStatus::parse("{}").unwrap();
        assert!(bare.version.is_empty() && bare.tailnet_name.is_none() && bare.users.is_empty());
    }

    #[test]
    fn active_status_parses_and_classifies() {
        let st = TailscaleStatus::parse(ACTIVE).unwrap();
        assert_eq!(st.backend_state, "Running");
        assert_eq!(st.classify(), TailnetState::Active);
        let me = st.self_node.as_ref().unwrap();
        assert_eq!(me.dns_name, "alpha.tail1234.ts.net");
        assert_eq!(me.host_name, "alpha");
        assert_eq!(me.ips.len(), 2);
        assert_eq!(st.peers.len(), 3);
        assert_eq!(st.peers[0].dns_name, "a-charlie.tail1234.ts.net");
        // Only bravo is online with an IP.
        let online: Vec<_> = st.online_peers().map(|p| p.host_name.as_str()).collect();
        assert_eq!(online, ["bravo"]);
    }

    #[test]
    fn needs_login_is_stopped_with_reason() {
        let st = TailscaleStatus::parse(
            r#"{"BackendState":"NeedsLogin","Self":null,"Peer":null,"AuthURL":"https://x"}"#,
        )
        .unwrap();
        assert_eq!(
            st.classify(),
            TailnetState::Stopped {
                reason: "NeedsLogin".into()
            }
        );
        assert!(st.peers.is_empty());
        assert!(st.self_node.is_none());
    }

    #[test]
    fn stopped_with_peers_absent_key() {
        let st = TailscaleStatus::parse(r#"{"BackendState":"Stopped"}"#).unwrap();
        assert_eq!(st.classify().reason(), Some("Stopped"));
        assert!(st.peers.is_empty());
    }

    #[test]
    fn running_but_self_offline_or_missing_is_stopped() {
        let st = TailscaleStatus::parse(
            r#"{"BackendState":"Running","Self":{"Online":false,"DNSName":"a."}}"#,
        )
        .unwrap();
        assert_eq!(st.classify().reason(), Some("Self offline"));
        let st = TailscaleStatus::parse(r#"{"BackendState":"Running"}"#).unwrap();
        assert_eq!(st.classify().reason(), Some("no Self node"));
    }

    #[test]
    fn empty_object_is_nostate_and_garbage_is_error() {
        let st = TailscaleStatus::parse("{}").unwrap();
        assert_eq!(st.classify().reason(), Some("NoState"));
        let err = TailscaleStatus::parse("not json").unwrap_err();
        assert_eq!(err.code(), "ENTANGLE-E0649");
    }

    #[test]
    fn bad_ip_strings_are_dropped() {
        let st = TailscaleStatus::parse(
            r#"{"BackendState":"Running","Self":{"Online":true,"TailscaleIPs":["nope","100.64.0.9"]}}"#,
        )
        .unwrap();
        assert_eq!(st.self_node.unwrap().ips.len(), 1);
    }
}
