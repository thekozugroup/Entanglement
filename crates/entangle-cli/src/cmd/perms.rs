//! `entangle perms` — inspect and revoke plugins' capability grants
//! (spec §4.6).
//!
//! `entangle perms list [<plugin>]` shows every declared capability of the
//! daemon's loaded plugins with its broker state: `granted` (with the
//! outstanding grant ids), `denied` (operator `[security]
//! deny_capabilities` or the tier ceiling, with the reason), `revoked`, or
//! `not-granted`. `entangle perms revoke <plugin> <capability>` withdraws a
//! capability until the plugin is reloaded: `capability.fetch` answers
//! `revoked` at once, network access stops at once, and storage is gone from
//! the next invocation.
//!
//! Both talk to the daemon; an in-process kernel has no loaded plugins to
//! report on, so there is no `--allow-local` fallback.

use clap::{Args, Subcommand};
use entangle_rpc::methods::PermsListResult;
use entangle_rpc::{Client as RpcClient, RpcError};
use std::fmt::Write as _;

use crate::daemon_not_running_error;

/// Arguments for the `perms` top-level subcommand.
#[derive(Args)]
pub struct PermsArgs {
    #[command(subcommand)]
    pub cmd: PermsCmd,
}

/// `entangle perms` subcommands.
#[derive(Subcommand)]
pub enum PermsCmd {
    /// Show each loaded plugin's declared capabilities and whether they are granted.
    List {
        /// Only this plugin (full id, `<publisher>/<name>@<version>`).
        plugin: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Revoke a capability from a loaded plugin until it is reloaded.
    Revoke {
        /// Full plugin id.
        plugin: String,
        /// Capability key as declared in the manifest, e.g. `net.wan`,
        /// `storage.local`, `storage.share.photos`.
        capability: String,
    },
}

pub async fn run(args: PermsArgs) -> anyhow::Result<()> {
    let client = RpcClient::new(RpcClient::default_socket());
    let not_running = |e: RpcError| match e {
        RpcError::DaemonNotRunning(_) => daemon_not_running_error(),
        e => e.into(),
    };
    match args.cmd {
        PermsCmd::List { plugin, json } => {
            let r = client
                .perms_list(plugin.as_deref())
                .await
                .map_err(not_running)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                print!("{}", render_text(&r));
            }
            Ok(())
        }
        PermsCmd::Revoke { plugin, capability } => {
            let r = client
                .perms_revoke(&plugin, &capability)
                .await
                .map_err(not_running)?;
            if r.withdrawn.is_empty() {
                println!("{capability} revoked from {plugin} (no grant was outstanding)");
            } else {
                let ids: Vec<String> = r.withdrawn.iter().map(ToString::to_string).collect();
                println!(
                    "{capability} revoked from {plugin}; withdrew grant(s) {}",
                    ids.join(", ")
                );
            }
            println!("{REVOKE_CAVEAT}");
            Ok(())
        }
    }
}

/// What an operator must know about how long a revocation lasts: it is held
/// in the daemon's memory only, so a reload or a daemon restart restores the
/// plugin's declared grants.
pub const REVOKE_CAVEAT: &str =
    "Not persistent: the plugin gets this capability back when it is unloaded and \
loaded again or when the daemon restarts. To keep a capability away for good, \
add it to [security] deny_capabilities.";

/// Render `perms list` for a terminal.
pub fn render_text(r: &PermsListResult) -> String {
    let mut out = String::new();
    if r.plugins.is_empty() {
        out.push_str("no plugins loaded\n");
        return out;
    }
    for p in &r.plugins {
        // Writing to a String cannot fail.
        let _ = writeln!(out, "{} (tier {})", p.plugin_id, p.effective_tier);
        if p.capabilities.is_empty() {
            out.push_str("  (no capabilities declared)\n");
        }
        for c in &p.capabilities {
            let cap = if c.params.is_empty() {
                c.capability.clone()
            } else {
                format!("{} [{}]", c.capability, c.params)
            };
            let detail = match (c.state.as_str(), &c.reason) {
                ("granted", _) => {
                    let ids: Vec<String> = c.grant_ids.iter().map(ToString::to_string).collect();
                    format!("granted (grant {})", ids.join(", "))
                }
                (state, Some(reason)) => format!("{state}: {reason}"),
                (state, None) => state.to_owned(),
            };
            let _ = writeln!(out, "  {cap:<48} {detail}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_rpc::methods::{CapabilityGrantInfo, PluginPerms};

    #[test]
    fn revoke_caveat_names_the_daemon_restart_and_the_permanent_remedy() {
        assert!(REVOKE_CAVEAT.contains("daemon restarts"), "{REVOKE_CAVEAT}");
        assert!(
            REVOKE_CAVEAT.contains("deny_capabilities"),
            "{REVOKE_CAVEAT}"
        );
    }

    #[test]
    fn renders_each_state() {
        let r = PermsListResult {
            plugins: vec![PluginPerms {
                plugin_id: "aabbccddeeff00112233445566778899/probe@0.1.0".into(),
                effective_tier: 3,
                capabilities: vec![
                    CapabilityGrantInfo {
                        capability: "storage.local".into(),
                        params: "scope=plugin mode=rw".into(),
                        state: "granted".into(),
                        grant_ids: vec![4],
                        reason: None,
                    },
                    CapabilityGrantInfo {
                        capability: "net.wan".into(),
                        params: "hosts=api.example.com:443".into(),
                        state: "denied".into(),
                        grant_ids: vec![],
                        reason: Some("operator policy".into()),
                    },
                    CapabilityGrantInfo {
                        capability: "net.lan".into(),
                        params: String::new(),
                        state: "revoked".into(),
                        grant_ids: vec![],
                        reason: None,
                    },
                ],
            }],
        };
        let text = render_text(&r);
        assert!(text.contains("probe@0.1.0 (tier 3)"), "{text}");
        assert!(
            text.contains("storage.local [scope=plugin mode=rw]"),
            "{text}"
        );
        assert!(text.contains("granted (grant 4)"), "{text}");
        assert!(text.contains("denied: operator policy"), "{text}");
        assert!(text.contains("net.lan"), "{text}");
        assert!(text.contains("revoked"), "{text}");
        assert_eq!(
            render_text(&PermsListResult { plugins: vec![] }),
            "no plugins loaded\n"
        );
    }
}
