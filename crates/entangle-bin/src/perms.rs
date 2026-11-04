//! `perms/list` and `perms/revoke`: the broker's view of each loaded
//! plugin's declared capabilities (spec §4.6).
//!
//! A capability is `granted` (with its outstanding grant ids — the load-time
//! grant plus any handle a running instance holds), `denied` (refused by the
//! operator's `[security] deny_capabilities` or the tier ceiling, with the
//! reason), `revoked` (`entangle perms revoke`, until the plugin is
//! reloaded) or `not-granted`. Nothing here grants or audits anything.

use entangle_broker::{CapabilityStatus, GrantState};
use entangle_rpc::methods::{CapabilityGrantInfo, PermsListResult, PluginPerms};
use entangle_runtime::Kernel;
use entangle_types::plugin_id::PluginId;

/// Why a `perms/*` request could not be answered.
#[derive(Debug)]
pub enum PermsError {
    /// The plugin id does not parse (JSON-RPC invalid params).
    InvalidId(String),
    /// The plugin is not loaded.
    NotLoaded(String),
    /// The broker refused (e.g. revoking a capability that is not declared).
    Broker(String),
}

impl std::fmt::Display for PermsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermsError::InvalidId(e) => write!(f, "invalid plugin id: {e}"),
            PermsError::NotLoaded(id) => write!(f, "plugin not loaded: {id}"),
            PermsError::Broker(e) => f.write_str(e),
        }
    }
}

fn parse_id(s: &str) -> Result<PluginId, PermsError> {
    s.parse()
        .map_err(|e: entangle_types::errors::EntangleError| PermsError::InvalidId(e.to_string()))
}

/// The wire form of one capability's state.
pub fn grant_info(status: &CapabilityStatus) -> CapabilityGrantInfo {
    let (state, grant_ids, reason) = match &status.state {
        GrantState::Granted { grant_ids } => ("granted", grant_ids.clone(), None),
        GrantState::Denied { reason } => ("denied", Vec::new(), Some(reason.clone())),
        GrantState::Revoked => ("revoked", Vec::new(), None),
        GrantState::NotGranted => ("not-granted", Vec::new(), None),
    };
    CapabilityGrantInfo {
        capability: status.capability.key().into_owned(),
        params: status.capability.params(),
        state: state.to_owned(),
        grant_ids,
        reason,
    }
}

/// `perms/list`: one plugin (`Some(id)`) or every loaded plugin.
pub fn list(kernel: &Kernel, plugin: Option<&str>) -> Result<PermsListResult, PermsError> {
    let mut ids = match plugin {
        Some(s) => vec![parse_id(s)?],
        None => kernel.list_plugins(),
    };
    ids.sort_by_key(ToString::to_string);
    let mut plugins = Vec::with_capacity(ids.len());
    for id in ids {
        let (Some(report), Some(tier)) = (
            kernel.capability_report(&id),
            kernel.broker().effective_tier(&id),
        ) else {
            if plugin.is_some() {
                return Err(PermsError::NotLoaded(id.to_string()));
            }
            // Unloaded between listing and reporting.
            continue;
        };
        plugins.push(PluginPerms {
            plugin_id: id.to_string(),
            effective_tier: u8::from(tier),
            capabilities: report.iter().map(grant_info).collect(),
        });
    }
    Ok(PermsListResult { plugins })
}

/// `perms/revoke`: withdraw `capability` (a manifest key) from `plugin`.
pub fn revoke(kernel: &Kernel, plugin: &str, capability: &str) -> Result<Vec<u64>, PermsError> {
    let id = parse_id(plugin)?;
    if kernel.capability_report(&id).is_none() {
        return Err(PermsError::NotLoaded(id.to_string()));
    }
    kernel
        .revoke_capability(&id, capability)
        .map_err(|e| PermsError::Broker(e.to_string()))
}
