use std::collections::BTreeSet;
use std::io::{ErrorKind, Write};
use std::path::Path;

use anyhow::{ensure, Context};
use entangle_rpc::{TierPolicyAction, TierPolicyParams, TierReview};
use serde_json::Value;
use toml_edit::{value, Array, DocumentMut};

use super::{error_resp, ok_resp, DaemonState};
use crate::config::Config;

pub(super) async fn dispatch(id: Value, params: Value, state: &DaemonState) -> String {
    let params = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return error_resp(id, -32602, format!("invalid tier policy parameters: {e}")),
    };
    match handle(params, state).await {
        Ok(result) => ok_resp(id, result),
        Err(e) => error_resp(id, -32000, format!("{e:#}")),
    }
}

fn read_config(path: &Path) -> anyhow::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(raw) => Ok(raw),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.into()),
    }
}

fn persist(path: &Path, original: &str, doc: &DocumentMut) -> anyhow::Result<()> {
    let writer = entangle_runtime::config::lock_config_writer(path)?;
    let updated = doc.to_string();
    if updated != original {
        let mut tmp =
            tempfile::NamedTempFile::new_in(path.parent().context("config parent directory")?)?;
        if let Ok(meta) = std::fs::metadata(path) {
            tmp.as_file().set_permissions(meta.permissions())?;
        }
        tmp.write_all(updated.as_bytes())?;
        tmp.as_file().sync_all()?;
        ensure!(
            read_config(path)? == original,
            "configuration changed; review the new file"
        );
        tmp.persist(path)?;
        // The rename already committed. Keep the live policy in sync even if the filesystem
        // cannot confirm directory durability across power loss.
        if let Err(error) = writer.sync_all() {
            tracing::warn!(%error, "could not sync directory after committing tier policy");
        }
    } else {
        ensure!(
            read_config(path)? == original,
            "configuration changed; review the new file"
        );
    }
    Ok(())
}

async fn handle(params: TierPolicyParams, state: &DaemonState) -> anyhow::Result<TierReview> {
    let path = state
        .config_path
        .as_deref()
        .context("daemon configuration path unavailable")?;
    let raw = read_config(path)?;
    let parsed: Config = toml::from_str(&raw)?;
    let target = match params.target {
        Some(tier) => tier.try_into()?,
        None => parsed.security.max_tier_allowed,
    };
    let change = state.kernel.reserve_tier_change(target).await?;
    let revision = format!(
        "{}:{}:{}",
        state.policy_session,
        change.generation(),
        blake3::hash(raw.as_bytes())
    );
    let review = TierReview {
        current: change.current().into(),
        proposed: target.into(),
        affected: change
            .affected()
            .iter()
            .map(|(id, tier)| (id.to_string(), (*tier).into()))
            .collect(),
        revision,
    };
    if params.action == TierPolicyAction::Review {
        return Ok(review);
    }
    ensure!(
        params.approved.as_ref() == Some(&review),
        "configuration or loaded plugins changed; review the affected plugins again"
    );
    let mut doc: DocumentMut = raw.parse()?;
    let accepted = params.action == TierPolicyAction::Apply;
    let tier = if accepted {
        review.proposed
    } else {
        review.current
    };
    if parsed.security.max_tier_allowed as u8 != tier {
        doc["security"]["max_tier_allowed"] = value(i64::from(tier));
    }
    if accepted {
        let mut disabled: BTreeSet<_> = parsed.runtime.disabled_plugins.into_iter().collect();
        let old_len = disabled.len();
        disabled.extend(review.affected.iter().map(|(id, _)| id.clone()));
        if disabled.len() != old_len {
            doc["runtime"]["disabled_plugins"] = value(disabled.iter().cloned().collect::<Array>());
        }
        change.apply(disabled, || persist(path, &raw, &doc)).await?;
    } else {
        persist(path, &raw, &doc)?;
        change.cancelled();
    }
    Ok(review)
}
