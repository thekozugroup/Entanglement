//! The optional hot-reload `migrate` hook (spec §3.3; WIT world
//! `migrate-hook`): `migrate(from-version: string) -> result<_, string>`.
//!
//! A component of either `entangle:plugin` world may also export `migrate`.
//! When the kernel replaces a loaded version of a plugin with a new one it
//! runs the **new** version's hook — in a fresh instance with the new
//! version's capability grants, exactly like a call — before routing any
//! call to it. A component exporting `migrate` with another signature is
//! refused at load ([`HostError::Instantiate`]) rather than silently treated
//! as having no hook.

use crate::capability::CapabilityContext;
use crate::engine::{HostEngine, EPOCH_TICK_MS};
use crate::errors::HostError;
use crate::plugin::{backstop, classify_call_error, classify_instantiate_error, instance_grants};
use crate::state::{HostState, ResourceLimits};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use wasmtime::component::InstancePre;
use wasmtime::Store;

#[allow(missing_docs)] // generated code
mod bindings {
    wasmtime::component::bindgen!({
        // Relative to this crate's Cargo.toml (crates/entangle-host/).
        path: "../entangle-wit/wit",
        world: "migrate-hook",
        exports: { default: async },
    });
}

/// A component's pre-instantiated `migrate` export.
pub(crate) type MigratePre = bindings::MigrateHookPre<HostState>;

/// What running a component's `migrate` hook did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrateOutcome {
    /// The component exports no `migrate`: nothing ran (drain-and-swap).
    NoHook,
    /// `migrate` returned `ok`.
    Migrated,
    /// `migrate` returned `err` with this message.
    Refused(String),
}

/// The `migrate` export of `instance_pre`'s component: `None` when it has
/// none, an error when it has one of the wrong type.
pub(crate) fn hook_pre(
    instance_pre: &InstancePre<HostState>,
) -> Result<Option<MigratePre>, HostError> {
    if instance_pre
        .component()
        .get_export_index(None, "migrate")
        .is_none()
    {
        return Ok(None);
    }
    bindings::MigrateHookPre::new(instance_pre.clone())
        .map(Some)
        .map_err(|e| {
            HostError::Instantiate(anyhow::anyhow!(
                "the component's `migrate` export is not the `migrate-hook` world's \
                 `migrate: func(from-version: string) -> result<_, string>`: {e}"
            ))
        })
}

/// Instantiate the component once and call `migrate(from_version)`, with the
/// plugin's grants as they stand now and the same timeout and resource
/// limits as a call.
pub(crate) async fn run(
    pre: &MigratePre,
    engine: &HostEngine,
    plugin_id: &PluginId,
    effective_tier: Tier,
    caps: Option<&CapabilityContext>,
    from_version: &str,
    timeout_ms: u64,
) -> Result<MigrateOutcome, HostError> {
    let grants = instance_grants(caps, plugin_id, timeout_ms).await?;
    let state = HostState::with_capabilities(
        plugin_id.clone(),
        effective_tier,
        ResourceLimits::default(),
        &grants,
        caps.cloned(),
    )?;
    let mut store = Store::new(engine.engine(), state);
    store.limiter(|s| &mut s.limits);
    store.set_epoch_deadline(timeout_ms.div_ceil(EPOCH_TICK_MS).max(1));
    let call = async {
        let hook = pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| classify_instantiate_error(e.into(), timeout_ms))?;
        hook.call_migrate(&mut store, from_version)
            .await
            .map_err(|e| classify_call_error(e.into(), timeout_ms))
    };
    match tokio::time::timeout(backstop(timeout_ms), call).await {
        Ok(Ok(Ok(()))) => Ok(MigrateOutcome::Migrated),
        Ok(Ok(Err(message))) => Ok(MigrateOutcome::Refused(message)),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => Err(HostError::Timeout(timeout_ms)),
    }
}
