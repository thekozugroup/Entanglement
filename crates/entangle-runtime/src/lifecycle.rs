//! Lifecycle phase enumeration and event type for plugin state transitions.

use entangle_types::{plugin_id::PluginId, tier::Tier};
use std::time::SystemTime;

/// The ordered phases a plugin passes through during its lifetime.
///
/// Each phase corresponds to a step in the load flow described in spec §3.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecyclePhase {
    /// The manifest was loaded and passed semantic validation.
    ManifestValidated,
    /// The artifact signature was verified against the trusted keyring.
    SignatureVerified,
    /// The plugin was registered with the capability broker.
    Registered,
    /// The plugin artifact was compiled and loaded by the host engine.
    Loaded,
    /// The plugin has been activated (future use).
    Activated,
    /// The plugin has been idled (future use).
    Idled,
    /// The plugin was unloaded and de-registered.
    Unloaded,
}

/// A lifecycle transition event emitted on the IPC bus.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LifecycleEvent {
    /// The plugin that transitioned.
    pub plugin: PluginId,
    /// The phase reached.
    pub phase: LifecyclePhase,
    /// The effective capability tier of the plugin.
    pub effective_tier: Tier,
    /// Wall-clock time of the transition (seconds since UNIX epoch).
    #[serde(with = "system_time_secs")]
    pub at: SystemTime,
}

mod system_time_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        let secs = t
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        s.serialize_u64(secs)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs))
    }
}
