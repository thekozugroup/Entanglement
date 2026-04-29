//! Raw TOML schema structs for `entangle.toml` — spec §4.4.
//!
//! These structs are deserialized directly from TOML; no semantic validation
//! is performed here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level shape of an `entangle.toml` manifest.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    /// `[plugin]` section (required).
    pub plugin: PluginSection,

    /// `[capabilities]` table — raw TOML values; validated in `validate.rs`.
    #[serde(default)]
    pub capabilities: BTreeMap<String, toml::Value>,

    /// `[build]` section (optional).
    pub build: Option<BuildSection>,

    /// `[signature]` section (optional).
    pub signature: Option<SignatureSection>,
}

/// `[plugin]` section of `entangle.toml`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginSection {
    /// `"<publisher>/<name>"` — validated to `PluginId` during validation.
    pub id: String,

    /// Semver version of the plugin.
    pub version: semver::Version,

    /// Declared capability-tier ceiling (1..=5).
    pub tier: u8,

    /// Execution runtime.
    pub runtime: Runtime,

    /// Human-readable description (empty string if omitted).
    #[serde(default)]
    pub description: String,
}

/// Plugin execution runtime — `"wasm"` or `"native"`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    /// WebAssembly (wasip2) runtime.
    Wasm,
    /// Native host process runtime.
    Native,
}

/// `[build]` section of `entangle.toml`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuildSection {
    /// WIT world reference, e.g. `"entangle:plugin/hello@0.1.0"`.
    pub wit_world: Option<String>,

    /// Cargo/rustup target triple, e.g. `"wasm32-wasip2"`.
    pub target: Option<String>,
}

/// `[signature]` section of `entangle.toml`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureSection {
    /// Publisher public-key fingerprint (hex).
    pub publisher: String,

    /// Signature algorithm — defaults to `"ed25519"`.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_algorithm() -> String {
    "ed25519".into()
}
