//! Raw TOML schema structs for `entangle.toml` — spec §4.4.
//!
//! These structs are deserialized directly from TOML; no semantic validation
//! is performed here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level shape of an `entangle.toml` manifest.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "WireManifest")]
pub struct Manifest {
    /// `[plugin]` section (required).
    pub plugin: PluginSection,

    /// `[capabilities]` table — raw TOML values; validated in `validate.rs`.
    #[serde(default)]
    pub capabilities: BTreeMap<String, toml::Value>,

    /// `[build]` section (optional).
    pub build: Option<BuildSection>,

    /// `[signature]` section (optional).
    ///
    /// When present, the runtime kernel cross-checks it against the verified
    /// signature bundle at load time: `publisher` must equal the fingerprint
    /// of the key that actually signed the artifact, and `algorithm` must
    /// match the bundle's algorithm. A mismatch fails the load.
    pub signature: Option<SignatureSection>,
}

// Keep the in-memory and serialized representation compatible with existing
// packages while accepting the architecture's separate runtime declaration.
#[derive(Deserialize)]
struct WireManifest {
    plugin: toml::Table,
    runtime: Option<RuntimeDeclaration>,
    #[serde(default)]
    capabilities: BTreeMap<String, toml::Value>,
    build: Option<BuildSection>,
    signature: Option<SignatureSection>,
}

#[derive(Deserialize)]
struct RuntimeDeclaration {
    kind: Runtime,
}

impl TryFrom<WireManifest> for Manifest {
    type Error = String;

    fn try_from(mut wire: WireManifest) -> Result<Self, Self::Error> {
        if let Some(runtime) = wire.runtime {
            if let Some(existing) = wire.plugin.get("runtime") {
                let kind: Runtime = existing
                    .clone()
                    .try_into()
                    .map_err(|e: toml::de::Error| e.to_string())?;
                if kind != runtime.kind {
                    return Err("conflicting plugin.runtime and runtime.kind declarations".into());
                }
            } else {
                let kind = match runtime.kind {
                    Runtime::Wasm => "wasm",
                    Runtime::Native => "native",
                };
                wire.plugin
                    .insert("runtime".into(), toml::Value::String(kind.into()));
            }
        }
        let plugin = toml::Value::Table(wire.plugin)
            .try_into()
            .map_err(|e: toml::de::Error| e.to_string())?;
        Ok(Self {
            plugin,
            capabilities: wire.capabilities,
            build: wire.build,
            signature: wire.signature,
        })
    }
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
    #[serde(alias = "wasm-component")]
    Wasm,
    /// Native host process runtime.
    #[serde(alias = "subprocess")]
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
///
/// Optional declaration of the expected signer. The kernel enforces that the
/// values here agree with the detached signature bundle that verified — this
/// section can only narrow trust, never widen it (the manifest itself is
/// covered by the signed digest, so it cannot be edited post-signing).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureSection {
    /// Publisher public-key fingerprint (hex, 16-byte BLAKE3 → 32 hex chars).
    pub publisher: String,

    /// Signature algorithm — defaults to `"ed25519"`.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_algorithm() -> String {
    "ed25519".into()
}
