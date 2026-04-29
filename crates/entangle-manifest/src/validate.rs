//! Semantic validation of a raw [`crate::schema::Manifest`] — spec §4.4 and §4.4.1.
//!
//! The entry point is [`validate`], which converts a [`crate::schema::Manifest`] into
//! a [`ValidatedManifest`] or returns a [`ValidationError`].

use std::str::FromStr;

use thiserror::Error;

use entangle_types::{
    capability::{CapabilityKind, ShareMode, StorageScope},
    plugin_id::PluginId,
    tier::Tier,
};

use crate::schema::{Manifest, Runtime};

// ── ValidatedManifest ────────────────────────────────────────────────────────

/// A fully-parsed and semantically-validated plugin manifest.
#[derive(Debug)]
pub struct ValidatedManifest {
    /// Parsed plugin identifier (`<publisher>/<name>`).
    pub plugin_id: PluginId,

    /// Tier explicitly declared by the plugin author.
    pub declared_tier: Tier,

    /// Tier implied by the highest-privilege capability listed.
    /// Equals `Tier::Pure` when no capabilities are declared.
    pub implied_tier: Tier,

    /// Effective runtime ceiling: `max(declared_tier, implied_tier)`.
    pub effective_tier: Tier,

    /// Execution runtime.
    pub runtime: Runtime,

    /// Parsed capability list.
    pub capabilities: Vec<CapabilityKind>,

    /// Original raw manifest (retained for tooling / display).
    pub raw: Manifest,
}

// ── ValidationError ──────────────────────────────────────────────────────────

/// Errors produced during manifest validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// `plugin.tier` was outside the 1..=5 range.
    #[error("invalid tier {0}, must be 1..=5")]
    InvalidTier(u8),

    /// `plugin.id` could not be parsed as a valid `PluginId`.
    #[error("invalid plugin id: {0}")]
    InvalidPluginId(String),

    /// A key in `[capabilities]` is not recognised.
    #[error("unknown capability key: {key}")]
    UnknownCapability {
        /// The unrecognised capability key string.
        key: String,
    },

    /// ENTANGLE-E0042: the declared tier is below what the capability set requires.
    #[error(
        "ENTANGLE-E0042: declared tier {declared:?} below implied tier {implied:?} \
         from capability '{capability}'"
    )]
    TierBelowCapability {
        /// Tier the plugin author declared.
        declared: Tier,
        /// Tier implied by the offending capability.
        implied: Tier,
        /// The first capability whose `min_tier` exceeds `declared`.
        capability: String,
    },

    /// The combination of `runtime` and `tier` is forbidden by spec §4.4.1 case 3.
    #[error("runtime '{runtime:?}' incompatible with tier {tier:?}")]
    RuntimeTierMismatch {
        /// The runtime that was declared.
        runtime: Runtime,
        /// The effective tier.
        tier: Tier,
    },

    /// A capability key was recognised but its argument table is malformed.
    #[error("malformed capability args for '{key}': {message}")]
    CapabilityArgs {
        /// The capability key.
        key: String,
        /// Human-readable description of the problem.
        message: String,
    },

    /// TOML deserialisation failed.
    #[error("toml parse: {0}")]
    Toml(#[from] toml::de::Error),
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Parse and validate a raw [`Manifest`].
///
/// Returns a [`ValidatedManifest`] on success, or the first
/// [`ValidationError`] encountered.
pub fn validate(m: Manifest) -> Result<ValidatedManifest, ValidationError> {
    // Rule 1 — tier in range.
    let raw_tier = m.plugin.tier;
    if !(1..=5).contains(&raw_tier) {
        return Err(ValidationError::InvalidTier(raw_tier));
    }
    let declared_tier =
        Tier::try_from(raw_tier).map_err(|_| ValidationError::InvalidTier(raw_tier))?;

    // Rule 2 — valid PluginId.
    let plugin_id = PluginId::from_str(&m.plugin.id)
        .map_err(|e| ValidationError::InvalidPluginId(e.to_string()))?;

    // Rule 3 — parse all capabilities.
    let mut capabilities: Vec<CapabilityKind> = Vec::with_capacity(m.capabilities.len());
    for (key, args) in &m.capabilities {
        capabilities.push(parse_capability(key, args)?);
    }

    // Rule 4 (§4.4.1) — implied tier.
    let implied_tier = capabilities
        .iter()
        .map(|c| c.min_tier())
        .max()
        .unwrap_or(Tier::Pure);

    // Rule 5 (§4.4.1 case 1) — under-declared is rejected.
    if declared_tier < implied_tier {
        // Find the first offending capability for the error message.
        let (offending_key, _) = m
            .capabilities
            .iter()
            .find(|(k, v)| {
                parse_capability(k, v)
                    .map(|c| c.min_tier() > declared_tier)
                    .unwrap_or(false)
            })
            .expect("implied_tier > declared means at least one cap exceeds it");

        return Err(ValidationError::TierBelowCapability {
            declared: declared_tier,
            implied: implied_tier,
            capability: offending_key.clone(),
        });
    }

    // Rule 6 (§4.4.1 case 2) — over-declared is fine; effective = declared.
    let effective_tier = declared_tier.max(implied_tier);

    // Rule 7 (§4.4.1 case 3) — runtime / tier mismatch.
    // Tier 4+ requires native; tier 1-3 requires wasm.
    match (m.plugin.runtime, effective_tier) {
        (Runtime::Wasm, t) if t >= Tier::Privileged => {
            return Err(ValidationError::RuntimeTierMismatch {
                runtime: Runtime::Wasm,
                tier: effective_tier,
            });
        }
        (Runtime::Native, t) if t <= Tier::Networked => {
            return Err(ValidationError::RuntimeTierMismatch {
                runtime: Runtime::Native,
                tier: effective_tier,
            });
        }
        _ => {}
    }

    Ok(ValidatedManifest {
        plugin_id,
        declared_tier,
        implied_tier,
        effective_tier,
        runtime: m.plugin.runtime,
        capabilities,
        raw: m,
    })
}

// ── Capability key parsing ───────────────────────────────────────────────────

/// Parse a single `[capabilities]` entry from its string key and raw TOML args.
///
/// Mapping table per spec §4.4:
///
/// | Key | Maps to |
/// |-----|---------|
/// | `compute.cpu` | [`CapabilityKind::ComputeCpu`] |
/// | `compute.gpu` | [`CapabilityKind::ComputeGpu`] |
/// | `compute.npu` | [`CapabilityKind::ComputeNpu`] |
/// | `storage.local` | [`CapabilityKind::StorageLocal`] |
/// | `storage.share.<name>` | [`CapabilityKind::StorageShare`] |
/// | `net.lan` | [`CapabilityKind::NetLan`] |
/// | `net.wan` | [`CapabilityKind::NetWan`] |
/// | `mesh.peer` | [`CapabilityKind::MeshPeer`] |
/// | `agent.invoke` | [`CapabilityKind::AgentInvoke`] |
/// | `host.docker-socket` | [`CapabilityKind::HostDockerSocket`] |
/// | `custom.*` | [`CapabilityKind::Custom`] |
pub fn parse_capability(key: &str, args: &toml::Value) -> Result<CapabilityKind, ValidationError> {
    // Helper: extract an optional string field from an inline table.
    let str_field = |field: &str, default: &str| -> Result<String, ValidationError> {
        match args.get(field) {
            None => Ok(default.to_owned()),
            Some(toml::Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(ValidationError::CapabilityArgs {
                key: key.to_owned(),
                message: format!("field `{field}` must be a string"),
            }),
        }
    };

    match key {
        "compute.cpu" => Ok(CapabilityKind::ComputeCpu),

        "compute.gpu" => Ok(CapabilityKind::ComputeGpu),

        "compute.npu" => Ok(CapabilityKind::ComputeNpu),

        "storage.local" => {
            let scope_str = str_field("scope", "plugin")?;
            let scope = match scope_str.as_str() {
                "plugin" => StorageScope::Plugin,
                "shared" => StorageScope::Shared,
                other => {
                    return Err(ValidationError::CapabilityArgs {
                        key: key.to_owned(),
                        message: format!("unknown scope `{other}`; expected `plugin` or `shared`"),
                    })
                }
            };
            Ok(CapabilityKind::StorageLocal { scope })
        }

        k if k.starts_with("storage.share.") => {
            let name = k
                .strip_prefix("storage.share.")
                .expect("checked by starts_with")
                .to_owned();
            let mode_str = str_field("mode", "ro")?;
            let mode = match mode_str.as_str() {
                "ro" => ShareMode::Ro,
                "rw" => ShareMode::Rw,
                "rw-scoped" => ShareMode::RwScoped,
                other => {
                    return Err(ValidationError::CapabilityArgs {
                        key: key.to_owned(),
                        message: format!(
                            "unknown mode `{other}`; expected `ro`, `rw`, or `rw-scoped`"
                        ),
                    })
                }
            };
            Ok(CapabilityKind::StorageShare { name, mode })
        }

        "net.lan" => Ok(CapabilityKind::NetLan),

        "net.wan" => Ok(CapabilityKind::NetWan),

        "mesh.peer" => Ok(CapabilityKind::MeshPeer),

        "agent.invoke" => Ok(CapabilityKind::AgentInvoke),

        "host.docker-socket" => Ok(CapabilityKind::HostDockerSocket),

        k if k.starts_with("custom.") => Ok(CapabilityKind::Custom(key.to_owned())),

        _ => Err(ValidationError::UnknownCapability {
            key: key.to_owned(),
        }),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{BuildSection, Manifest, PluginSection, Runtime};

    /// 32 lowercase hex chars (BLAKE3-16 fingerprint).
    const PUB: &str = "aabbccddeeff00112233445566778899";

    fn minimal_manifest(name: &str, tier: u8, runtime: Runtime) -> Manifest {
        Manifest {
            plugin: PluginSection {
                id: format!("{PUB}/{name}@0.1.0"),
                version: semver::Version::parse("0.1.0").unwrap(),
                tier,
                runtime,
                description: String::new(),
            },
            capabilities: Default::default(),
            build: Some(BuildSection {
                wit_world: None,
                target: None,
            }),
            signature: None,
        }
    }

    // Test 1 — declared > implied: valid, effective = declared.
    // compute.cpu min_tier = Sandboxed(2); declared = Networked(3) > implied.
    #[test]
    fn valid_declared_above_implied() {
        let mut m = minimal_manifest("hello-world", 3, Runtime::Wasm);
        m.capabilities
            .insert("compute.cpu".into(), toml::Value::Table(Default::default()));
        let v = validate(m).expect("should be valid");
        assert_eq!(v.effective_tier, Tier::Networked);
        assert_eq!(v.implied_tier, Tier::Sandboxed);
        assert!(v.effective_tier >= v.implied_tier);
    }

    // Test 2 — declared == implied: valid (tier=5/Native, host.docker-socket min=Native).
    #[test]
    fn valid_declared_equals_implied() {
        let mut m = minimal_manifest("docker-plugin", 5, Runtime::Native);
        m.capabilities.insert(
            "host.docker-socket".into(),
            toml::Value::Table(Default::default()),
        );
        let v = validate(m).expect("should be valid");
        assert_eq!(v.effective_tier, Tier::Native);
    }

    // Test 3 — §4.4.1 case 1: declared < implied is rejected.
    // host.docker-socket min=Native(5); declared=Sandboxed(2) < Native.
    #[test]
    fn rejected_when_declared_below_implied() {
        let mut m = minimal_manifest("too-low", 2, Runtime::Wasm);
        m.capabilities.insert(
            "host.docker-socket".into(),
            toml::Value::Table(Default::default()),
        );
        let err = validate(m).expect_err("should fail");
        assert!(
            matches!(err, ValidationError::TierBelowCapability { .. }),
            "got: {err}"
        );
    }

    // Test 4 — runtime/tier mismatch: Wasm + tier 5 (Native) rejected.
    // declared=5==implied=5 so TierBelowCapability is skipped; then RuntimeTierMismatch fires.
    #[test]
    fn rejected_wasm_with_tier5() {
        let mut m = minimal_manifest("bad-runtime", 5, Runtime::Wasm);
        m.capabilities.insert(
            "host.docker-socket".into(),
            toml::Value::Table(Default::default()),
        );
        let err = validate(m).expect_err("wasm + tier 5 should fail");
        assert!(
            matches!(err, ValidationError::RuntimeTierMismatch { .. }),
            "got: {err}"
        );
    }

    // Test 5 — runtime/tier mismatch: Native + tier 2 rejected.
    // No caps → implied=Pure(1), effective=Sandboxed(2) ≤ Networked → Native forbidden.
    #[test]
    fn rejected_native_with_tier2() {
        let m = minimal_manifest("bad-native", 2, Runtime::Native);
        let err = validate(m).expect_err("native at tier 2 should fail");
        assert!(
            matches!(err, ValidationError::RuntimeTierMismatch { .. }),
            "got: {err}"
        );
    }

    // Test 6 — unknown capability rejected.
    #[test]
    fn rejected_unknown_capability() {
        let mut m = minimal_manifest("unknown-cap", 1, Runtime::Wasm);
        m.capabilities
            .insert("compute.tpu".into(), toml::Value::Table(Default::default()));
        let err = validate(m).expect_err("unknown cap should fail");
        assert!(
            matches!(err, ValidationError::UnknownCapability { .. }),
            "got: {err}"
        );
    }

    // Test 7 — plugin name rejects uppercase.
    #[test]
    fn rejected_uppercase_plugin_name() {
        // Build the raw id string directly (bypassing minimal_manifest helper).
        let mut m = minimal_manifest("hello-world", 1, Runtime::Wasm);
        m.plugin.id = format!("{PUB}/HelloWorld@0.1.0");
        let err = validate(m).expect_err("uppercase name should fail");
        assert!(
            matches!(err, ValidationError::InvalidPluginId(_)),
            "got: {err}"
        );
    }

    // Test 8 — storage.share parses name and mode.
    #[test]
    fn storage_share_parses_correctly() {
        use entangle_types::capability::ShareMode;
        let mut args = toml::map::Map::new();
        args.insert("mode".into(), toml::Value::String("ro".into()));
        let cap = parse_capability("storage.share.photos", &toml::Value::Table(args))
            .expect("should parse");
        assert!(
            matches!(cap, CapabilityKind::StorageShare { ref name, mode } if name == "photos" && mode == ShareMode::Ro),
            "got: {cap:?}"
        );
    }
}
