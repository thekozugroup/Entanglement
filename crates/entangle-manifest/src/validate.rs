//! Semantic validation of a raw [`crate::schema::Manifest`] — spec §4.4 and §4.4.1.
//!
//! The entry point is [`validate`], which converts a [`crate::schema::Manifest`] into
//! a [`ValidatedManifest`] or returns a [`ValidationError`].

use std::str::FromStr;

use thiserror::Error;

use entangle_types::{
    capability::{
        is_valid_share_name, CapabilityKind, NetHost, ShareMode, StorageMode, StorageScope,
    },
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

    /// ENTANGLE-E0202: a capability key was recognised but one of its
    /// parameters is malformed (wrong type, unknown value, bad host entry).
    #[error("ENTANGLE-E0202: malformed capability args for '{key}': {message}")]
    CapabilityArgs {
        /// The capability key.
        key: String,
        /// Human-readable description of the problem.
        message: String,
    },

    /// ENTANGLE-E0203: a capability table contains a parameter this
    /// capability does not take. Unknown parameters are refused rather than
    /// ignored, so a typo (`host = …` for `hosts = …`) can never silently
    /// widen or drop a restriction.
    #[error(
        "ENTANGLE-E0203: capability '{key}' does not take parameter '{param}' \
         (allowed: {allowed})"
    )]
    UnknownCapabilityParam {
        /// The capability key.
        key: String,
        /// The unrecognised parameter.
        param: String,
        /// The parameters this capability accepts, comma-separated.
        allowed: String,
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

        // An unrestricted / wildcard WAN grant is the usual way a tier-3
        // plugin trips this; say how to fix it rather than just the tiers.
        let capability = match parse_capability(offending_key, &m.capabilities[offending_key]) {
            Ok(CapabilityKind::NetWan { hosts })
                if declared_tier >= Tier::Networked && hosts.iter().any(NetHost::is_wildcard) =>
            {
                format!(
                    "{offending_key}: a wildcard or unrestricted WAN allowlist is a tier-4 \
                     authority; list the hosts instead, e.g. hosts = [\"api.example.com:443\"]"
                )
            }
            _ => offending_key.clone(),
        };
        return Err(ValidationError::TierBelowCapability {
            declared: declared_tier,
            implied: implied_tier,
            capability,
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

/// The parameter every capability accepts: why the plugin needs it, shown
/// to the operator (spec §11 #9).
const RATIONALE: &str = "rationale";

/// Parse a single `[capabilities]` entry from its string key and raw TOML args.
///
/// Mapping table per spec §4.4:
///
/// | Key | Maps to | Parameters (besides `rationale`) |
/// |-----|---------|------------|
/// | `compute.cpu` | [`CapabilityKind::ComputeCpu`] | — |
/// | `compute.gpu` | [`CapabilityKind::ComputeGpu`] | — |
/// | `compute.npu` | [`CapabilityKind::ComputeNpu`] | — |
/// | `storage.local` | [`CapabilityKind::StorageLocal`] | `scope` = `plugin` (alias `$plugin_data`, default) \| `shared`; `mode` = `ro` \| `rw` (default) |
/// | `storage.share.<name>` | [`CapabilityKind::StorageShare`] (`<name>` per [`is_valid_share_name`]) | `mode` = `ro` (default) \| `rw` \| `rw-scoped` |
/// | `net.lan` | [`CapabilityKind::NetLan`] | — |
/// | `net.wan` | [`CapabilityKind::NetWan`] | `hosts` = non-empty list of `host[:port]` ([`NetHost`]); omitted = `["*"]` (tier 4) |
/// | `mesh.peer` | [`CapabilityKind::MeshPeer`] | — |
/// | `agent.invoke` | [`CapabilityKind::AgentInvoke`] | — |
/// | `host.docker-socket` | [`CapabilityKind::HostDockerSocket`] | — |
/// | `custom.*` | [`CapabilityKind::Custom`] | — |
///
/// The value must be a table (`"compute.cpu" = {}`); any parameter not
/// listed is refused ([`ValidationError::UnknownCapabilityParam`]), and
/// `rationale`, when present, must be a string.
pub fn parse_capability(key: &str, args: &toml::Value) -> Result<CapabilityKind, ValidationError> {
    let bad = |message: String| ValidationError::CapabilityArgs {
        key: key.to_owned(),
        message,
    };
    let table = args.as_table().ok_or_else(|| {
        bad(format!(
            "expected a table of parameters (e.g. `\"{key}\" = {{}}`), found {}",
            args.type_str()
        ))
    })?;
    // Refuse anything this capability does not take.
    let allow = |params: &[&str]| -> Result<(), ValidationError> {
        for name in table.keys() {
            if name != RATIONALE && !params.contains(&name.as_str()) {
                let mut allowed: Vec<&str> = params.to_vec();
                allowed.push(RATIONALE);
                return Err(ValidationError::UnknownCapabilityParam {
                    key: key.to_owned(),
                    param: name.clone(),
                    allowed: allowed.join(", "),
                });
            }
        }
        match table.get(RATIONALE) {
            None | Some(toml::Value::String(_)) => Ok(()),
            Some(_) => Err(bad(format!("field `{RATIONALE}` must be a string"))),
        }
    };
    // An optional string field.
    let str_field = |field: &str| -> Result<Option<&str>, ValidationError> {
        match table.get(field) {
            None => Ok(None),
            Some(toml::Value::String(s)) => Ok(Some(s.as_str())),
            Some(_) => Err(bad(format!("field `{field}` must be a string"))),
        }
    };

    match key {
        "compute.cpu" => allow(&[]).map(|()| CapabilityKind::ComputeCpu),

        "compute.gpu" => allow(&[]).map(|()| CapabilityKind::ComputeGpu),

        "compute.npu" => allow(&[]).map(|()| CapabilityKind::ComputeNpu),

        "storage.local" => {
            allow(&["scope", "mode"])?;
            let scope = match str_field("scope")?.unwrap_or("plugin") {
                "plugin" | "$plugin_data" => StorageScope::Plugin,
                "shared" => StorageScope::Shared,
                other => {
                    return Err(bad(format!(
                        "unknown scope `{other}`; expected `plugin` (or `$plugin_data`) or `shared`"
                    )))
                }
            };
            let mode = match str_field("mode")?.unwrap_or("rw") {
                "ro" => StorageMode::Ro,
                "rw" => StorageMode::Rw,
                other => {
                    return Err(bad(format!(
                        "unknown mode `{other}`; expected `ro` or `rw`"
                    )))
                }
            };
            Ok(CapabilityKind::StorageLocal { scope, mode })
        }

        k if k.starts_with("storage.share.") => {
            let name = k
                .strip_prefix("storage.share.")
                .expect("checked by starts_with")
                .to_owned();
            // The name becomes one directory under `<data>/shares`: refuse
            // anything that could address a path outside it (`/`, `..`, …).
            if !is_valid_share_name(&name) {
                return Err(bad(format!(
                    "invalid share name `{name}`; expected `[a-z0-9][a-z0-9_-]*` \
                     (one path component, at most 63 characters)"
                )));
            }
            allow(&["mode"])?;
            let mode = match str_field("mode")?.unwrap_or("ro") {
                "ro" => ShareMode::Ro,
                "rw" => ShareMode::Rw,
                "rw-scoped" => ShareMode::RwScoped,
                other => {
                    return Err(bad(format!(
                        "unknown mode `{other}`; expected `ro`, `rw`, or `rw-scoped`"
                    )))
                }
            };
            Ok(CapabilityKind::StorageShare { name, mode })
        }

        "net.lan" => allow(&[]).map(|()| CapabilityKind::NetLan),

        "net.wan" => {
            allow(&["hosts"])?;
            let hosts = match table.get("hosts") {
                // No allowlist = any host: a wildcard, which `min_tier`
                // prices at tier 4 (§4.2).
                None => vec![NetHost::any()],
                Some(toml::Value::Array(entries)) => {
                    if entries.is_empty() {
                        return Err(bad(
                            "`hosts` is empty; list at least one `host[:port]`".to_owned()
                        ));
                    }
                    let mut hosts: Vec<NetHost> = Vec::with_capacity(entries.len());
                    for e in entries {
                        let s = e.as_str().ok_or_else(|| {
                            bad("`hosts` entries must be strings `host[:port]`".to_owned())
                        })?;
                        let h: NetHost = s.parse().map_err(|e| bad(format!("{e}")))?;
                        if !hosts.contains(&h) {
                            hosts.push(h);
                        }
                    }
                    hosts
                }
                Some(_) => {
                    return Err(bad(
                        "`hosts` must be a list of strings `host[:port]`".to_owned()
                    ))
                }
            };
            Ok(CapabilityKind::NetWan { hosts })
        }

        "mesh.peer" => allow(&[]).map(|()| CapabilityKind::MeshPeer),

        "agent.invoke" => allow(&[]).map(|()| CapabilityKind::AgentInvoke),

        "host.docker-socket" => allow(&[]).map(|()| CapabilityKind::HostDockerSocket),

        k if k.starts_with("custom.") => {
            allow(&[]).map(|()| CapabilityKind::Custom(key.to_owned()))
        }

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

    /// A share name becomes one directory under `<data>/shares`; anything
    /// that is not a single plain component (an absolute path, `..`, `.`,
    /// an empty name, a separator) would let a manifest name a scope outside
    /// that tree — `"storage.share./" = { mode = "rw" }` would grant `/`.
    #[test]
    fn storage_share_rejects_names_that_are_not_one_plain_component() {
        for mode in ["ro", "rw", "rw-scoped"] {
            let mut args = toml::map::Map::new();
            args.insert("mode".into(), toml::Value::String(mode.into()));
            let args = toml::Value::Table(args);
            for bad in [
                "/", "/etc", "..", "../..", "../x", "x/../..", ".", "", "a/b", "a\\b", "C:", "a b",
                "-a", "Photos",
            ] {
                let key = format!("storage.share.{bad}");
                let err = parse_capability(&key, &args).expect_err(&key);
                assert!(
                    matches!(err, ValidationError::CapabilityArgs { .. }),
                    "{key}: got {err}"
                );
                assert!(err.to_string().contains("share name"), "{key}: {err}");
            }
            for good in ["photos", "inbox", "a", "0", "my-share", "my_share", "s3"] {
                let key = format!("storage.share.{good}");
                let cap = parse_capability(&key, &args).expect(&key);
                assert!(
                    matches!(cap, CapabilityKind::StorageShare { ref name, .. } if name == good),
                    "{key}: {cap:?}"
                );
            }
        }
        // Through the whole validator, too.
        let mut m = minimal_manifest("escape", 5, Runtime::Native);
        let mut args = toml::map::Map::new();
        args.insert("mode".into(), toml::Value::String("rw".into()));
        m.capabilities
            .insert("storage.share./".into(), toml::Value::Table(args));
        let err = validate(m).expect_err("a share named `/` must be refused");
        assert!(err.to_string().contains("share name"), "{err}");
    }

    #[test]
    fn validate_rejects_tier_0() {
        let m = minimal_manifest("zero-tier", 0, Runtime::Wasm);
        let err = validate(m).expect_err("tier 0 must be rejected");
        assert!(
            matches!(err, ValidationError::InvalidTier(0)),
            "got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_tier_6() {
        let m = minimal_manifest("over-tier", 6, Runtime::Native);
        let err = validate(m).expect_err("tier 6 must be rejected");
        assert!(
            matches!(err, ValidationError::InvalidTier(6)),
            "got: {err:?}"
        );
    }

    fn table(pairs: &[(&str, toml::Value)]) -> toml::Value {
        let mut t = toml::map::Map::new();
        for (k, v) in pairs {
            t.insert((*k).to_owned(), v.clone());
        }
        toml::Value::Table(t)
    }

    fn s(v: &str) -> toml::Value {
        toml::Value::String(v.to_owned())
    }

    fn hosts(v: &[&str]) -> toml::Value {
        toml::Value::Array(v.iter().map(|h| s(h)).collect())
    }

    #[test]
    fn storage_local_parses_scope_and_mode() {
        let cases = [
            (vec![], StorageScope::Plugin, StorageMode::Rw),
            (
                vec![("mode", s("ro"))],
                StorageScope::Plugin,
                StorageMode::Ro,
            ),
            (
                vec![("scope", s("$plugin_data")), ("mode", s("rw"))],
                StorageScope::Plugin,
                StorageMode::Rw,
            ),
            (
                vec![("scope", s("shared")), ("mode", s("ro"))],
                StorageScope::Shared,
                StorageMode::Ro,
            ),
            (
                vec![("scope", s("plugin")), ("rationale", s("cache AOT output"))],
                StorageScope::Plugin,
                StorageMode::Rw,
            ),
        ];
        for (args, scope, mode) in cases {
            let cap = parse_capability("storage.local", &table(&args)).expect("valid");
            assert_eq!(
                cap,
                CapabilityKind::StorageLocal { scope, mode },
                "{args:?}"
            );
        }
        for (args, needle) in [
            (vec![("mode", s("rwx"))], "unknown mode"),
            (vec![("mode", s("rw-scoped"))], "unknown mode"),
            (vec![("scope", s("/etc"))], "unknown scope"),
            (
                vec![("mode", toml::Value::Boolean(true))],
                "must be a string",
            ),
            (
                vec![("rationale", toml::Value::Integer(3))],
                "must be a string",
            ),
        ] {
            let err = parse_capability("storage.local", &table(&args)).expect_err(needle);
            assert!(
                matches!(err, ValidationError::CapabilityArgs { .. }),
                "{args:?}: {err}"
            );
            assert!(err.to_string().contains(needle), "{args:?}: {err}");
            assert!(err.to_string().starts_with("ENTANGLE-E0202"), "{err}");
        }
    }

    /// A typo must never silently drop a restriction: unknown parameters are
    /// refused for every capability, with the allowed set in the message.
    #[test]
    fn unknown_capability_parameters_are_refused() {
        for (key, param) in [
            ("compute.cpu", "max-threads"),
            ("storage.local", "path"),
            ("storage.share.photos", "scope"),
            ("net.lan", "hosts"),
            ("net.wan", "host"),
            ("mesh.peer", "scope"),
            ("custom.thing", "anything"),
        ] {
            let err = parse_capability(key, &table(&[(param, s("x"))])).expect_err(key);
            match &err {
                ValidationError::UnknownCapabilityParam {
                    key: k,
                    param: p,
                    allowed,
                } => {
                    assert_eq!(k, key);
                    assert_eq!(p, param);
                    assert!(allowed.contains("rationale"), "{allowed}");
                }
                other => panic!("{key}: expected UnknownCapabilityParam, got {other}"),
            }
            assert!(err.to_string().starts_with("ENTANGLE-E0203"), "{err}");
        }
    }

    #[test]
    fn capability_value_must_be_a_table() {
        for v in [toml::Value::Boolean(true), s("rw"), toml::Value::Integer(1)] {
            let err = parse_capability("compute.cpu", &v).expect_err("non-table");
            assert!(err.to_string().contains("expected a table"), "{err}");
        }
    }

    #[test]
    fn net_wan_parses_and_deduplicates_hosts() {
        let cap = parse_capability(
            "net.wan",
            &table(&[(
                "hosts",
                hosts(&["API.example.com:443", "api.example.com:443", "203.0.113.9"]),
            )]),
        )
        .expect("valid");
        let CapabilityKind::NetWan { hosts } = cap else {
            panic!("expected NetWan, got {cap:?}");
        };
        let rendered: Vec<String> = hosts.iter().map(ToString::to_string).collect();
        assert_eq!(rendered, ["api.example.com:443", "203.0.113.9"]);
    }

    #[test]
    fn net_wan_rejects_malformed_allowlists() {
        for (v, needle) in [
            (hosts(&[]), "empty"),
            (hosts(&["https://api.example.com"]), "invalid host entry"),
            (hosts(&["api.example.com:0"]), "port"),
            (
                toml::Value::Array(vec![toml::Value::Integer(1)]),
                "must be strings",
            ),
            (s("api.example.com"), "must be a list"),
        ] {
            let err = parse_capability("net.wan", &table(&[("hosts", v)])).expect_err(needle);
            assert!(err.to_string().contains(needle), "{err}");
        }
    }

    /// §4.2: WAN wildcards are tier 4. Below that, an explicit wildcard or an
    /// unrestricted `net.wan` (no `hosts`) is refused with ENTANGLE-E0042 and
    /// a hint to list hosts instead.
    #[test]
    fn net_wan_wildcards_require_tier_4() {
        for args in [
            table(&[]),
            table(&[("hosts", hosts(&["*"]))]),
            table(&[("hosts", hosts(&["api.example.com:443", "*.example.org"]))]),
        ] {
            let mut m = minimal_manifest("wan-wild", 3, Runtime::Wasm);
            m.capabilities.insert("net.wan".into(), args.clone());
            let err = validate(m).expect_err("wildcard at tier 3");
            assert!(
                matches!(
                    err,
                    ValidationError::TierBelowCapability {
                        implied: Tier::Privileged,
                        ..
                    }
                ),
                "{args:?}: {err}"
            );
            assert!(err.to_string().contains("list the hosts"), "{err}");

            // At tier 4+ (native) the same allowlist is accepted.
            let mut m = minimal_manifest("wan-wild", 5, Runtime::Native);
            m.capabilities.insert("net.wan".into(), args);
            validate(m).expect("wildcard at tier 5");
        }

        // Named hosts are an ordinary tier-3 capability.
        let mut m = minimal_manifest("wan-named", 3, Runtime::Wasm);
        m.capabilities.insert(
            "net.wan".into(),
            table(&[("hosts", hosts(&["api.example.com:443"]))]),
        );
        let v = validate(m).expect("named hosts at tier 3");
        assert_eq!(v.implied_tier, Tier::Networked);

        // Below tier 3 the ordinary E0042 message names the capability.
        let mut m = minimal_manifest("wan-low", 1, Runtime::Wasm);
        m.capabilities.insert("net.wan".into(), table(&[]));
        let err = validate(m).expect_err("tier 1");
        assert!(
            matches!(err, ValidationError::TierBelowCapability { ref capability, .. } if capability == "net.wan"),
            "{err}"
        );
    }

    /// Every manifest shipped in `examples/` and `plugins/` still validates
    /// (with the build-time publisher placeholder filled in).
    #[test]
    fn shipped_manifests_still_validate() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut seen = 0;
        for dir in ["examples", "plugins"] {
            for entry in std::fs::read_dir(root.join(dir)).expect(dir).flatten() {
                let path = entry.path().join("entangle.toml");
                if !path.exists() {
                    continue;
                }
                let text = std::fs::read_to_string(&path)
                    .expect("read manifest")
                    .replace("PUBLISHER_PLACEHOLDER", PUB);
                let raw: Manifest =
                    toml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                validate(raw).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                seen += 1;
            }
        }
        assert!(seen >= 5, "expected the shipped manifests, found {seen}");
    }
}
