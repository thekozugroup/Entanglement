//! Task types for one-shot and streaming plugin invocations.
//!
//! # Specification reference
//! §7.1 (task structure) and §7.5 (integrity policies) of the
//! Entanglement Architecture specification.

use crate::peer_id::PeerId;
use crate::plugin_id::PluginId;
use crate::resource::ResourceSpec;

/// Opaque unique identifier for a single task invocation (UUID v4).
pub type TaskId = uuid::Uuid;

/// Policy governing output integrity verification.
///
/// # §7.5 Integrity policies
///
/// The policy is chosen per task by the submitter and travels, hashed, in the
/// work-unit envelope (INV-INT-1). Verification always happens on the
/// **submitter**: workers execute the task exactly once per replica and return
/// raw output; they never evaluate the policy themselves.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum IntegrityPolicy {
    /// Run `replicas` identical copies; require identical byte-for-byte outputs.
    Deterministic {
        /// Number of independent execution replicas.
        replicas: u8,
    },
    /// Replicate and compare the replica outputs pairwise with a signed metric
    /// component (`entangle:integrity/metric@0.1.0`).
    ///
    /// The task is accepted iff at least `quorum` of the
    /// `replicas * (replicas - 1) / 2` replica pairs have
    /// `metric.compare(a, b) < threshold` — counted among the pairs that back
    /// the returned output (its agreement cluster), so agreeing pairs in an
    /// unrelated group of replicas never count toward it. The metric runs
    /// only on the submitter (§7.5 verifier-locality, Rule 3).
    SemanticEquivalent {
        /// Number of independent execution replicas (at least 2: one pair).
        replicas: u8,
        /// Minimum number of agreeing replica *pairs* that must back the
        /// returned output.
        quorum: u8,
        /// The exact metric component used to compare replica outputs.
        metric: MetricRef,
        /// Pairwise distance strictly below which two outputs agree.
        threshold: f64,
    },
    /// Accept output only from explicitly allow-listed peers.
    TrustedExecutor {
        /// Peers whose outputs are trusted without further verification.
        allowlist: Vec<PeerId>,
    },
    /// Require a Trusted Execution Environment attestation report.
    ///
    /// Carried so the wire format is forward-compatible; every build of this
    /// workspace rejects it (TEE attestation is Phase 4+, §7.5).
    Attested {
        /// TEE kind identifier (e.g. `"sgx"`, `"sev"`, `"trustzone"`).
        tee: String,
    },
    /// No integrity checking; accept the first response.
    None,
}

impl IntegrityPolicy {
    /// The policy variant, without its parameters.
    pub fn kind(&self) -> PolicyKind {
        match self {
            IntegrityPolicy::Deterministic { .. } => PolicyKind::Deterministic,
            IntegrityPolicy::SemanticEquivalent { .. } => PolicyKind::SemanticEquivalent,
            IntegrityPolicy::TrustedExecutor { .. } => PolicyKind::TrustedExecutor,
            IntegrityPolicy::Attested { .. } => PolicyKind::Attested,
            IntegrityPolicy::None => PolicyKind::None,
        }
    }
}

/// The variant of an [`IntegrityPolicy`], without its parameters.
///
/// Used where a decision depends only on *which* policy is in force — notably
/// per-peer reputation, which §7.5 Layer 3 keeps separately per variant.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyKind {
    /// [`IntegrityPolicy::Deterministic`].
    Deterministic,
    /// [`IntegrityPolicy::SemanticEquivalent`].
    SemanticEquivalent,
    /// [`IntegrityPolicy::TrustedExecutor`].
    TrustedExecutor,
    /// [`IntegrityPolicy::Attested`].
    Attested,
    /// [`IntegrityPolicy::None`].
    None,
}

impl PolicyKind {
    /// Stable kebab-case label, identical to the serde `kind` tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyKind::Deterministic => "deterministic",
            PolicyKind::SemanticEquivalent => "semantic-equivalent",
            PolicyKind::TrustedExecutor => "trusted-executor",
            PolicyKind::Attested => "attested",
            PolicyKind::None => "none",
        }
    }
}

impl std::fmt::Display for PolicyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Pins the exact metric component a [`IntegrityPolicy::SemanticEquivalent`]
/// task is verified with (§7.5 Rule 2).
///
/// Three facts identify it, so a worker or a man in the middle cannot
/// substitute a look-alike:
///
/// * `plugin` — the fully-qualified plugin id, whose `publisher` is the
///   BLAKE3-16 fingerprint of the signing key;
/// * `publisher_key` — the Ed25519 public key itself, which the submitter
///   checks against its own keyring;
/// * `artifact_blake3` — the BLAKE3 digest of the component bytes, so a
///   re-signed or rebuilt component is a *different* metric.
///
/// Serialised with both 32-byte values as lowercase hex strings, so the type
/// round-trips through JSON and TOML.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MetricRef {
    /// Fully-qualified metric plugin id (`<publisher>/<name>@<version>`).
    pub plugin: PluginId,
    /// Raw 32-byte Ed25519 public key of the metric's publisher.
    #[serde(with = "hex32")]
    pub publisher_key: [u8; 32],
    /// BLAKE3 digest of the metric component's artifact bytes.
    #[serde(with = "hex32")]
    pub artifact_blake3: [u8; 32],
}

impl MetricRef {
    /// BLAKE3-16 fingerprint of [`MetricRef::publisher_key`] — the same
    /// derivation `entangle-signing` uses for keyring entries.
    pub fn publisher_fingerprint(&self) -> [u8; 16] {
        let hash = blake3::hash(&self.publisher_key);
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&hash.as_bytes()[..16]);
        fp
    }

    /// `true` when the plugin id's publisher is the fingerprint of
    /// `publisher_key`.
    ///
    /// A reference that fails this check names one publisher in its id and
    /// carries another's key; nothing should ever accept it.
    pub fn is_self_consistent(&self) -> bool {
        self.plugin
            .publisher
            .eq_ignore_ascii_case(&hex::encode(self.publisher_fingerprint()))
    }

    /// Lowercase hex of [`MetricRef::artifact_blake3`].
    pub fn artifact_hex(&self) -> String {
        hex::encode(self.artifact_blake3)
    }
}

impl std::fmt::Display for MetricRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (blake3 {})", self.plugin, self.artifact_hex())
    }
}

/// Serde helper: a `[u8; 32]` as a 64-character lowercase hex string.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let raw = hex::decode(&text).map_err(serde::de::Error::custom)?;
        raw.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes of hex, got {}", v.len()))
        })
    }
}

/// A single-input / single-output task invocation.
///
/// # §7.1
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OneShotTask {
    /// Unique task identifier.
    pub id: TaskId,
    /// Plugin to invoke.
    pub plugin: PluginId,
    /// Serialised input payload.
    pub input: Vec<u8>,
    /// Maximum accepted size of `input` in bytes (default: 16 MiB).
    pub max_input_bytes: u64,
    /// Maximum accepted size of the output in bytes (default: 16 MiB).
    pub max_output_bytes: u64,
    /// Resource requirements for the task.
    pub resources: ResourceSpec,
    /// Integrity verification policy.
    pub integrity: IntegrityPolicy,
    /// Wall-clock timeout in milliseconds.
    pub timeout_ms: u64,
}

impl OneShotTask {
    /// Default for `max_input_bytes` (16 MiB).
    pub const DEFAULT_MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
    /// Default for `max_output_bytes` (16 MiB).
    pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
    /// Default wall-clock timeout (30 s).
    pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

    /// Construct a `OneShotTask` with spec-default size and timeout limits per §7.1.
    pub fn with_defaults(plugin: PluginId, input: Vec<u8>) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            plugin,
            input,
            max_input_bytes: Self::DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: Self::DEFAULT_MAX_OUTPUT_BYTES,
            resources: ResourceSpec::default(),
            integrity: IntegrityPolicy::None,
            timeout_ms: Self::DEFAULT_TIMEOUT_MS,
        }
    }
}

/// Channel parameters for a streaming task.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChannelSpec {
    /// Maximum size of a single chunk in bytes (default: 1 MiB).
    pub max_chunk_bytes: u64,
    /// Maximum cumulative transfer size in bytes (default: 256 MiB).
    pub max_total_bytes: u64,
    /// Back-pressure credit window in chunk units (default: 16).
    pub credit_window: u32,
    /// Heartbeat interval in milliseconds (default: 5 000).
    pub heartbeat_ms: u32,
}

impl Default for ChannelSpec {
    fn default() -> Self {
        Self {
            max_chunk_bytes: 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            credit_window: 16,
            heartbeat_ms: 5_000,
        }
    }
}

/// What to do with partial results if a streaming task is interrupted.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PartialResultPolicy {
    /// Discard all partial results.
    Discard,
    /// Keep partial results as-is.
    Keep,
    /// Keep partial results only if they carry a valid plugin signature.
    KeepSigned,
}

/// A bidirectional streaming task invocation.
///
/// # §7.1
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StreamingTask {
    /// Unique task identifier.
    pub id: TaskId,
    /// Plugin to invoke.
    pub plugin: PluginId,
    /// Channel configuration.
    pub channel: ChannelSpec,
    /// Resource requirements for the task.
    pub resources: ResourceSpec,
    /// Integrity verification policy.
    pub integrity: IntegrityPolicy,
    /// Wall-clock timeout in milliseconds.
    pub timeout_ms: u64,
    /// Partial-result retention policy.
    pub partial_result: PartialResultPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_spec_defaults() {
        let c = ChannelSpec::default();
        assert_eq!(c.max_chunk_bytes, 1024 * 1024);
        assert_eq!(c.max_total_bytes, 256 * 1024 * 1024);
        assert_eq!(c.credit_window, 16);
        assert_eq!(c.heartbeat_ms, 5_000);
    }

    #[test]
    fn one_shot_defaults() {
        assert_eq!(OneShotTask::DEFAULT_MAX_INPUT_BYTES, 16 * 1024 * 1024);
        assert_eq!(OneShotTask::DEFAULT_MAX_OUTPUT_BYTES, 16 * 1024 * 1024);
    }

    #[test]
    fn integrity_policy_none_eq() {
        assert_eq!(IntegrityPolicy::None, IntegrityPolicy::None);
    }

    fn sample_metric() -> MetricRef {
        let publisher_key = [7u8; 32];
        let fp = blake3::hash(&publisher_key);
        let publisher = hex::encode(&fp.as_bytes()[..16]);
        MetricRef {
            plugin: format!("{publisher}/metric-bleu-4@0.1.0").parse().unwrap(),
            publisher_key,
            artifact_blake3: [9u8; 32],
        }
    }

    fn semantic() -> IntegrityPolicy {
        IntegrityPolicy::SemanticEquivalent {
            replicas: 3,
            quorum: 2,
            metric: sample_metric(),
            threshold: 0.15,
        }
    }

    #[test]
    fn semantic_equivalent_json_round_trip() {
        let policy = semantic();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains(r#""kind":"semantic-equivalent""#), "{json}");
        // Both pinned digests travel as hex, not as arrays of numbers.
        assert!(json.contains(&hex::encode([9u8; 32])), "{json}");
        let back: IntegrityPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, policy);
    }

    #[test]
    fn semantic_equivalent_toml_round_trip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrapper {
            policy: IntegrityPolicy,
        }
        let w = Wrapper { policy: semantic() };
        let text = toml::to_string(&w).unwrap();
        let back: Wrapper = toml::from_str(&text).unwrap();
        assert_eq!(back, w);
    }

    #[test]
    fn metric_ref_rejects_short_hex() {
        let json = serde_json::to_value(sample_metric()).unwrap();
        let mut bad = json.clone();
        bad["artifact_blake3"] = serde_json::Value::String("abcd".into());
        assert!(serde_json::from_value::<MetricRef>(bad).is_err());
        let mut not_hex = json;
        not_hex["publisher_key"] = serde_json::Value::String("zz".repeat(32));
        assert!(serde_json::from_value::<MetricRef>(not_hex).is_err());
    }

    #[test]
    fn metric_ref_self_consistency_binds_id_to_key() {
        let good = sample_metric();
        assert!(good.is_self_consistent());
        let mut swapped = good.clone();
        swapped.publisher_key = [8u8; 32];
        assert!(
            !swapped.is_self_consistent(),
            "a key that does not hash to the id's publisher must be flagged"
        );
    }

    #[test]
    fn policy_kind_labels_match_serde_tags() {
        for policy in [
            IntegrityPolicy::None,
            IntegrityPolicy::Deterministic { replicas: 2 },
            semantic(),
            IntegrityPolicy::TrustedExecutor { allowlist: vec![] },
            IntegrityPolicy::Attested { tee: "sgx".into() },
        ] {
            let json = serde_json::to_value(&policy).unwrap();
            assert_eq!(json["kind"], policy.kind().as_str());
        }
    }
}
