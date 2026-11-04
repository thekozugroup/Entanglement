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
    /// Run `replicas` identical copies; a strict majority of them
    /// (`replicas / 2 + 1`) must return byte-for-byte identical output — a
    /// hash quorum tolerating up to `(replicas - 1) / 2` faulty replicas.
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
        #[serde(deserialize_with = "metric_ref_or_hint")]
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

/// Deserialize `SemanticEquivalent::metric`: a [`MetricRef`] map, or — for
/// the earlier policy shape, where `metric` was a bare name such as
/// `"cosine"` and there were no `replicas` / `quorum` — an error that says
/// what the shape is now instead of a bare type mismatch.
fn metric_ref_or_hint<'de, D: serde::Deserializer<'de>>(d: D) -> Result<MetricRef, D::Error> {
    struct MetricRefVisitor;

    impl<'de> serde::de::Visitor<'de> for MetricRefVisitor {
        type Value = MetricRef;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a pinned metric reference { plugin, publisher_key, artifact_blake3 }")
        }

        fn visit_str<E: serde::de::Error>(self, name: &str) -> Result<MetricRef, E> {
            Err(E::custom(format!(
                "semantic-equivalent `metric` must be a pinned metric reference \
                 {{ plugin = \"<publisher>/<name>@<version>\", publisher_key = \"<64 hex>\", \
                 artifact_blake3 = \"<64 hex>\" }}, not the name {name:?}: this policy changed \
                 shape and now also needs `replicas` and `quorum` (agreeing pairs); load the \
                 signed metric package on the submitter and reference it exactly \
                 (docs/operations.md section 11)"
            )))
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<MetricRef, A::Error> {
            serde::Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    d.deserialize_any(MetricRefVisitor)
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

/// How often, and how patiently, a task is re-run after a failure that is
/// not its own fault (spec §7.1 `retry: RetryPolicy`, §7.6 "crash → retry
/// per policy").
///
/// The **scheduler** decides what is retryable, not the task: only a failure
/// that says nothing about the task itself — the worker crashed, the peer
/// was lost, or the transport failed after the request was sent and before
/// any answer arrived — is retried. A policy refusal, an integrity mismatch,
/// a capability-token refusal, a plugin error or a timeout the task itself
/// ran into never is (see `entangle_scheduler::retry` for the exact rule).
///
/// Every attempt counts, the first one included: `max_attempts = 1` never
/// retries. Waits grow from `backoff_ms`, doubling per retry up to
/// `max_backoff_ms`, and are cut short by the task's own deadline — no retry
/// starts after `timeout_ms`, measured from the first attempt, has passed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RetryPolicy {
    /// Attempts in all, the first included (1 = never retry). Values above
    /// [`RetryPolicy::MAX_ATTEMPTS`] are treated as that, 0 as 1.
    pub max_attempts: u8,
    /// Wait before the first retry, in milliseconds; each later wait doubles.
    pub backoff_ms: u64,
    /// The longest single wait, in milliseconds.
    pub max_backoff_ms: u64,
}

impl RetryPolicy {
    /// The most attempts any task gets, whatever it asks for.
    pub const MAX_ATTEMPTS: u8 = 8;
    /// Default `max_attempts` (3: the first attempt and two retries).
    pub const DEFAULT_MAX_ATTEMPTS: u8 = 3;
    /// Default `backoff_ms` (200 ms).
    pub const DEFAULT_BACKOFF_MS: u64 = 200;
    /// Default `max_backoff_ms` (5 s).
    pub const DEFAULT_MAX_BACKOFF_MS: u64 = 5_000;

    /// A policy that never retries.
    pub const fn never() -> Self {
        Self {
            max_attempts: 1,
            backoff_ms: 0,
            max_backoff_ms: 0,
        }
    }

    /// `max_attempts`, clamped to `1..=MAX_ATTEMPTS`.
    pub fn attempts(&self) -> u8 {
        self.max_attempts.clamp(1, Self::MAX_ATTEMPTS)
    }

    /// How long to wait before retry number `retry` (1 for the first retry):
    /// `backoff_ms * 2^(retry - 1)`, at most `max_backoff_ms`.
    pub fn backoff(&self, retry: u32) -> std::time::Duration {
        let shift = retry.saturating_sub(1).min(16);
        let ms = self
            .backoff_ms
            .saturating_mul(1u64 << shift)
            .min(self.max_backoff_ms);
        std::time::Duration::from_millis(ms)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: Self::DEFAULT_MAX_ATTEMPTS,
            backoff_ms: Self::DEFAULT_BACKOFF_MS,
            max_backoff_ms: Self::DEFAULT_MAX_BACKOFF_MS,
        }
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
    /// What to do after a failure that is not the task's own fault (spec
    /// §7.1, §7.6). Defaults to [`RetryPolicy::default`] when absent.
    #[serde(default)]
    pub retry: RetryPolicy,
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
            retry: RetryPolicy::default(),
        }
    }
}

/// Channel parameters for a streaming task (spec §7.1).
///
/// Every limit is declared by the submitter and enforced by **both** ends:
/// the executor refuses to exceed it and the submitter tears the stream down
/// if the executor does anyway (defense in depth, §7.1 DoS table).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChannelSpec {
    /// Maximum size of a single chunk in bytes (default: 1 MiB).
    pub max_chunk_bytes: u64,
    /// Maximum cumulative transfer size in bytes, per direction (default:
    /// 256 MiB). Crossing it closes the stream with `TotalBytesExceeded`.
    pub max_total_bytes: u64,
    /// Back-pressure credit window in chunk units (default: 16): the
    /// executor may have at most this many chunks unacknowledged.
    pub credit_window: u32,
    /// Heartbeat interval in milliseconds (default: 5 000). Three
    /// consecutive missed pongs close the stream with `PeerLost`.
    pub heartbeat_ms: u32,
    /// How long, in milliseconds, an executor with zero credit waits for a
    /// `Credit` frame before it reports the stream as stalled — the spec's
    /// `task_timeout` / `credit_exhaustion_timeout` (default: 30 minutes).
    /// A stall that lasts twice this long cancels the stream.
    #[serde(default = "ChannelSpec::default_credit_exhaustion_timeout_ms")]
    pub credit_exhaustion_timeout_ms: u64,
}

impl ChannelSpec {
    /// Default `max_chunk_bytes` (1 MiB).
    pub const DEFAULT_MAX_CHUNK_BYTES: u64 = 1024 * 1024;
    /// Default `max_total_bytes` (256 MiB).
    pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
    /// Default `credit_window` (16 chunks).
    pub const DEFAULT_CREDIT_WINDOW: u32 = 16;
    /// Default `heartbeat_ms` (5 s).
    pub const DEFAULT_HEARTBEAT_MS: u32 = 5_000;
    /// Default `credit_exhaustion_timeout_ms` (30 minutes, spec §7.1).
    pub const DEFAULT_CREDIT_EXHAUSTION_TIMEOUT_MS: u64 = 30 * 60 * 1_000;

    fn default_credit_exhaustion_timeout_ms() -> u64 {
        Self::DEFAULT_CREDIT_EXHAUSTION_TIMEOUT_MS
    }
}

impl Default for ChannelSpec {
    fn default() -> Self {
        Self {
            max_chunk_bytes: Self::DEFAULT_MAX_CHUNK_BYTES,
            max_total_bytes: Self::DEFAULT_MAX_TOTAL_BYTES,
            credit_window: Self::DEFAULT_CREDIT_WINDOW,
            heartbeat_ms: Self::DEFAULT_HEARTBEAT_MS,
            credit_exhaustion_timeout_ms: Self::DEFAULT_CREDIT_EXHAUSTION_TIMEOUT_MS,
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
    /// Keep partial results only if they carry a valid executor signature
    /// (the signed chunk transcript is kept with them, for attribution).
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
    /// Initial input (prompt, parameters) handed to the plugin's
    /// `start-stream` export. Further input may follow as inbound chunks.
    #[serde(default)]
    pub input: Vec<u8>,
    /// Maximum accepted size of `input` in bytes (default: 16 MiB).
    #[serde(default = "StreamingTask::default_max_input_bytes")]
    pub max_input_bytes: u64,
    /// Channel configuration.
    pub channel: ChannelSpec,
    /// Resource requirements for the task.
    pub resources: ResourceSpec,
    /// Integrity verification policy. Only `TrustedExecutor` and `None` are
    /// valid for a stream (§7.5); the scheduler refuses the others at submit
    /// time.
    pub integrity: IntegrityPolicy,
    /// Wall-clock timeout for the whole stream, in milliseconds.
    pub timeout_ms: u64,
    /// Partial-result retention policy.
    pub partial_result: PartialResultPolicy,
    /// What to do when the stream fails for a reason that is not its own
    /// fault (spec §7.1: "retries restart from `initial_inputs` only"). A
    /// stream that fails before the consumer received any chunk is restarted
    /// from [`StreamingTask::input`] on another executor; one that already
    /// delivered chunks only with [`StreamingTask::restart_after_delivery`].
    #[serde(default)]
    pub retry: RetryPolicy,
    /// Opt in to restarting a stream that already delivered chunks. Every
    /// chunk of a restart carries a new attempt **epoch** and starts again
    /// at sequence 0, so the consumer can tell a re-delivered chunk from a
    /// new one and discard the duplicates. Default `false`: a stream that
    /// delivered output is never restarted behind the consumer's back.
    #[serde(default)]
    pub restart_after_delivery: bool,
    /// The output the submitter expects, in bytes, if it knows (e.g. an
    /// LLM's `max_tokens` times a typical token length). Only used to judge
    /// stalls: an executor that stalls after delivering at least half of it
    /// loses reputation (spec §7.1, "stall blame"). Never sent to the
    /// executor.
    #[serde(default)]
    pub expected_output_bytes: Option<u64>,
}

impl StreamingTask {
    /// Default for `max_input_bytes` (16 MiB, as for a one-shot task).
    pub const DEFAULT_MAX_INPUT_BYTES: u64 = OneShotTask::DEFAULT_MAX_INPUT_BYTES;
    /// Default wall-clock timeout for a whole stream (1 hour).
    pub const DEFAULT_TIMEOUT_MS: u64 = 60 * 60 * 1_000;

    fn default_max_input_bytes() -> u64 {
        Self::DEFAULT_MAX_INPUT_BYTES
    }

    /// A streaming task with spec-default channel limits, `IntegrityPolicy::None`
    /// and `PartialResultPolicy::Keep`.
    pub fn with_defaults(plugin: PluginId, input: Vec<u8>) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            plugin,
            input,
            max_input_bytes: Self::DEFAULT_MAX_INPUT_BYTES,
            channel: ChannelSpec::default(),
            resources: ResourceSpec::default(),
            integrity: IntegrityPolicy::None,
            timeout_ms: Self::DEFAULT_TIMEOUT_MS,
            partial_result: PartialResultPolicy::Keep,
            retry: RetryPolicy::default(),
            restart_after_delivery: false,
            expected_output_bytes: None,
        }
    }
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
        assert_eq!(c.credit_exhaustion_timeout_ms, 30 * 60 * 1_000);
    }

    /// A channel spec serialised before `credit_exhaustion_timeout_ms`
    /// existed still deserialises, with the spec default.
    #[test]
    fn channel_spec_without_credit_timeout_gets_the_default() {
        let old =
            r#"{"max_chunk_bytes":10,"max_total_bytes":100,"credit_window":2,"heartbeat_ms":50}"#;
        let c: ChannelSpec = serde_json::from_str(old).unwrap();
        assert_eq!(
            c.credit_exhaustion_timeout_ms,
            ChannelSpec::DEFAULT_CREDIT_EXHAUSTION_TIMEOUT_MS
        );
        assert_eq!(c.credit_window, 2);
    }

    #[test]
    fn streaming_task_defaults_and_round_trip() {
        let plugin: PluginId = "0123456789abcdef0123456789abcdef/s@0.1.0".parse().unwrap();
        let task = StreamingTask::with_defaults(plugin, b"prompt".to_vec());
        assert_eq!(task.max_input_bytes, 16 * 1024 * 1024);
        assert_eq!(task.integrity, IntegrityPolicy::None);
        assert_eq!(task.partial_result, PartialResultPolicy::Keep);
        assert_eq!(task.channel, ChannelSpec::default());
        let json = serde_json::to_string(&task).unwrap();
        let back: StreamingTask = serde_json::from_str(&json).unwrap();
        assert_eq!(back.input, b"prompt");
        assert_eq!(back.id, task.id);
        assert_eq!(back.channel, task.channel);
    }

    #[test]
    fn retry_policy_defaults_backoff_and_clamps() {
        let p = RetryPolicy::default();
        assert_eq!(p.attempts(), 3);
        assert_eq!(p.backoff(1).as_millis(), 200);
        assert_eq!(p.backoff(2).as_millis(), 400);
        assert_eq!(p.backoff(3).as_millis(), 800);
        assert_eq!(p.backoff(30).as_millis(), 5_000, "capped at max_backoff_ms");
        assert_eq!(RetryPolicy::never().attempts(), 1);
        let wild = RetryPolicy {
            max_attempts: 200,
            ..RetryPolicy::default()
        };
        assert_eq!(wild.attempts(), RetryPolicy::MAX_ATTEMPTS);
        let zero = RetryPolicy {
            max_attempts: 0,
            ..RetryPolicy::default()
        };
        assert_eq!(zero.attempts(), 1, "0 attempts still runs the task once");
    }

    /// A task serialised before `retry` existed gets the default policy;
    /// a partial policy fills in the rest.
    #[test]
    fn retry_policy_is_optional_on_the_wire() {
        let plugin: PluginId = "0123456789abcdef0123456789abcdef/s@0.1.0".parse().unwrap();
        let task = OneShotTask::with_defaults(plugin.clone(), b"x".to_vec());
        let mut json = serde_json::to_value(&task).unwrap();
        json.as_object_mut().unwrap().remove("retry");
        let back: OneShotTask = serde_json::from_value(json).unwrap();
        assert_eq!(back.retry, RetryPolicy::default());
        let partial: RetryPolicy = serde_json::from_str(r#"{"max_attempts":1}"#).unwrap();
        assert_eq!(
            partial,
            RetryPolicy {
                max_attempts: 1,
                ..RetryPolicy::default()
            }
        );

        let stream = StreamingTask::with_defaults(plugin, b"p".to_vec());
        let mut json = serde_json::to_value(&stream).unwrap();
        for k in ["retry", "restart_after_delivery", "expected_output_bytes"] {
            json.as_object_mut().unwrap().remove(k);
        }
        let back: StreamingTask = serde_json::from_value(json).unwrap();
        assert_eq!(back.retry, RetryPolicy::default());
        assert!(!back.restart_after_delivery);
        assert_eq!(back.expected_output_bytes, None);
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

    /// A policy in the pre-replication shape (`metric` was a bare name and
    /// there were no `replicas` / `quorum`) is refused with an error that
    /// says what the shape is now, not a bare serde type mismatch.
    #[test]
    fn old_shape_semantic_equivalent_explains_the_new_shape() {
        let old = r#"{"kind":"semantic-equivalent","metric":"cosine","threshold":0.9}"#;
        let err = serde_json::from_str::<IntegrityPolicy>(old)
            .unwrap_err()
            .to_string();
        for needle in ["pinned metric reference", "replicas", "quorum", "cosine"] {
            assert!(err.contains(needle), "missing {needle:?} in: {err}");
        }

        #[derive(serde::Deserialize, Debug)]
        struct Wrapper {
            #[allow(dead_code)]
            policy: IntegrityPolicy,
        }
        let toml_old =
            "[policy]\nkind = \"semantic-equivalent\"\nmetric = \"bleu\"\nthreshold = 0.85\n";
        let err = toml::from_str::<Wrapper>(toml_old).unwrap_err().to_string();
        assert!(err.contains("pinned metric reference"), "{err}");

        // The current shape is unaffected, including MetricRef's own errors.
        let mut json = serde_json::to_value(semantic()).unwrap();
        assert!(serde_json::from_value::<IntegrityPolicy>(json.clone()).is_ok());
        json["metric"]["artifact_blake3"] = serde_json::Value::String("abcd".into());
        let err = serde_json::from_value::<IntegrityPolicy>(json)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected 32 bytes"), "{err}");
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
