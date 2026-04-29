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
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum IntegrityPolicy {
    /// Run `replicas` identical copies; require identical byte-for-byte outputs.
    Deterministic {
        /// Number of independent execution replicas.
        replicas: u8,
    },
    /// Accept outputs that are semantically equivalent within a distance metric.
    SemanticEquivalent {
        /// Name of the metric (e.g. `"cosine"`, `"rouge-l"`).
        metric: String,
        /// Minimum similarity threshold in `[0.0, 1.0]`.
        threshold: f32,
    },
    /// Accept output only from explicitly allow-listed peers.
    TrustedExecutor {
        /// Peers whose outputs are trusted without further verification.
        allowlist: Vec<PeerId>,
    },
    /// Require a Trusted Execution Environment attestation report.
    Attested {
        /// TEE kind identifier (e.g. `"sgx"`, `"sev"`, `"trustzone"`).
        tee: String,
    },
    /// No integrity checking; accept the first response.
    None,
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
}
