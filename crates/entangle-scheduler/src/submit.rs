//! Submit-time checks and workload presets (spec §7.0, §7.1, §7.5).
//!
//! * **Determinism** — "`Deterministic` is rejected at submit if the
//!   manifest declares nondeterminism" (§7.5): a `Deterministic`
//!   (hash-quorum) task for a plugin whose manifest declares `pure = false`,
//!   a non-deterministic host function or a network, agent or mesh capability
//!   ([`entangle_manifest::determinism`]) fails before anything is placed,
//!   with [`SubmitError::NondeterministicPlugin`] naming the reasons and
//!   pointing at `SemanticEquivalent`. The submitter checks the manifest of
//!   the plugin its own kernel has loaded; an executor checks its own copy
//!   again before it runs a `Deterministic` replica, so a submitter that
//!   does not have the plugin is refused too.
//! * **Workload presets** — [`Workload`]: the spec's reference workloads
//!   (§7.0) with their default integrity policy (§7.5 table) and limits
//!   (§7.1), applied to a task before the caller's explicit settings.

use std::str::FromStr;

use entangle_runtime::Kernel;
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::{
    IntegrityPolicy, OneShotTask, PartialResultPolicy, RetryPolicy, StreamingTask,
};

/// A task refused at submit time by a check of this module
/// (`ENTANGLE-E0470`–`E0473`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SubmitError {
    /// `ENTANGLE-E0470` — a `Deterministic` task for a plugin whose
    /// manifest declares non-determinism. Nothing was placed or sent.
    #[error(
        "ENTANGLE-E0470: task uses Integrity::Deterministic but plugin {plugin} declares \
         nondeterminism ({reasons}): its replicas cannot be expected to agree byte for byte. \
         hint: use Integrity::SemanticEquivalent with a metric (--integrity \
         semantic-equivalent --metric <metric-bleu-4 | metric-embedding-cosine | \
         metric-numerical-l2-relative> --threshold <d>), or trusted-executor"
    )]
    NondeterministicPlugin {
        /// The plugin.
        plugin: String,
        /// What its manifest declares, joined with `; `.
        reasons: String,
    },
    /// `ENTANGLE-E0471` — a workload name that is not `a`, `b`,
    /// `b-federated` or `c`.
    #[error(
        "ENTANGLE-E0471: unknown workload {0:?} (expected a, b, b-federated or c — the spec \
         §7.0 reference workloads)"
    )]
    UnknownWorkload(String),
    /// `ENTANGLE-E0472` — workload A's `TrustedExecutor` preset needs the
    /// executors to trust and none were given.
    #[error(
        "ENTANGLE-E0472: workload a (LLM offload to your own machine) dispatches with \
         Integrity::TrustedExecutor and needs the node ids you trust as executors: pass \
         --allow <your-own-node-id> (or --peer for a stream)"
    )]
    PresetNeedsExecutors,
    /// `ENTANGLE-E0473` — a one-shot-only workload preset used for a
    /// stream.
    #[error(
        "ENTANGLE-E0473: workload {0} is a batch workload of one-shot tasks; streams take \
         workload a (or no preset)"
    )]
    PresetNotForStreams(&'static str),
}

/// Why `plugin`'s manifest says its runs may differ, if `kernel` has it
/// loaded: what the manifest **verified at load** declares (the kernel
/// records it from the verified bytes; the file in the package directory
/// is not read again, so editing or deleting it later changes nothing).
/// `None` when the plugin is not loaded here; `Some(Err(_))` when its
/// declaration keys have the wrong type and cannot be read.
pub fn declared_nondeterminism(
    kernel: &Kernel,
    plugin: &PluginId,
) -> Option<Result<Vec<String>, String>> {
    let resolved = kernel.resolve(plugin)?;
    Some(kernel.loaded_source(&resolved)?.nondeterminism)
}

/// Refuse a `Deterministic` policy for `plugin` when `kernel`'s copy of it
/// declares non-determinism — or declares it in a form that cannot be read
/// (fail closed). Any other policy, and a plugin not loaded here, pass.
pub fn check_determinism(
    kernel: &Kernel,
    plugin: &PluginId,
    policy: &IntegrityPolicy,
) -> Result<(), SubmitError> {
    if !matches!(policy, IntegrityPolicy::Deterministic { .. }) {
        return Ok(());
    }
    let reasons = match declared_nondeterminism(kernel, plugin) {
        None => return Ok(()),
        Some(Ok(reasons)) => reasons,
        Some(Err(why)) => vec![format!(
            "its manifest's `pure` / `nondeterministic` declaration cannot be read ({}), \
             so it cannot be taken as deterministic",
            why.trim()
        )],
    };
    if reasons.is_empty() {
        return Ok(());
    }
    Err(SubmitError::NondeterministicPlugin {
        plugin: plugin.to_string(),
        reasons: reasons.join("; "),
    })
}

/// The reference workloads of spec §7.0, as presets.
///
/// A preset sets the spec's default integrity policy for the workload
/// (§7.5 table) and its limits (§7.1); apply it first and then whatever
/// the caller set explicitly, so explicit settings win.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Workload {
    /// A — LLM inference offload to the user's own machine:
    /// `TrustedExecutor { allowlist: <own node ids> }`, replication 1; a
    /// one-shot response is capped at 1 MiB (`max_output_bytes`), a stream
    /// at 64 MiB (`max_total_bytes`) with a 32-chunk credit window and
    /// partial results kept.
    A,
    /// B — batch image processing across a trusted home cluster:
    /// `Deterministic { replicas: 1 }`. One-shot only.
    B,
    /// B on a federated mesh: `Deterministic { 3, 2 }` (three replicas, a
    /// strict-majority quorum of two). One-shot only.
    BFederated,
    /// C — test-suite parallelisation: `Deterministic { replicas: 1 }`
    /// and the standard retry policy (three attempts: a crashed or lost
    /// worker is retried). A failing test — a plugin error or a failing
    /// output — is **not** re-run: the spec's "rerun on flake" is not
    /// implemented. One-shot only.
    C,
}

impl Workload {
    /// Workload A's one-shot `max_output_bytes` (1 MiB, spec §7.1).
    pub const A_MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
    /// Workload A's streaming `max_total_bytes` (64 MiB, spec §7.1).
    pub const A_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    /// Workload A's credit window (32 chunks, spec §7.0).
    pub const A_CREDIT_WINDOW: u32 = 32;

    /// The CLI spelling: `a`, `b`, `b-federated`, `c`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
            Self::BFederated => "b-federated",
            Self::C => "c",
        }
    }

    /// The preset's integrity policy, given the executors to trust (used
    /// by workload A only).
    pub fn integrity(self, executors: &[PeerId]) -> Result<IntegrityPolicy, SubmitError> {
        Ok(match self {
            Self::A => {
                if executors.is_empty() {
                    return Err(SubmitError::PresetNeedsExecutors);
                }
                IntegrityPolicy::TrustedExecutor {
                    allowlist: executors.to_vec(),
                }
            }
            Self::B | Self::C => IntegrityPolicy::Deterministic { replicas: 1 },
            Self::BFederated => IntegrityPolicy::Deterministic { replicas: 3 },
        })
    }

    /// Apply the preset to a one-shot task: integrity, `max_output_bytes`
    /// (A) and the retry policy (C).
    pub fn apply_one_shot(
        self,
        task: &mut OneShotTask,
        executors: &[PeerId],
    ) -> Result<(), SubmitError> {
        task.integrity = self.integrity(executors)?;
        match self {
            Self::A => task.max_output_bytes = Self::A_MAX_OUTPUT_BYTES,
            Self::C => {
                task.retry = RetryPolicy {
                    max_attempts: 3,
                    ..RetryPolicy::default()
                }
            }
            Self::B | Self::BFederated => {}
        }
        Ok(())
    }

    /// Apply the preset to a stream: integrity, `max_total_bytes`, the
    /// credit window and the partial-result policy. Only workload A
    /// streams.
    pub fn apply_stream(
        self,
        task: &mut StreamingTask,
        executors: &[PeerId],
    ) -> Result<(), SubmitError> {
        if self != Self::A {
            return Err(SubmitError::PresetNotForStreams(self.as_str()));
        }
        task.integrity = self.integrity(executors)?;
        task.channel.max_total_bytes = Self::A_MAX_TOTAL_BYTES;
        task.channel.credit_window = Self::A_CREDIT_WINDOW;
        // "partial results accepted (a half-streamed answer is still
        // useful to the user)".
        task.partial_result = PartialResultPolicy::Keep;
        Ok(())
    }
}

impl FromStr for Workload {
    type Err = SubmitError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "a" => Ok(Self::A),
            "b" => Ok(Self::B),
            "b-federated" => Ok(Self::BFederated),
            "c" => Ok(Self::C),
            other => Err(SubmitError::UnknownWorkload(other.to_owned())),
        }
    }
}

impl std::fmt::Display for Workload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin() -> PluginId {
        "0123456789abcdef0123456789abcdef/demo@1.0.0"
            .parse()
            .expect("id")
    }

    #[test]
    fn workload_a_one_shot_and_stream_defaults() {
        let me = PeerId::from_public_key_bytes(&[3; 32]);
        let mut t = OneShotTask::with_defaults(plugin(), vec![]);
        Workload::A.apply_one_shot(&mut t, &[me]).unwrap();
        assert_eq!(t.max_output_bytes, 1024 * 1024);
        assert_eq!(
            t.integrity,
            IntegrityPolicy::TrustedExecutor {
                allowlist: vec![me]
            }
        );
        let mut s = StreamingTask::with_defaults(plugin(), vec![]);
        Workload::A.apply_stream(&mut s, &[me]).unwrap();
        assert_eq!(s.channel.max_total_bytes, 64 * 1024 * 1024);
        assert_eq!(s.channel.credit_window, 32);
        assert_eq!(s.partial_result, PartialResultPolicy::Keep);
        assert_eq!(
            Workload::A.apply_one_shot(&mut t, &[]),
            Err(SubmitError::PresetNeedsExecutors)
        );
    }

    #[test]
    fn workloads_b_and_c_are_deterministic_one_shot_presets() {
        let mut t = OneShotTask::with_defaults(plugin(), vec![]);
        Workload::B.apply_one_shot(&mut t, &[]).unwrap();
        assert_eq!(t.integrity, IntegrityPolicy::Deterministic { replicas: 1 });
        assert_eq!(t.max_output_bytes, OneShotTask::DEFAULT_MAX_OUTPUT_BYTES);
        Workload::BFederated.apply_one_shot(&mut t, &[]).unwrap();
        assert_eq!(t.integrity, IntegrityPolicy::Deterministic { replicas: 3 });
        Workload::C.apply_one_shot(&mut t, &[]).unwrap();
        assert_eq!(t.integrity, IntegrityPolicy::Deterministic { replicas: 1 });
        assert_eq!(t.retry.attempts(), 3);
        let mut s = StreamingTask::with_defaults(plugin(), vec![]);
        for w in [Workload::B, Workload::BFederated, Workload::C] {
            let err = w.apply_stream(&mut s, &[]).unwrap_err();
            assert!(err.to_string().starts_with("ENTANGLE-E0473"), "{err}");
        }
    }

    #[test]
    fn workload_names_parse_and_codes_prefix_messages() {
        for w in [Workload::A, Workload::B, Workload::BFederated, Workload::C] {
            assert_eq!(w.as_str().parse::<Workload>(), Ok(w));
        }
        assert_eq!("A".parse::<Workload>(), Ok(Workload::A));
        let err = "d".parse::<Workload>().unwrap_err().to_string();
        assert!(err.starts_with("ENTANGLE-E0471"), "{err}");
        let e = SubmitError::NondeterministicPlugin {
            plugin: "p".into(),
            reasons: "pure = false".into(),
        }
        .to_string();
        assert!(
            e.starts_with("ENTANGLE-E0470") && e.contains("SemanticEquivalent"),
            "{e}"
        );
    }
}
