//! OS-sandbox probes for tier-5 subprocess plugins (spec §0.2, §3.4, §3.5).
//!
//! A thin, `unsafe`-free façade over `entangle-sandbox`, which does the real
//! work: [`probe`] reports the primitive this host offers (Landlock is
//! detected through the `landlock_create_ruleset` ABI-version query — there is
//! no `/proc/sys/kernel/landlock/status` file to read), [`plan_for`] reports
//! the full set of layers that *would* be engaged for a profile, and
//! [`trial`] actually engages it on two trivial children. The doctor command,
//! `entangle print-platform`, and the native-plugin loader all use these.

pub use entangle_sandbox::trial::TrialOutcome;
pub use entangle_sandbox::{HostSupport, Plan, Policy, SandboxError};

/// Summary of the sandbox primitive available on this host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxProbe {
    /// macOS Seatbelt via `sandbox-exec` is available.
    SeatbeltAvailable,
    /// Linux Landlock is available at this ABI version.
    LandlockAvailable {
        /// ABI version from the version query syscall.
        abi: u32,
    },
    /// No Landlock, but bubblewrap is present (fallback isolation).
    BubblewrapFallback,
    /// No supported sandbox primitive detected for this host.
    NoneAvailable {
        /// Operator-facing reason string.
        reason: &'static str,
    },
    /// The current platform has no sandbox support in this version of Entanglement.
    Unsupported {
        /// Operator-facing reason string (e.g. `"native Windows is Phase 5+"`).
        reason: &'static str,
    },
}

impl SandboxProbe {
    /// `true` when the probe found a usable primitive.
    pub const fn is_available(&self) -> bool {
        matches!(
            self,
            Self::SeatbeltAvailable | Self::LandlockAvailable { .. } | Self::BubblewrapFallback
        )
    }

    /// Short, operator-facing description suitable for `entangle doctor`.
    pub fn description(&self) -> String {
        match self {
            Self::SeatbeltAvailable => "macOS Seatbelt (sandbox-exec) available".to_owned(),
            Self::LandlockAvailable { abi } => format!("Linux Landlock available (ABI {abi})"),
            Self::BubblewrapFallback => {
                "Landlock unavailable; bubblewrap present (fallback isolation)".to_owned()
            }
            Self::NoneAvailable { reason } | Self::Unsupported { reason } => (*reason).to_owned(),
        }
    }
}

/// The detailed host support report (cached for the process lifetime).
pub fn host_support() -> &'static HostSupport {
    entangle_sandbox::probe()
}

/// Probe the OS sandbox primitive for the current host.
///
/// Performs no engagement on the calling process. On Linux the
/// user-namespace check forks one short-lived child (see `entangle-sandbox`).
pub fn probe() -> SandboxProbe {
    let h = host_support();
    match &h.platform {
        entangle_sandbox::Platform::Linux => match (h.landlock_abi, &h.bubblewrap) {
            (Some(abi), _) => SandboxProbe::LandlockAvailable { abi },
            (None, Some(_)) => SandboxProbe::BubblewrapFallback,
            (None, None) => SandboxProbe::NoneAvailable {
                reason: "neither Landlock nor bubblewrap available",
            },
        },
        entangle_sandbox::Platform::MacOs => match h.sandbox_exec {
            Some(_) => SandboxProbe::SeatbeltAvailable,
            None => SandboxProbe::NoneAvailable {
                reason: "sandbox-exec not found — Seatbelt unavailable",
            },
        },
        entangle_sandbox::Platform::Unsupported { reason } => SandboxProbe::Unsupported { reason },
    }
}

/// The layers that would be engaged for a native plugin with (or without)
/// network access under `policy` — or why it would be refused.
pub fn plan_for(allow_network: bool, policy: Policy) -> Result<Plan, SandboxError> {
    let profile =
        entangle_sandbox::SandboxProfile::new("/entangle/plugin").allow_network(allow_network);
    entangle_sandbox::plan(&profile, host_support(), policy)
}

/// Engage the sandbox for real on two trivial children (blocking): `true`
/// must run, and `cat` of a file outside the profile must fail.
pub fn trial(policy: Policy) -> TrialOutcome {
    entangle_sandbox::trial::run_trial(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_a_known_variant() {
        let p = probe();
        assert!(!p.description().is_empty());
    }

    #[test]
    fn is_available_matrix() {
        assert!(SandboxProbe::SeatbeltAvailable.is_available());
        assert!(SandboxProbe::LandlockAvailable { abi: 1 }.is_available());
        assert!(SandboxProbe::BubblewrapFallback.is_available());
        assert!(!SandboxProbe::NoneAvailable { reason: "x" }.is_available());
        assert!(!SandboxProbe::Unsupported { reason: "y" }.is_available());
    }

    #[test]
    fn landlock_description_names_the_abi() {
        let d = SandboxProbe::LandlockAvailable { abi: 7 }.description();
        assert!(d.contains("ABI 7"), "{d}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_probe_agrees_with_the_abi_syscall() {
        match (probe(), host_support().landlock_abi) {
            (SandboxProbe::LandlockAvailable { abi }, Some(real)) => assert_eq!(abi, real),
            (SandboxProbe::BubblewrapFallback | SandboxProbe::NoneAvailable { .. }, None) => {}
            (p, abi) => panic!("probe {p:?} disagrees with ABI query {abi:?}"),
        }
    }
}
