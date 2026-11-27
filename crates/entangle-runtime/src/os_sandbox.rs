//! Host observations reported by the CLI for tier-5 native plugins.
//!
//! The probe reads kernel information and system tool metadata. It does not
//! test sandbox enforcement or enable the native plugin loader.

/// Current native plugin loading behavior shown alongside host observations.
pub const NATIVE_RUNNER_STATUS: &str =
    "This build refuses native plugins because it has no sandboxed native runner.";

/// Result of a sandbox probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxProbe {
    /// The system sandbox-exec file has execute permission bits.
    SeatbeltAvailable,
    /// The kernel lists Landlock as an active Linux Security Module.
    LandlockAvailable,
    /// The system bubblewrap file has execute permission bits.
    BubblewrapFallback,
    /// No positive indicator was observed on this host.
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
    /// `true` when the probe observed a host indicator. This does not establish enforcement.
    pub const fn is_available(&self) -> bool {
        matches!(
            self,
            Self::SeatbeltAvailable | Self::LandlockAvailable | Self::BubblewrapFallback
        )
    }

    /// Short, operator-facing description suitable for `entangle doctor`.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::SeatbeltAvailable => "found /usr/bin/sandbox-exec with execute permission bits",
            Self::LandlockAvailable => "the kernel lists Landlock in /sys/kernel/security/lsm",
            Self::BubblewrapFallback => "found /usr/bin/bwrap with execute permission bits",
            Self::NoneAvailable { reason } => reason,
            Self::Unsupported { reason } => reason,
        }
    }
}

/// Look for OS sandbox indicators at system paths for the current host.
///
/// The probe never spawns a process or engages a sandbox.
pub fn probe() -> SandboxProbe {
    #[cfg(target_os = "macos")]
    {
        if has_execute_bits("/usr/bin/sandbox-exec") {
            return SandboxProbe::SeatbeltAvailable;
        }
        return SandboxProbe::NoneAvailable {
            reason: "no executable /usr/bin/sandbox-exec observed",
        };
    }

    #[cfg(target_os = "linux")]
    {
        if landlock_listed() {
            return SandboxProbe::LandlockAvailable;
        }
        if has_execute_bits("/usr/bin/bwrap") {
            return SandboxProbe::BubblewrapFallback;
        }
        return SandboxProbe::NoneAvailable {
            reason: "no Landlock listing or executable /usr/bin/bwrap observed",
        };
    }

    #[cfg(target_os = "windows")]
    {
        return SandboxProbe::Unsupported {
            reason: "native Windows AppContainer support is Phase 5+",
        };
    }

    #[allow(unreachable_code)]
    SandboxProbe::Unsupported {
        reason: "no sandbox primitive supported on this platform",
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn has_execute_bits(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(target_os = "linux")]
fn landlock_listed() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .is_ok_and(|list| list.split(',').any(|name| name.trim() == "landlock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_a_known_variant() {
        let p = probe();
        // Sanity: it must be one of the variants, and its description
        // must be a non-empty string.
        assert!(!p.description().is_empty());
    }

    #[test]
    fn positive_indicators_describe_only_the_observed_kernel_or_file_state() {
        assert_eq!(
            SandboxProbe::SeatbeltAvailable.description(),
            "found /usr/bin/sandbox-exec with execute permission bits"
        );
        assert_eq!(
            SandboxProbe::LandlockAvailable.description(),
            "the kernel lists Landlock in /sys/kernel/security/lsm"
        );
        assert_eq!(
            SandboxProbe::BubblewrapFallback.description(),
            "found /usr/bin/bwrap with execute permission bits"
        );
    }

    #[test]
    fn is_available_matrix() {
        assert!(SandboxProbe::SeatbeltAvailable.is_available());
        assert!(SandboxProbe::LandlockAvailable.is_available());
        assert!(SandboxProbe::BubblewrapFallback.is_available());
        assert!(!SandboxProbe::NoneAvailable { reason: "x" }.is_available());
        assert!(!SandboxProbe::Unsupported { reason: "y" }.is_available());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_probe_does_not_panic() {
        // On Linux the result depends on the kernel + binaries; whatever it
        // returns, it must be a Linux-compatible variant.
        let p = probe();
        match p {
            SandboxProbe::LandlockAvailable
            | SandboxProbe::BubblewrapFallback
            | SandboxProbe::NoneAvailable { .. } => {}
            other => panic!("unexpected probe on Linux: {other:?}"),
        }
    }
}
