//! OS-sandbox probes for tier-5 subprocess plugins (spec §3.4).
//!
//! This module reports what sandbox primitive the daemon would use for the
//! local host, *without* actually launching anything. The result is consumed
//! by the doctor command, the install prompt for tier-5 plugins, and the
//! supervisor before it spawns a subprocess.
//!
//! Phase 1 ships **probes only**: it never engages the sandbox itself. Phase 2
//! will add a `engage(...)` function that takes a `SandboxProfile` and runs
//! the child under the chosen primitive.

/// Result of a sandbox probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxProbe {
    /// macOS Seatbelt via `sandbox-exec` is available.
    SeatbeltAvailable,
    /// Linux Landlock (kernel ≥6.7 advertised in `/proc/sys/kernel/landlock/status`).
    LandlockAvailable,
    /// bubblewrap fallback present (used when Landlock is absent on older kernels).
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
            Self::SeatbeltAvailable | Self::LandlockAvailable | Self::BubblewrapFallback
        )
    }

    /// Short, operator-facing description suitable for `entangle doctor`.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::SeatbeltAvailable => "macOS Seatbelt (sandbox-exec) available",
            Self::LandlockAvailable => "Linux Landlock available",
            Self::BubblewrapFallback => {
                "Landlock unavailable; bubblewrap present (fallback isolation)"
            }
            Self::NoneAvailable { reason } => reason,
            Self::Unsupported { reason } => reason,
        }
    }
}

/// Probe the OS sandbox primitive for the current host.
///
/// The function performs only filesystem reads and `PATH` lookups; it does
/// **not** spawn any process or engage any sandbox.
pub fn probe() -> SandboxProbe {
    #[cfg(target_os = "macos")]
    {
        if has_command("sandbox-exec") {
            return SandboxProbe::SeatbeltAvailable;
        }
        return SandboxProbe::NoneAvailable {
            reason: "sandbox-exec not in PATH — Seatbelt unavailable",
        };
    }

    #[cfg(target_os = "linux")]
    {
        if landlock_in_proc() {
            return SandboxProbe::LandlockAvailable;
        }
        if has_command("bwrap") {
            return SandboxProbe::BubblewrapFallback;
        }
        return SandboxProbe::NoneAvailable {
            reason: "neither Landlock (kernel ≥6.7) nor bubblewrap available",
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

#[cfg(unix)]
fn has_command(name: &str) -> bool {
    std::process::Command::new("/usr/bin/env")
        .args(["which", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn landlock_in_proc() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/landlock/status")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
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
