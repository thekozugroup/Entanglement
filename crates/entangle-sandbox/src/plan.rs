//! Mechanism selection: from a [`SandboxProfile`] and a [`HostSupport`] to a
//! [`Plan`], or a refusal.
//!
//! This module is pure (no I/O) so that every branch — including hosts this
//! test machine is not, such as Ubuntu with restricted user namespaces or a
//! pre-Landlock kernel — is covered by unit tests.

use std::path::PathBuf;

use crate::error::SandboxError;
use crate::probe::{HostSupport, Platform};
use crate::profile::SandboxProfile;

/// Operator policy for native plugins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// `[security] allow_unsandboxed_native`: when `true`, a native plugin may
    /// run *without* an OS sandbox on a host that has none. Default `false`:
    /// such a plugin is refused with `ENTANGLE-E0700`. It has no effect on a
    /// host that does have a primitive — the sandbox is then always engaged.
    pub allow_unsandboxed: bool,
}

/// The filesystem-confinement mechanism.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mechanism {
    /// Linux Landlock at the given ABI version.
    Landlock {
        /// ABI version reported by the kernel.
        abi: u32,
    },
    /// Linux bubblewrap (bind-mount allowlist in fresh namespaces).
    Bubblewrap {
        /// The `bwrap` executable.
        path: PathBuf,
    },
    /// macOS Seatbelt via `sandbox-exec -p`.
    Seatbelt {
        /// The `sandbox-exec` executable.
        path: PathBuf,
    },
    /// No filesystem confinement — only under [`Policy::allow_unsandboxed`].
    /// rlimits, descriptor hygiene and (on Linux) `no_new_privs` and any
    /// available network layers still apply.
    Unsandboxed,
}

/// How completely the child is cut off from the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkIsolation {
    /// The profile grants networking.
    Granted,
    /// No IP networking at all (network namespace and/or seccomp socket
    /// filter, or the Seatbelt / bubblewrap equivalent).
    Denied,
    /// Reduced: only Landlock's TCP `bind`/`connect` rules apply. UDP and
    /// other protocols remain reachable.
    TcpOnly,
    /// Not granted but not isolated either — only under the operator opt-out.
    NotIsolated,
}

/// Everything the spawn step needs to know about which layers to engage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Filesystem confinement.
    pub mechanism: Mechanism,
    /// Linux: unshare a user + network namespace in the child.
    pub net_namespace: bool,
    /// Linux: install the seccomp socket-family filter.
    pub seccomp: bool,
    /// Linux/Landlock: handle (deny) TCP bind/connect (ABI ≥ 4).
    pub landlock_net: bool,
    /// Linux/Landlock: scope signals and abstract Unix sockets (ABI ≥ 6).
    pub landlock_scopes: bool,
    /// Linux: set `PR_SET_NO_NEW_PRIVS` in the child.
    pub no_new_privs: bool,
    /// Resulting network isolation.
    pub network: NetworkIsolation,
}

impl Plan {
    /// `true` when this plan isolates less than the profile asked for.
    ///
    /// Besides a missing filesystem or network layer this includes Landlock
    /// below ABI 6: without signal scoping (and with no PID namespace) the
    /// plugin, which runs under the daemon's uid, can signal the daemon and
    /// every other process of that user.
    pub fn is_degraded(&self) -> bool {
        matches!(self.mechanism, Mechanism::Unsandboxed)
            || matches!(
                self.network,
                NetworkIsolation::TcpOnly | NetworkIsolation::NotIsolated
            )
            || self.signals_unscoped()
    }

    /// Landlock without `LANDLOCK_SCOPE_SIGNAL` (ABI < 6): nothing stops the
    /// plugin from signalling processes outside its sandbox.
    fn signals_unscoped(&self) -> bool {
        matches!(self.mechanism, Mechanism::Landlock { .. }) && !self.landlock_scopes
    }

    /// Operator-facing summary, e.g. `Landlock ABI 7 + seccomp + user/net
    /// namespace; network denied`.
    pub fn describe(&self) -> String {
        let mut layers: Vec<String> = Vec::new();
        layers.push(match &self.mechanism {
            Mechanism::Landlock { abi } => format!("Landlock ABI {abi}"),
            Mechanism::Bubblewrap { .. } => "bubblewrap".to_owned(),
            Mechanism::Seatbelt { .. } => "Seatbelt".to_owned(),
            Mechanism::Unsandboxed => "NO filesystem sandbox (operator opt-out)".to_owned(),
        });
        if self.seccomp {
            layers.push("seccomp".to_owned());
        }
        if self.net_namespace {
            layers.push("user/net namespace".to_owned());
        }
        if self.landlock_net {
            layers.push("Landlock TCP rules".to_owned());
        }
        let net = match self.network {
            NetworkIsolation::Granted => "network granted",
            NetworkIsolation::Denied => "network denied",
            NetworkIsolation::TcpOnly => "network: TCP denied, UDP NOT isolated (reduced)",
            NetworkIsolation::NotIsolated => "network NOT isolated (operator opt-out)",
        };
        let mut out = format!("{}; {net}", layers.join(" + "));
        if self.signals_unscoped() {
            out.push_str(
                "; signals NOT scoped (Landlock ABI < 6: the plugin can signal the daemon)",
            );
        }
        out
    }
}

/// Choose the mechanisms for `profile` on `host`, or refuse.
///
/// Linux, in order of preference:
/// 1. **Landlock** (any ABI) when the network is granted, or when it can be
///    taken away by a user/net namespace, the seccomp socket filter, or (ABI
///    ≥ 4) Landlock TCP rules — the last alone yields
///    [`NetworkIsolation::TcpOnly`] and is reported as degraded.
/// 2. **bubblewrap** when Landlock is missing, or present but unable to
///    isolate the network.
/// 3. **Unsandboxed** only with [`Policy::allow_unsandboxed`]; otherwise
///    `ENTANGLE-E0700` (no primitive) or `ENTANGLE-E0701` (a primitive, but no
///    way to take the network away).
///
/// macOS: Seatbelt when `sandbox-exec` exists, else as step 3.
pub fn plan(
    profile: &SandboxProfile,
    host: &HostSupport,
    policy: Policy,
) -> Result<Plan, SandboxError> {
    match &host.platform {
        Platform::Linux => plan_linux(profile, host, policy),
        Platform::MacOs => match &host.sandbox_exec {
            Some(path) => Ok(Plan {
                mechanism: Mechanism::Seatbelt { path: path.clone() },
                net_namespace: false,
                seccomp: false,
                landlock_net: false,
                landlock_scopes: false,
                no_new_privs: false,
                network: granted_or(profile, NetworkIsolation::Denied),
            }),
            None if policy.allow_unsandboxed => Ok(Plan {
                mechanism: Mechanism::Unsandboxed,
                net_namespace: false,
                seccomp: false,
                landlock_net: false,
                landlock_scopes: false,
                no_new_privs: false,
                network: granted_or(profile, NetworkIsolation::NotIsolated),
            }),
            None => Err(SandboxError::Unavailable {
                reason: "sandbox-exec not found — Seatbelt unavailable".into(),
            }),
        },
        Platform::Unsupported { reason } => Err(SandboxError::UnsupportedPlatform {
            reason: (*reason).to_owned(),
        }),
    }
}

fn granted_or(profile: &SandboxProfile, otherwise: NetworkIsolation) -> NetworkIsolation {
    if profile.allow_network {
        NetworkIsolation::Granted
    } else {
        otherwise
    }
}

fn plan_linux(
    profile: &SandboxProfile,
    host: &HostSupport,
    policy: Policy,
) -> Result<Plan, SandboxError> {
    let mut network_blocker: Option<String> = None;

    if let Some(abi) = host.landlock_abi.filter(|a| *a >= 1) {
        let landlock_scopes = abi >= 6;
        if profile.allow_network {
            return Ok(Plan {
                mechanism: Mechanism::Landlock { abi },
                net_namespace: false,
                // Still filter socket families: raw/packet sockets, AF_UNIX
                // (unless granted) and io_uring stay off.
                seccomp: host.seccomp,
                landlock_net: false,
                landlock_scopes,
                no_new_privs: true,
                network: NetworkIsolation::Granted,
            });
        }
        let net_namespace = host.user_namespaces;
        let seccomp = host.seccomp;
        let landlock_net = abi >= 4;
        let network = if net_namespace || seccomp {
            Some(NetworkIsolation::Denied)
        } else if landlock_net {
            Some(NetworkIsolation::TcpOnly)
        } else {
            None
        };
        if let Some(network) = network {
            return Ok(Plan {
                mechanism: Mechanism::Landlock { abi },
                net_namespace,
                seccomp,
                landlock_net,
                landlock_scopes,
                no_new_privs: true,
                network,
            });
        }
        network_blocker = Some(format!(
            "Landlock ABI {abi} has no network rules (needs ABI 4), unprivileged user \
             namespaces are unavailable, and seccomp filters are unavailable"
        ));
    }

    if let Some(path) = &host.bubblewrap {
        return Ok(Plan {
            mechanism: Mechanism::Bubblewrap { path: path.clone() },
            net_namespace: false,
            seccomp: false,
            landlock_net: false,
            landlock_scopes: false,
            // bwrap sets no_new_privs itself; setting it on a setuid-root
            // bwrap would stop it from working at all.
            no_new_privs: false,
            network: granted_or(profile, NetworkIsolation::Denied),
        });
    }

    if policy.allow_unsandboxed {
        // No filesystem confinement, but keep whatever network layers exist.
        let (net_namespace, seccomp) = if profile.allow_network {
            (false, host.seccomp)
        } else {
            (host.user_namespaces, host.seccomp)
        };
        let network = if profile.allow_network {
            NetworkIsolation::Granted
        } else if net_namespace || seccomp {
            NetworkIsolation::Denied
        } else {
            NetworkIsolation::NotIsolated
        };
        return Ok(Plan {
            mechanism: Mechanism::Unsandboxed,
            net_namespace,
            seccomp,
            landlock_net: false,
            landlock_scopes: false,
            no_new_privs: true,
            network,
        });
    }

    match network_blocker {
        Some(reason) => Err(SandboxError::NetworkIsolationUnavailable { reason }),
        None => Err(SandboxError::Unavailable {
            reason: "neither Landlock (kernel ≥ 5.13, enabled) nor bubblewrap is available".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux(abi: Option<u32>, userns: bool, seccomp: bool, bwrap: bool) -> HostSupport {
        HostSupport {
            platform: Platform::Linux,
            landlock_abi: abi,
            user_namespaces: userns,
            seccomp,
            bubblewrap: bwrap.then(|| PathBuf::from("/usr/bin/bwrap")),
            sandbox_exec: None,
        }
    }

    fn no_net() -> SandboxProfile {
        SandboxProfile::new("/plugin/bin")
    }

    fn net() -> SandboxProfile {
        SandboxProfile::new("/plugin/bin").allow_network(true)
    }

    const STRICT: Policy = Policy {
        allow_unsandboxed: false,
    };
    const OPT_OUT: Policy = Policy {
        allow_unsandboxed: true,
    };

    /// This container: Landlock 7, user namespaces, seccomp.
    #[test]
    fn full_linux_host_engages_every_layer() {
        let p = plan(&no_net(), &linux(Some(7), true, true, false), STRICT).unwrap();
        assert_eq!(p.mechanism, Mechanism::Landlock { abi: 7 });
        assert!(p.net_namespace && p.seccomp && p.landlock_net && p.landlock_scopes);
        assert!(p.no_new_privs);
        assert_eq!(p.network, NetworkIsolation::Denied);
        assert!(!p.is_degraded());
    }

    /// GitHub's ubuntu-24.04: Landlock 4, user namespaces restricted by
    /// AppArmor, seccomp available. Network denial must not depend on the
    /// namespace.
    #[test]
    fn ubuntu_with_restricted_userns_still_denies_network() {
        let p = plan(&no_net(), &linux(Some(4), false, true, false), STRICT).unwrap();
        assert!(!p.net_namespace);
        assert!(p.seccomp && p.landlock_net);
        assert!(!p.landlock_scopes, "scopes need ABI 6");
        assert_eq!(p.network, NetworkIsolation::Denied);
    }

    /// Only Landlock TCP rules left: allowed, but reported as reduced.
    #[test]
    fn landlock_tcp_rules_alone_are_reported_as_reduced() {
        let p = plan(&no_net(), &linux(Some(4), false, false, false), STRICT).unwrap();
        assert_eq!(p.network, NetworkIsolation::TcpOnly);
        assert!(p.is_degraded());
        assert!(
            p.describe().contains("UDP NOT isolated"),
            "{}",
            p.describe()
        );
    }

    /// Below Landlock ABI 6 signals are not scoped: with no PID namespace the
    /// plugin shares the daemon's uid and can `kill(getppid(), SIGKILL)` or
    /// `kill(-1, SIGKILL)`. That is reduced isolation and must say so.
    #[test]
    fn unscoped_signals_are_reported_as_reduced() {
        for profile in [no_net(), net()] {
            for abi in [1, 4, 5] {
                let p = plan(&profile, &linux(Some(abi), true, true, false), STRICT).unwrap();
                assert!(!p.landlock_scopes);
                assert!(p.is_degraded(), "ABI {abi}: {}", p.describe());
                assert!(
                    p.describe().contains("signals NOT scoped"),
                    "{}",
                    p.describe()
                );
            }
            let p = plan(&profile, &linux(Some(6), true, true, false), STRICT).unwrap();
            assert!(!p.is_degraded(), "{}", p.describe());
            assert!(!p.describe().contains("NOT scoped"), "{}", p.describe());
        }
    }

    /// Landlock without any way to take the network: fall back to bwrap ...
    #[test]
    fn old_landlock_without_net_layers_falls_back_to_bwrap() {
        let p = plan(&no_net(), &linux(Some(3), false, false, true), STRICT).unwrap();
        assert!(matches!(p.mechanism, Mechanism::Bubblewrap { .. }));
        assert_eq!(p.network, NetworkIsolation::Denied);
    }

    /// ... or refuse with E0701 rather than silently allowing the network.
    #[test]
    fn old_landlock_without_net_layers_or_bwrap_refuses() {
        let err = plan(&no_net(), &linux(Some(3), false, false, false), STRICT).unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0701"), "{err}");
        // A plugin that *is* granted the network is fine on the same host.
        let p = plan(&net(), &linux(Some(3), false, false, false), STRICT).unwrap();
        assert_eq!(p.network, NetworkIsolation::Granted);
    }

    #[test]
    fn granted_network_keeps_the_socket_filter_but_no_namespace() {
        let p = plan(&net(), &linux(Some(7), true, true, false), STRICT).unwrap();
        assert!(!p.net_namespace && !p.landlock_net);
        assert!(p.seccomp, "raw sockets / AF_UNIX / io_uring still filtered");
        assert_eq!(p.network, NetworkIsolation::Granted);
    }

    #[test]
    fn no_landlock_uses_bwrap() {
        let p = plan(&no_net(), &linux(None, true, true, true), STRICT).unwrap();
        assert_eq!(
            p.mechanism,
            Mechanism::Bubblewrap {
                path: PathBuf::from("/usr/bin/bwrap")
            }
        );
        assert!(!p.no_new_privs, "bwrap may be setuid; it sets NNP itself");
    }

    #[test]
    fn nothing_available_refuses_with_e0700_by_default() {
        let err = plan(&no_net(), &linux(None, false, false, false), STRICT).unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0700"), "{err}");
        assert!(
            err.to_string().contains("allow_unsandboxed_native"),
            "{err}"
        );
    }

    #[test]
    fn opt_out_runs_unsandboxed_but_keeps_network_layers() {
        let p = plan(&no_net(), &linux(None, false, true, false), OPT_OUT).unwrap();
        assert_eq!(p.mechanism, Mechanism::Unsandboxed);
        assert_eq!(p.network, NetworkIsolation::Denied, "seccomp still applies");
        assert!(p.is_degraded());

        let p = plan(&no_net(), &linux(None, false, false, false), OPT_OUT).unwrap();
        assert_eq!(p.network, NetworkIsolation::NotIsolated);
        assert!(p.describe().contains("NOT isolated"));
    }

    /// The opt-out never weakens a host that has a primitive.
    #[test]
    fn opt_out_does_not_downgrade_an_available_sandbox() {
        let strict = plan(&no_net(), &linux(Some(7), true, true, false), STRICT).unwrap();
        let opted = plan(&no_net(), &linux(Some(7), true, true, false), OPT_OUT).unwrap();
        assert_eq!(strict, opted);
    }

    #[test]
    fn macos_uses_seatbelt_or_refuses() {
        let host = HostSupport {
            platform: Platform::MacOs,
            landlock_abi: None,
            user_namespaces: false,
            seccomp: false,
            bubblewrap: None,
            sandbox_exec: Some(PathBuf::from("/usr/bin/sandbox-exec")),
        };
        let p = plan(&no_net(), &host, STRICT).unwrap();
        assert!(matches!(p.mechanism, Mechanism::Seatbelt { .. }));
        assert_eq!(p.network, NetworkIsolation::Denied);

        let bare = HostSupport {
            sandbox_exec: None,
            ..host
        };
        let err = plan(&no_net(), &bare, STRICT).unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0700"), "{err}");
        let p = plan(&no_net(), &bare, OPT_OUT).unwrap();
        assert_eq!(p.mechanism, Mechanism::Unsandboxed);
    }

    #[test]
    fn unsupported_platform_is_refused_even_with_opt_out() {
        let host = HostSupport {
            platform: Platform::Unsupported { reason: "windows" },
            landlock_abi: None,
            user_namespaces: false,
            seccomp: false,
            bubblewrap: None,
            sandbox_exec: None,
        };
        let err = plan(&no_net(), &host, OPT_OUT).unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0705"), "{err}");
    }
}
