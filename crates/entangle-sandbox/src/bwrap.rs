//! bubblewrap fallback: render a [`SandboxProfile`] as a `bwrap` argv.
//!
//! Used on Linux hosts without Landlock. bubblewrap confines by construction:
//! the child gets a fresh mount namespace in which only the bind-mounted
//! allowlist exists, plus fresh user/PID/IPC/UTS/cgroup namespaces and — unless
//! the network is granted — a fresh network namespace.
//!
//! The environment is not passed with `--setenv`: the `bwrap` process itself
//! is started with a cleared environment holding only the profile's entries,
//! which it hands to the child unchanged (works on every bwrap version, unlike
//! `--clearenv`).

use std::ffi::OsString;
use std::path::Path;

use crate::profile::{
    SandboxProfile, LINUX_NETWORK_READ_ONLY, LINUX_SYSTEM_READ_EXEC, LINUX_SYSTEM_READ_ONLY,
};

/// Build the arguments that follow `bwrap` for `profile`.
///
/// `exists` decides which optional system paths are present on this host
/// (pass `|p| p.exists()`; tests pass a fixed set). Profile-named paths are
/// always bound — a missing one makes `bwrap` fail, which is the right
/// outcome for a storage scope that does not exist.
pub fn bwrap_args(profile: &SandboxProfile, exists: &dyn Fn(&Path) -> bool) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();
    let mut push = |items: &[&str]| a.extend(items.iter().map(OsString::from));
    push(&["--die-with-parent", "--new-session", "--unshare-all"]);
    if profile.allow_network {
        push(&["--share-net"]);
    }
    push(&[
        "--cap-drop",
        "ALL",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]);

    let mut bind = |flag: &str, p: &Path| {
        a.push(flag.into());
        a.push(p.as_os_str().to_owned());
        a.push(p.as_os_str().to_owned());
    };

    if profile.system_paths {
        // `--dev` already provides null/zero/random/urandom.
        let system = LINUX_SYSTEM_READ_EXEC
            .iter()
            .chain(LINUX_SYSTEM_READ_ONLY.iter())
            .chain(
                if profile.allow_network {
                    LINUX_NETWORK_READ_ONLY
                } else {
                    &[]
                }
                .iter(),
            )
            .map(Path::new)
            .filter(|p| !p.starts_with("/dev"));
        for p in system {
            if exists(p) {
                bind("--ro-bind", p);
            }
        }
    }
    for p in &profile.read_exec {
        bind("--ro-bind", p);
    }
    for p in &profile.read_only {
        bind("--ro-bind", p);
    }
    for p in &profile.read_write {
        bind("--bind", p);
    }
    bind("--ro-bind", &profile.program);

    a.push("--chdir".into());
    a.push(
        profile
            .cwd
            .as_deref()
            .unwrap_or(Path::new("/"))
            .as_os_str()
            .to_owned(),
    );
    a.push("--".into());
    a.push(profile.program.as_os_str().to_owned());
    a.extend(profile.args.iter().cloned());
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[OsString]) -> Vec<&str> {
        v.iter().map(|s| s.to_str().unwrap()).collect()
    }

    fn present(p: &Path) -> bool {
        matches!(
            p.to_str(),
            Some("/usr/lib") | Some("/lib64") | Some("/etc/ld.so.cache") | Some("/etc/resolv.conf")
        )
    }

    /// Position of the `flag src dst` triple binding `path`, if any.
    fn bound(args: &[&str], flag: &str, path: &str) -> bool {
        args.windows(3)
            .any(|w| w[0] == flag && w[1] == path && w[2] == path)
    }

    #[test]
    fn no_network_profile_unshares_everything() {
        let p = SandboxProfile::new("/opt/p/plugin")
            .arg("--serve")
            .read_write("/var/lib/entangle/data/p")
            .read_only("/opt/p/assets");
        let args = bwrap_args(&p, &present);
        let s = strs(&args);
        assert_eq!(
            &s[..3],
            &["--die-with-parent", "--new-session", "--unshare-all"]
        );
        assert!(!s.contains(&"--share-net"), "{s:?}");
        assert!(s.windows(2).any(|w| w == ["--cap-drop", "ALL"]));
        assert!(bound(&s, "--bind", "/var/lib/entangle/data/p"));
        assert!(bound(&s, "--ro-bind", "/opt/p/assets"));
        assert!(bound(&s, "--ro-bind", "/opt/p/plugin"));
        assert!(bound(&s, "--ro-bind", "/usr/lib"));
        assert!(bound(&s, "--ro-bind", "/lib64"));
        assert!(bound(&s, "--ro-bind", "/etc/ld.so.cache"));
        // Absent optional paths are not bound (bwrap would fail on them).
        assert!(!s.contains(&"/lib32"));
        // Network-only files are not exposed without the network.
        assert!(!s.contains(&"/etc/resolv.conf"));
        // The program and its arguments come last, after `--`.
        let dd = s.iter().position(|x| *x == "--").unwrap();
        assert_eq!(&s[dd + 1..], &["/opt/p/plugin", "--serve"]);
        assert!(s.windows(2).any(|w| w == ["--chdir", "/"]));
    }

    #[test]
    fn granted_network_shares_it_and_exposes_resolver_files() {
        let p = SandboxProfile::new("/opt/p/plugin").allow_network(true);
        let s = bwrap_args(&p, &present);
        let s = strs(&s);
        assert!(s.contains(&"--share-net"));
        assert!(bound(&s, "--ro-bind", "/etc/resolv.conf"));
    }

    #[test]
    fn storage_scopes_are_never_executable_binds() {
        // bwrap has no noexec flag per bind; the guarantee is that rw scopes
        // are bound with --bind and nothing else is writable.
        let p = SandboxProfile::new("/opt/p/plugin").read_write("/data");
        let s = bwrap_args(&p, &|_| false);
        let s = strs(&s);
        let writable: Vec<_> = s
            .windows(3)
            .filter(|w| w[0] == "--bind")
            .map(|w| w[1])
            .collect();
        assert_eq!(writable, vec!["/data"]);
    }
}
