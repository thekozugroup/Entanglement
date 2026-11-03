//! macOS Seatbelt: render a [`SandboxProfile`] as an SBPL program for
//! `sandbox-exec -p`.
//!
//! The renderer is pure and compiled on every platform so its output is
//! unit-tested everywhere; only spawning `sandbox-exec` is macOS-specific.
//!
//! Seatbelt matches the *resolved* path of a vnode (`/tmp` is
//! `/private/tmp`), so the spawn path canonicalizes profile paths before
//! rendering.

use std::fmt::Write as _;
use std::path::Path;

use crate::error::SandboxError;
use crate::profile::SandboxProfile;

/// System locations a program needs to start on macOS: dyld, the shared
/// cache (under `/System`, including the Cryptex volume), system libraries,
/// time zones.
pub const MACOS_SYSTEM_READ: &[&str] = &[
    "/usr/lib",
    "/usr/share",
    "/System",
    "/Library/Apple",
    "/private/var/db/dyld",
    "/private/var/db/timezone",
    "/private/etc/localtime",
];

/// Character devices every program may read.
pub const MACOS_DEVICES_READ: &[&str] = &["/dev/urandom", "/dev/random", "/dev/zero"];

/// Resolver and trust-store files, readable only when networking is granted.
pub const MACOS_NETWORK_READ: &[&str] = &[
    "/private/etc/hosts",
    "/private/etc/resolv.conf",
    "/private/var/run/resolv.conf",
    "/private/etc/ssl",
];

/// Quote `p` as an SBPL string literal, escaping `\` and `"`.
fn quote(p: &Path) -> Result<String, SandboxError> {
    let s = p.to_str().ok_or_else(|| {
        SandboxError::InvalidProfile(format!(
            "path {} is not UTF-8 and cannot be expressed in a Seatbelt profile",
            p.display()
        ))
    })?;
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// Render the SBPL program for `profile`. Default-deny; every allowance is
/// derived from the profile.
pub fn seatbelt_profile(profile: &SandboxProfile) -> Result<String, SandboxError> {
    let mut s = String::new();
    let program = quote(&profile.program)?;
    // `writeln!` into a String cannot fail; the results are ignored for that
    // reason (fmt::Write for String is infallible).
    let _ = writeln!(s, "(version 1)");
    let _ = writeln!(s, "(deny default)");
    let _ = writeln!(s, "(allow process-exec (literal {program}))");
    let _ = writeln!(s, "(allow process-fork)");
    let _ = writeln!(s, "(allow signal (target same-sandbox))");
    let _ = writeln!(s, "(allow sysctl-read)");
    // Metadata (stat) only — never contents — outside the allowlist; dyld and
    // most runtimes stat their way up the tree.
    let _ = writeln!(s, "(allow file-read-metadata)");

    let mut reads: Vec<String> = Vec::new();
    if profile.system_paths {
        for p in MACOS_SYSTEM_READ {
            reads.push(format!("(subpath {})", quote(Path::new(p))?));
        }
        for p in MACOS_DEVICES_READ {
            reads.push(format!("(literal {})", quote(Path::new(p))?));
        }
        if profile.allow_network {
            for p in MACOS_NETWORK_READ {
                reads.push(format!("(subpath {})", quote(Path::new(p))?));
            }
        }
    }
    reads.push(format!("(literal {program})"));
    for p in &profile.read_only {
        reads.push(format!("(subpath {})", quote(p)?));
    }
    let _ = writeln!(s, "(allow file-read* {})", reads.join(" "));

    if profile.system_paths {
        let _ = writeln!(
            s,
            "(allow file-read* file-write-data (literal \"/dev/null\"))"
        );
    }
    for p in &profile.read_exec {
        let q = quote(p)?;
        let _ = writeln!(s, "(allow file-read* process-exec (subpath {q}))");
    }
    for p in &profile.read_write {
        let q = quote(p)?;
        let _ = writeln!(s, "(allow file-read* file-write* (subpath {q}))");
    }
    // Assumption (not run here): SBPL's `file-ioctl` operation gates ioctls on
    // a vnode, as in Apple's own profiles.
    for p in &profile.devices {
        let q = quote(p)?;
        let _ = writeln!(s, "(allow file-read* file-write* file-ioctl (subpath {q}))");
    }

    if profile.allow_network {
        let _ = writeln!(s, "(allow network-outbound (remote ip))");
        let _ = writeln!(s, "(allow network-inbound (local ip))");
        let _ = writeln!(s, "(allow network-bind (local ip))");
        let _ = writeln!(s, "(allow system-socket)");
        // Name resolution goes through mDNSResponder over Mach IPC.
        let _ = writeln!(
            s,
            "(allow mach-lookup (global-name \"com.apple.dnssd.service\") \
             (global-name \"com.apple.system.opendirectoryd.libinfo\"))"
        );
    }
    if profile.allow_unix_sockets {
        let _ = writeln!(s, "(allow network-outbound (remote unix-socket))");
        let _ = writeln!(s, "(allow system-socket)");
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_deny_with_only_the_program_executable() {
        let p = SandboxProfile::new("/Users/a/.entangle/native/p/plugin");
        let sb = seatbelt_profile(&p).unwrap();
        assert!(sb.starts_with("(version 1)\n(deny default)\n"), "{sb}");
        assert!(
            sb.contains("(allow process-exec (literal \"/Users/a/.entangle/native/p/plugin\"))")
        );
        assert_eq!(sb.matches("process-exec").count(), 1, "{sb}");
        // No network, no writes beyond /dev/null.
        assert!(!sb.contains("network-outbound"), "{sb}");
        assert!(!sb.contains("file-write*"), "{sb}");
        assert!(sb.contains("(subpath \"/System\")"));
    }

    #[test]
    fn scopes_map_to_read_and_write_rules() {
        let p = SandboxProfile::new("/p/bin")
            .read_only("/p/assets")
            .read_write("/data/p")
            .read_exec("/p/lib");
        let sb = seatbelt_profile(&p).unwrap();
        assert!(sb.contains("(subpath \"/p/assets\")"));
        assert!(sb.contains("(allow file-read* file-write* (subpath \"/data/p\"))"));
        assert!(sb.contains("(allow file-read* process-exec (subpath \"/p/lib\"))"));
    }

    #[test]
    fn only_device_grants_allow_ioctl() {
        let sb = seatbelt_profile(&SandboxProfile::new("/p/bin").read_write("/data")).unwrap();
        assert!(!sb.contains("file-ioctl"), "{sb}");
        let sb = seatbelt_profile(&SandboxProfile::new("/p/bin").device("/dev/gpu")).unwrap();
        assert!(sb.contains("(allow file-read* file-write* file-ioctl (subpath \"/dev/gpu\"))"));
    }

    #[test]
    fn network_and_unix_sockets_only_when_granted() {
        let sb = seatbelt_profile(&SandboxProfile::new("/p/bin").allow_network(true)).unwrap();
        assert!(sb.contains("(allow network-outbound (remote ip))"));
        assert!(sb.contains("com.apple.dnssd.service"));
        assert!(!sb.contains("unix-socket"));
        let sb = seatbelt_profile(&SandboxProfile::new("/p/bin").allow_unix_sockets(true)).unwrap();
        assert!(sb.contains("(remote unix-socket)"));
        assert!(!sb.contains("(remote ip)"));
    }

    #[test]
    fn quotes_and_backslashes_cannot_break_out_of_a_string() {
        let p = SandboxProfile::new("/p/bin").read_write(r#"/data/evil") (allow default) ("x\"#);
        let sb = seatbelt_profile(&p).unwrap();
        assert!(!sb.contains("(allow default)\n"), "{sb}");
        assert!(
            sb.contains(r#"(subpath "/data/evil\") (allow default) (\"x\\")"#),
            "{sb}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_rejected() {
        use std::os::unix::ffi::OsStrExt;
        let bad = std::ffi::OsStr::from_bytes(b"/data/\xff");
        let err = seatbelt_profile(&SandboxProfile::new("/p/bin").read_write(bad)).unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0704"), "{err}");
    }
}
