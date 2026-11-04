//! The host `tailscale` binary's version and the supported floor (spec §11
//! #17).
//!
//! `entangle-mesh-tailscale` trusts the host `tailscale` binary's JSON for
//! peer enumeration, so it pins a minimum: [`MIN_SUPPORTED_VERSION`]
//! (1.62.0). `entangle init` refuses to enable the transport below it and so
//! does the daemon at boot; the liveness poller logs the version on every
//! state transition.

use std::fmt;
use std::str::FromStr;

/// A Tailscale release version, `major.minor.patch`.
///
/// Ordered numerically, so `1.62.0 < 1.100.0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TailscaleVersion {
    /// Major version (`1` for every release so far).
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

/// The oldest `tailscale` this build supports (spec §11 #17: "`tailscale
/// version >= 1.62.0` checked at boot").
pub const MIN_SUPPORTED_VERSION: TailscaleVersion = TailscaleVersion::new(1, 62, 0);

impl TailscaleVersion {
    /// `major.minor.patch`.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse what `tailscale version` prints on its first line (`1.76.1`),
    /// or the status JSON's `Version` field (`1.76.1-t0123abcd-g4567ef`).
    ///
    /// Leading whitespace and a `v` are ignored, anything after the numeric
    /// part (`-t…`, a newline and the commit lines) too. The patch number may
    /// be omitted (`1.62` is `1.62.0`). `None` when no `major.minor` is
    /// there.
    pub fn parse(text: &str) -> Option<Self> {
        let first = text.lines().map(str::trim).find(|l| !l.is_empty())?;
        let first = first.strip_prefix('v').unwrap_or(first);
        let numeric: String = first
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let mut parts = numeric.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = match parts.next() {
            None | Some("") => 0,
            Some(p) => p.parse().ok()?,
        };
        Some(Self::new(major, minor, patch))
    }

    /// Whether this version is at least [`MIN_SUPPORTED_VERSION`].
    pub fn is_supported(self) -> bool {
        self >= MIN_SUPPORTED_VERSION
    }

    /// `Ok` when supported, otherwise the error that refuses the transport.
    pub fn check_supported(self) -> Result<Self, crate::MeshTailscaleError> {
        if self.is_supported() {
            Ok(self)
        } else {
            Err(crate::MeshTailscaleError::UnsupportedVersion {
                found: self,
                minimum: MIN_SUPPORTED_VERSION,
            })
        }
    }
}

impl fmt::Display for TailscaleVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for TailscaleVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| format!("not a tailscale version: {s:?}"))
    }
}

/// One login profile from `tailscale switch --list`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailscaleProfile {
    /// Profile id (what `tailscale switch` accepts, along with the names).
    pub id: String,
    /// Tailnet name (e.g. `corp.ts.net` or `example.com`).
    pub tailnet: String,
    /// Account (login name) of the profile.
    pub account: String,
    /// Whether this is the active profile (`*` in the listing).
    pub active: bool,
}

impl TailscaleProfile {
    /// Whether `name` designates this profile: its id, tailnet or account
    /// (case-insensitive for the last two).
    pub fn matches(&self, name: &str) -> bool {
        let name = name.trim();
        !name.is_empty()
            && (self.id == name
                || self.tailnet.eq_ignore_ascii_case(name)
                || self.account.eq_ignore_ascii_case(name))
    }
}

/// Parse the table `tailscale switch --list` prints:
///
/// ```text
/// ID    Tailnet      Account
/// 1a2b  example.com  alice@example.com*
/// 3c4d  corp.ts.net  admin@corp.ts.net
/// ```
///
/// The active profile's account carries a trailing `*`. A header row (first
/// column `ID`) and blank lines are skipped; a row with fewer than two
/// columns is ignored.
pub fn parse_profiles(text: &str) -> Vec<TailscaleProfile> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 || cols[0].eq_ignore_ascii_case("id") {
            continue;
        }
        let last = cols[cols.len() - 1];
        let (account, active) = match last.strip_suffix('*') {
            Some(a) => (a, true),
            None => (last, false),
        };
        let tailnet = if cols.len() > 2 {
            cols[1..cols.len() - 1].join(" ")
        } else {
            String::new()
        };
        out.push(TailscaleProfile {
            id: cols[0].to_owned(),
            tailnet,
            account: account.to_owned(),
            active,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_from_cli_and_json_forms() {
        let cli = "1.76.1\n  tailscale commit: abc\n  go version: go1.23.1\n";
        assert_eq!(
            TailscaleVersion::parse(cli),
            Some(TailscaleVersion::new(1, 76, 1))
        );
        assert_eq!(
            TailscaleVersion::parse("1.62.0-t0123abcd-g4567ef"),
            Some(TailscaleVersion::new(1, 62, 0))
        );
        assert_eq!(
            TailscaleVersion::parse("  v1.62\n"),
            Some(TailscaleVersion::new(1, 62, 0))
        );
        for bad in ["", "tailscale", "1", "x.y.z", "\n\n"] {
            assert_eq!(TailscaleVersion::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_floor_is_1_62_0_and_compares_numerically() {
        assert_eq!(MIN_SUPPORTED_VERSION.to_string(), "1.62.0");
        assert!(TailscaleVersion::new(1, 62, 0).is_supported());
        assert!(TailscaleVersion::new(1, 100, 0).is_supported());
        assert!(TailscaleVersion::new(2, 0, 0).is_supported());
        assert!(!TailscaleVersion::new(1, 61, 9).is_supported());
        assert!(!TailscaleVersion::new(1, 6, 200).is_supported());
        let err = TailscaleVersion::new(1, 58, 2)
            .check_supported()
            .unwrap_err();
        let text = err.to_string();
        assert!(text.starts_with("ENTANGLE-E0791"), "{text}");
        assert!(text.contains("1.58.2") && text.contains("1.62.0"), "{text}");
        assert!(
            text.contains("entangle config set mesh.tailscale.enabled false"),
            "{text}"
        );
    }

    #[test]
    fn switch_list_parses_the_active_profile() {
        let text = "ID    Tailnet      Account\n\
                    1a2b  example.com  alice@example.com*\n\
                    \n\
                    3c4d  corp.ts.net  admin@corp.ts.net\n";
        let p = parse_profiles(text);
        assert_eq!(p.len(), 2);
        assert!(p[0].active && !p[1].active);
        assert_eq!(p[0].account, "alice@example.com");
        assert_eq!(p[1].tailnet, "corp.ts.net");
        assert!(p[1].matches("corp.ts.net") && p[1].matches("3c4d"));
        assert!(p[1].matches("ADMIN@corp.ts.net") && !p[1].matches(""));
        assert!(parse_profiles("ID Tailnet Account\n").is_empty());
    }
}
