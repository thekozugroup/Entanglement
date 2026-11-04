//! Governance checks: `cargo xtask bus-factor` (ATC-BUS-1) and
//! `cargo xtask rotation-note-check` (ATC-BUS-2).
//!
//! These used to be inline Python in `.github/workflows/bus-factor.yml`, which
//! could not be tested. Everything here is a pure function over inputs
//! (a roles file, `git log` output, a rotations file, a clock) so the
//! integration tests in `tests/governance.rs` can drive both commands against
//! fixture repositories and files.
//!
//! # Bus factor (spec 12.1, INV-BUS-1)
//! `docs/maintainers/roles.toml`:
//! ```toml
//! [role.release-lead]
//! holders = ["alice", "bob"]
//!
//! # optional: extra identities for a handle (git author name / e-mail)
//! [identity.alice]
//! emails = ["alice@corp.example"]
//! names  = ["Alice Example"]
//! ```
//! A holder is *active* if they authored at least one merge commit
//! (`git log --merges`) in the trailing window (default 60 days). An author
//! matches a handle when the author name equals the handle
//! (case-insensitive), the e-mail local part equals the handle, the e-mail is
//! a GitHub noreply address (`<id>+<handle>@users.noreply.github.com`) for
//! the handle, or the name / e-mail is listed under `[identity.<handle>]`.
//! Every role must have at least [`MIN_ACTIVE_HOLDERS`] active holders.
//!
//! # Rotation note freshness (spec 12.1)
//! `docs/governance/rotations.md` holds notes under `## YYYY-MM-DD ...`
//! headings. The newest must be at most 35 days old.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Minimum number of active holders per role (INV-BUS-1).
pub const MIN_ACTIVE_HOLDERS: usize = 2;
/// Trailing window for "active", in days.
pub const ACTIVE_WINDOW_DAYS: u32 = 60;
/// Maximum age of the newest rotation note, in days.
pub const ROTATION_MAX_AGE_DAYS: i64 = 35;

/// Roles that must exist in the roster, whatever the file says.
pub const REQUIRED_ROLES: &[&str] = &[
    "core-runtime-lead",
    "mesh-lead",
    "agent-lead",
    "security-lead",
    "release-lead",
];

// ---------------------------------------------------------------------------
// Roster
// ---------------------------------------------------------------------------

/// Parsed `roles.toml`.
#[derive(Debug, Default)]
pub struct Roster {
    /// Role name -> holder handles.
    pub roles: BTreeMap<String, Vec<String>>,
    /// Handle (lowercase) -> extra e-mails (lowercase).
    pub emails: BTreeMap<String, Vec<String>>,
    /// Handle (lowercase) -> extra names (lowercase).
    pub names: BTreeMap<String, Vec<String>>,
}

fn string_list(v: Option<&toml::Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

impl Roster {
    /// Parse the roster from TOML text.
    pub fn parse(text: &str) -> Result<Self> {
        let doc: toml::Value = toml::from_str(text).context("parsing roles file")?;
        let mut r = Roster::default();
        if let Some(roles) = doc.get("role").and_then(|v| v.as_table()) {
            for (name, body) in roles {
                r.roles
                    .insert(name.clone(), string_list(body.get("holders")));
            }
        }
        if let Some(ids) = doc.get("identity").and_then(|v| v.as_table()) {
            for (handle, body) in ids {
                let h = handle.to_lowercase();
                r.emails.insert(
                    h.clone(),
                    string_list(body.get("emails"))
                        .iter()
                        .map(|s| s.to_lowercase())
                        .collect(),
                );
                r.names.insert(
                    h,
                    string_list(body.get("names"))
                        .iter()
                        .map(|s| s.to_lowercase())
                        .collect(),
                );
            }
        }
        Ok(r)
    }

    /// Does git author (`name`, `email`) correspond to `handle`?
    pub fn matches(&self, handle: &str, name: &str, email: &str) -> bool {
        let h = handle.to_lowercase();
        let (name, email) = (name.to_lowercase(), email.to_lowercase());
        if name == h {
            return true;
        }
        if let Some((local, domain)) = email.split_once('@') {
            if local == h {
                return true;
            }
            if domain == "users.noreply.github.com" {
                let user = local.rsplit_once('+').map_or(local, |(_, u)| u);
                if user == h {
                    return true;
                }
            }
        }
        self.emails.get(&h).is_some_and(|v| v.contains(&email))
            || self.names.get(&h).is_some_and(|v| v.contains(&name))
    }
}

// ---------------------------------------------------------------------------
// Bus factor
// ---------------------------------------------------------------------------

/// One merge commit's author.
#[derive(Debug, Clone)]
pub struct Merge {
    /// Author name.
    pub name: String,
    /// Author e-mail.
    pub email: String,
}

/// Per-role outcome.
#[derive(Debug)]
pub struct RoleStatus {
    /// Role name.
    pub role: String,
    /// Declared holders.
    pub holders: Vec<String>,
    /// Declared holders with at least one merge in the window.
    pub active: Vec<String>,
}

/// Result of [`evaluate_bus_factor`].
#[derive(Debug)]
pub struct BusFactorReport {
    /// One entry per role (required roles first-class even when absent).
    pub roles: Vec<RoleStatus>,
}

impl BusFactorReport {
    /// Human-readable violations (empty = invariant holds).
    pub fn violations(&self) -> Vec<String> {
        self.roles
            .iter()
            .filter(|r| r.active.len() < MIN_ACTIVE_HOLDERS)
            .map(|r| {
                format!(
                    "{}: {} active holder(s) of {} declared (need >= {}); active: [{}], declared: [{}]",
                    r.role,
                    r.active.len(),
                    r.holders.len(),
                    MIN_ACTIVE_HOLDERS,
                    r.active.join(", "),
                    r.holders.join(", ")
                )
            })
            .collect()
    }

    /// Markdown body for the P0 issue.
    pub fn issue_body(&self) -> String {
        let mut s = String::from("## P0: Bus Factor Violation (INV-BUS-1)\n\n");
        s.push_str(&format!(
            "The following roles have fewer than {MIN_ACTIVE_HOLDERS} active holders \
             (active = at least one merge in the trailing {ACTIVE_WINDOW_DAYS} days):\n\n"
        ));
        for v in self.violations() {
            s.push_str(&format!("- {v}\n"));
        }
        s.push_str(
            "\n**Required action**: seat additional active holders in \
             `docs/maintainers/roles.toml` and update `.github/CODEOWNERS`.\n\n\
             See spec section 12.1 (INV-BUS-1).\n",
        );
        s
    }
}

/// Count active holders per role. Pure: `merges` are the merge commits already
/// restricted to the trailing window.
pub fn evaluate_bus_factor(roster: &Roster, merges: &[Merge]) -> BusFactorReport {
    let mut names: BTreeSet<String> = roster.roles.keys().cloned().collect();
    names.extend(REQUIRED_ROLES.iter().map(|s| (*s).to_owned()));
    let roles = names
        .into_iter()
        .map(|role| {
            let holders = roster.roles.get(&role).cloned().unwrap_or_default();
            let mut seen = BTreeSet::new();
            let active = holders
                .iter()
                .filter(|h| seen.insert(h.to_lowercase()))
                .filter(|h| merges.iter().any(|m| roster.matches(h, &m.name, &m.email)))
                .cloned()
                .collect();
            RoleStatus {
                role,
                holders,
                active,
            }
        })
        .collect();
    BusFactorReport { roles }
}

/// Read merge authors from `git log --merges` for the trailing window.
pub fn git_merges(repo: &Path, now_unix: i64, window_days: u32) -> Result<Vec<Merge>> {
    let since = now_unix - i64::from(window_days) * 86_400;
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["log", "--merges", "--all"])
        // No --since/--until: git stops walking at the first commit outside
        // the range, which hides in-window merges behind an older one when
        // dates are not monotonic along history. Filter ourselves instead.
        .arg("--format=%an%x1f%ae%x1f%at")
        .output()
        .context("running git — is it on PATH?")?;
    if !out.status.success() {
        bail!(
            "git log failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split('\u{1f}');
            let (n, e, t) = (it.next()?, it.next()?, it.next()?);
            let t: i64 = t.trim().parse().ok()?;
            (since <= t && t <= now_unix).then(|| Merge {
                name: n.to_owned(),
                email: e.to_owned(),
            })
        })
        .collect())
}

/// Options for [`bus_factor`].
pub struct BusFactorOptions<'a> {
    /// Roles file.
    pub roles_file: &'a Path,
    /// Git repository to read merges from.
    pub repo: &'a Path,
    /// "Now" as a unix timestamp.
    pub now_unix: i64,
    /// Where to write the issue body when violations exist.
    pub report: Option<&'a Path>,
}

/// Run the bus-factor check. `Ok(violations)`; empty means the invariant holds.
pub fn bus_factor(opts: &BusFactorOptions<'_>) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(opts.roles_file)
        .with_context(|| format!("reading {}", opts.roles_file.display()))?;
    let roster = Roster::parse(&text)?;
    let merges = git_merges(opts.repo, opts.now_unix, ACTIVE_WINDOW_DAYS)?;
    let report = evaluate_bus_factor(&roster, &merges);
    for r in &report.roles {
        println!(
            "{:<20} {} active of {} declared ({})",
            r.role,
            r.active.len(),
            r.holders.len(),
            if r.active.len() >= MIN_ACTIVE_HOLDERS {
                "ok"
            } else {
                "VIOLATION"
            }
        );
    }
    let violations = report.violations();
    if let (Some(path), false) = (opts.report, violations.is_empty()) {
        std::fs::write(path, report.issue_body())
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(violations)
}

// ---------------------------------------------------------------------------
// Rotation notes
// ---------------------------------------------------------------------------

/// Days since 1970-01-01 for a proleptic Gregorian civil date.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYY-MM-DD` into days since the epoch, validating ranges.
pub fn parse_date(s: &str) -> Option<i64> {
    let mut it = s.split('-');
    let (y, m, d) = (
        it.next()?.parse::<i64>().ok()?,
        it.next()?.parse::<i64>().ok()?,
        it.next()?.parse::<i64>().ok()?,
    );
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) || s.len() != 10 {
        return None;
    }
    let days = days_from_civil(y, m, d);
    // Reject 2026-02-31 style dates by round-tripping through the next day.
    let mdays = days_from_civil(
        if m == 12 { y + 1 } else { y },
        if m == 12 { 1 } else { m + 1 },
        1,
    ) - days_from_civil(y, m, 1);
    (d <= mdays).then_some(days)
}

/// Dates of all `## YYYY-MM-DD` note headings in `text`.
pub fn note_dates(text: &str) -> Vec<(String, i64)> {
    text.lines()
        .filter_map(|l| l.strip_prefix("## "))
        .filter_map(|rest| {
            let date: String = rest.chars().take(10).collect();
            parse_date(&date).map(|d| (date, d))
        })
        .collect()
}

/// Check rotation-note freshness. `today` is days since the epoch.
/// `Ok(message)` when fresh; `Err` with the reason when not.
pub fn rotation_note_check(text: &str, today: i64, max_age_days: i64) -> Result<String> {
    let notes = note_dates(text);
    let Some((date, days)) = notes.iter().max_by_key(|(_, d)| *d) else {
        bail!("no rotation notes found (expected headings like `## 2026-01-31 - title`)");
    };
    let age = today - days;
    if age < 0 {
        bail!(
            "newest rotation note is dated {date}, in the future ({} day(s) ahead)",
            -age
        );
    }
    if age > max_age_days {
        bail!(
            "newest rotation note is {date}, {age} days old; the limit is {max_age_days} days. \
             Add a dated note to docs/governance/rotations.md before releasing."
        );
    }
    Ok(format!(
        "newest rotation note {date} is {age} day(s) old (limit {max_age_days})"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("2024-02-29"), Some(19_782));
        assert_eq!(parse_date("2025-02-29"), None);
        assert_eq!(parse_date("2025-13-01"), None);
        assert_eq!(parse_date("2025-1-01"), None);
    }

    #[test]
    fn author_matching() {
        let r = Roster::parse(
            "[role.a]\nholders=[\"alice\"]\n[identity.alice]\nemails=[\"al@corp.example\"]\nnames=[\"Alice E\"]\n",
        )
        .unwrap();
        assert!(r.matches("alice", "Alice", "x@y"));
        assert!(r.matches("alice", "z", "alice@host"));
        assert!(r.matches("alice", "z", "123+alice@users.noreply.github.com"));
        assert!(r.matches("alice", "z", "AL@corp.example"));
        assert!(r.matches("alice", "alice e", "q@q"));
        assert!(!r.matches("alice", "mallory", "mallory@users.noreply.github.com"));
    }
}
