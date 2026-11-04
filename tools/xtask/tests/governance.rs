//! ATC-BUS-1 (bus factor) and ATC-BUS-2 (rotation-note freshness).
//!
//! Both commands are driven as real processes (`cargo xtask ...` equals the
//! `xtask` binary) against fixture git repositories and files in temp dirs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

/// 2026-06-30T00:00:00Z.
const NOW: i64 = 1_782_777_600;
const DAY: i64 = 86_400;

/// Make `cmd` ignore the caller's git configuration (hooks, signature
/// policies, `user.useConfigOnly`, ...) so fixtures behave the same
/// everywhere.
fn isolate_git(cmd: &mut Command) {
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
}

fn xtask() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_xtask"));
    isolate_git(&mut c);
    c
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}

fn git(dir: &Path, args: &[&str], env: &[(&str, String)]) {
    let mut cmd = Command::new("git");
    isolate_git(&mut cmd);
    let out = cmd
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "merge.verifySignatures=false",
            "-c",
            "user.useConfigOnly=false",
        ])
        .args(args)
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .output()
        .expect("git on PATH");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repo with a base commit, then one `--no-ff` merge per `(name, email,
/// unix_time)` entry, each authored (and committed) as that person at that time.
fn fixture_repo(merges: &[(&str, &str, i64)]) -> TempDir {
    let d = TempDir::new().unwrap();
    let p = d.path();
    git(p, &["init", "-q"], &[]);
    let base_env = |t: i64| {
        vec![
            ("GIT_AUTHOR_NAME", "base".to_string()),
            ("GIT_AUTHOR_EMAIL", "base@example.com".to_string()),
            ("GIT_COMMITTER_NAME", "base".to_string()),
            ("GIT_COMMITTER_EMAIL", "base@example.com".to_string()),
            ("GIT_AUTHOR_DATE", format!("@{t} +0000")),
            ("GIT_COMMITTER_DATE", format!("@{t} +0000")),
        ]
    };
    git(
        p,
        &["commit", "-q", "--allow-empty", "-m", "base"],
        &base_env(NOW - 400 * DAY),
    );
    for (i, (name, email, t)) in merges.iter().enumerate() {
        let env = vec![
            ("GIT_AUTHOR_NAME", (*name).to_string()),
            ("GIT_AUTHOR_EMAIL", (*email).to_string()),
            ("GIT_COMMITTER_NAME", (*name).to_string()),
            ("GIT_COMMITTER_EMAIL", (*email).to_string()),
            ("GIT_AUTHOR_DATE", format!("@{t} +0000")),
            ("GIT_COMMITTER_DATE", format!("@{t} +0000")),
        ];
        let branch = format!("feature-{i}");
        git(p, &["checkout", "-q", "-b", &branch, "main"], &env);
        git(
            p,
            &["commit", "-q", "--allow-empty", "-m", &format!("work {i}")],
            &env,
        );
        git(p, &["checkout", "-q", "main"], &env);
        git(
            p,
            &[
                "merge",
                "-q",
                "--no-ff",
                "-m",
                &format!("merge {i}"),
                &branch,
            ],
            &env,
        );
    }
    d
}

fn roles_file(dir: &Path, body: &str) -> PathBuf {
    let p = dir.join("roles.toml");
    std::fs::write(&p, body).unwrap();
    p
}

/// Every required role held by exactly alice and bob.
const TWO_HOLDERS: &str = r#"
[role.core-runtime-lead]
holders = ["alice", "bob"]
[role.mesh-lead]
holders = ["alice", "bob"]
[role.agent-lead]
holders = ["alice", "bob"]
[role.security-lead]
holders = ["alice", "bob"]
[role.release-lead]
holders = ["alice", "bob"]
"#;

fn bus_factor(repo: &Path, roles: &Path, report: Option<&Path>) -> Output {
    let mut c = xtask();
    c.arg("bus-factor")
        .arg("--repo")
        .arg(repo)
        .arg("--roles")
        .arg(roles)
        .arg("--now")
        .arg(NOW.to_string());
    if let Some(r) = report {
        c.arg("--report").arg(r);
    }
    c.output().unwrap()
}

#[test]
fn atc_bus_1_passes_when_every_role_has_two_active_holders() {
    let repo = fixture_repo(&[
        ("alice", "alice@example.com", NOW - 5 * DAY),
        ("bob", "bob@example.com", NOW - 59 * DAY),
    ]);
    let roles = roles_file(repo.path(), TWO_HOLDERS);
    let out = bus_factor(repo.path(), &roles, None);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("bus factor OK"));
}

#[test]
fn atc_bus_1_fails_when_a_holder_has_no_merge_in_sixty_days() {
    // bob's only merge is 61 days old: he is a declared but inactive holder.
    let repo = fixture_repo(&[
        ("alice", "alice@example.com", NOW - 5 * DAY),
        ("bob", "bob@example.com", NOW - 61 * DAY),
    ]);
    let roles = roles_file(repo.path(), TWO_HOLDERS);
    let report = repo.path().join("report.md");
    let out = bus_factor(repo.path(), &roles, Some(&report));
    assert!(!out.status.success(), "must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    for role in [
        "core-runtime-lead",
        "mesh-lead",
        "agent-lead",
        "security-lead",
        "release-lead",
    ] {
        assert!(stderr.contains(&format!("VIOLATION {role}")), "{stderr}");
    }
    let body = std::fs::read_to_string(&report).unwrap();
    assert!(body.contains("P0: Bus Factor Violation"), "{body}");
    assert!(body.contains("1 active holder(s) of 2 declared"), "{body}");
}

#[test]
fn atc_bus_1_fails_for_a_missing_required_role_and_for_a_single_declared_holder() {
    let repo = fixture_repo(&[
        ("alice", "alice@example.com", NOW - DAY),
        ("bob", "bob@example.com", NOW - DAY),
    ]);
    // release-lead is absent; mesh-lead has a single declared holder.
    let roles = roles_file(
        repo.path(),
        r#"
[role.core-runtime-lead]
holders = ["alice", "bob"]
[role.mesh-lead]
holders = ["alice"]
[role.agent-lead]
holders = ["alice", "bob"]
[role.security-lead]
holders = ["alice", "bob"]
"#,
    );
    let out = bus_factor(repo.path(), &roles, None);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("VIOLATION release-lead: 0 active"),
        "{stderr}"
    );
    assert!(stderr.contains("VIOLATION mesh-lead: 1 active"), "{stderr}");
    assert!(!stderr.contains("VIOLATION agent-lead"), "{stderr}");
}

#[test]
fn atc_bus_1_maps_authors_by_noreply_address_and_identity_table() {
    let repo = fixture_repo(&[
        (
            "Alice Example",
            "12345+alice@users.noreply.github.com",
            NOW - DAY,
        ),
        ("Robert B.", "rb@corp.example", NOW - 2 * DAY),
        // Not a holder: must not count for anyone.
        ("mallory", "mallory@example.com", NOW - DAY),
    ]);
    let roles = roles_file(
        repo.path(),
        &format!("{TWO_HOLDERS}\n[identity.bob]\nemails = [\"rb@corp.example\"]\n"),
    );
    let out = bus_factor(repo.path(), &roles, None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Non-holders never count, however active: a role with one declared holder
/// stays in violation although another author merges every day.
#[test]
fn atc_bus_1_non_holders_do_not_count_toward_a_role() {
    let repo = fixture_repo(&[
        ("alice", "alice@example.com", NOW - DAY),
        ("mallory", "mallory@example.com", NOW - DAY),
        ("mallory", "mallory@example.com", NOW - 2 * DAY),
    ]);
    let roles = roles_file(
        repo.path(),
        &TWO_HOLDERS.replace(
            "[role.mesh-lead]\nholders = [\"alice\", \"bob\"]",
            "[role.mesh-lead]\nholders = [\"alice\"]",
        ),
    );
    let out = bus_factor(repo.path(), &roles, None);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("VIOLATION mesh-lead: 1 active"), "{stderr}");
    // bob is declared but never merged: every other role sees one active
    // holder (alice) too, and mallory is not counted for any of them.
    assert!(!stderr.contains("2 active"), "{stderr}");
}

/// The window is inclusive: a merge exactly 60 days old is still active, one
/// second older is not.
#[test]
fn atc_bus_1_sixty_day_boundary_is_inclusive() {
    let at = |bob_age: i64| {
        let repo = fixture_repo(&[
            ("alice", "alice@example.com", NOW - DAY),
            ("bob", "bob@example.com", NOW - bob_age),
        ]);
        let roles = roles_file(repo.path(), TWO_HOLDERS);
        bus_factor(repo.path(), &roles, None)
    };
    let exact = at(60 * DAY);
    assert!(
        exact.status.success(),
        "{}",
        String::from_utf8_lossy(&exact.stderr)
    );
    assert!(!at(60 * DAY + 1).status.success());
}

#[test]
fn atc_bus_1_ignores_non_merge_commits() {
    // Only plain commits by alice and bob: nobody has a merge.
    let repo = fixture_repo(&[]);
    for who in ["alice", "bob"] {
        git(
            repo.path(),
            &["commit", "-q", "--allow-empty", "-m", "plain"],
            &[
                ("GIT_AUTHOR_NAME", who.to_string()),
                ("GIT_AUTHOR_EMAIL", format!("{who}@example.com")),
                ("GIT_COMMITTER_NAME", who.to_string()),
                ("GIT_COMMITTER_EMAIL", format!("{who}@example.com")),
                ("GIT_AUTHOR_DATE", format!("@{} +0000", NOW - DAY)),
                ("GIT_COMMITTER_DATE", format!("@{} +0000", NOW - DAY)),
            ],
        );
    }
    let roles = roles_file(repo.path(), TWO_HOLDERS);
    assert!(!bus_factor(repo.path(), &roles, None).status.success());
}

/// The roles of INV-BUS-1, `{core-runtime, mesh, agent, security, release}`
/// (spec §12.1 and ATC-BUS-1), as the roster names them.
const SPEC_ROLES: [&str; 5] = [
    "core-runtime-lead",
    "mesh-lead",
    "agent-lead",
    "security-lead",
    "release-lead",
];

/// `[role.<name>] holders` of a roles file.
fn declared_holders(roles_toml: &str) -> Vec<(String, Vec<String>)> {
    let doc: toml::Table = toml::from_str(roles_toml).unwrap();
    doc["role"]
        .as_table()
        .expect("[role.*] tables")
        .iter()
        .map(|(role, body)| {
            let holders = body["holders"]
                .as_array()
                .unwrap_or_else(|| panic!("{role}: holders is not a list"))
                .iter()
                .map(|h| h.as_str().unwrap().to_owned())
                .collect();
            (role.clone(), holders)
        })
        .collect()
}

/// Every spec role is required by the xtask itself, whatever the roster
/// says: a roster that omits any one of the five fails for exactly that role,
/// as a role with no holder.
#[test]
fn atc_bus_1_every_spec_role_is_required_even_when_the_roster_omits_it() {
    let repo = fixture_repo(&[
        ("alice", "alice@example.com", NOW - DAY),
        ("bob", "bob@example.com", NOW - DAY),
    ]);
    let full = roles_file(repo.path(), TWO_HOLDERS);
    let out = bus_factor(repo.path(), &full, None);
    assert!(
        out.status.success(),
        "the full roster passes: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for missing in SPEC_ROLES {
        let roster: String = SPEC_ROLES
            .iter()
            .filter(|r| **r != missing)
            .map(|r| format!("[role.{r}]\nholders = [\"alice\", \"bob\"]\n"))
            .collect();
        let roles = roles_file(repo.path(), &roster);
        let out = bus_factor(repo.path(), &roles, None);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "omitting {missing} must fail");
        assert!(
            stderr.contains(&format!(
                "VIOLATION {missing}: 0 active holder(s) of 0 declared"
            )),
            "{stderr}"
        );
        let violations = stderr
            .lines()
            .filter(|l| l.starts_with("VIOLATION "))
            .count();
        assert_eq!(violations, 1, "only {missing} is in violation: {stderr}");
    }
}

/// The shipped roster `docs/maintainers/roles.toml` declares exactly the five
/// spec roles, each with a holder, and every holder is a code owner in the
/// shipped `.github/CODEOWNERS` (the roster is CODEOWNERS-enforced, §12.1).
#[test]
fn atc_bus_1_shipped_roster_declares_exactly_the_spec_roles_held_by_code_owners() {
    let text = std::fs::read_to_string(repo_root().join("docs/maintainers/roles.toml")).unwrap();
    let roles = declared_holders(&text);
    let names: BTreeSet<&str> = roles.iter().map(|(r, _)| r.as_str()).collect();
    assert_eq!(names, BTreeSet::from(SPEC_ROLES), "roles.toml roles");

    let codeowners = std::fs::read_to_string(repo_root().join(".github/CODEOWNERS")).unwrap();
    let owners: BTreeSet<String> = codeowners
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .flat_map(|l| l.split_whitespace().skip(1))
        .take_while(|o| !o.starts_with('#'))
        .filter_map(|o| o.strip_prefix('@'))
        .map(str::to_lowercase)
        .collect();
    assert!(!owners.is_empty(), "CODEOWNERS names no owner");
    for (role, holders) in &roles {
        assert!(!holders.is_empty(), "{role} has no declared holder");
        for h in holders {
            assert!(
                owners.contains(&h.to_lowercase()),
                "{role} holder {h} is not a code owner in .github/CODEOWNERS ({owners:?})"
            );
        }
    }
}

/// GIVEN the git log and roster at HEAD: invoked as the workflow invokes it
/// (from the repository root, default `--roles` and `--repo`), the check
/// evaluates the shipped roster against this repository's history, reports
/// each spec role with its declared holder count, and fails for any role with
/// fewer than two declared holders.
#[test]
fn atc_bus_1_default_invocation_checks_the_shipped_roster_at_head() {
    let text = std::fs::read_to_string(repo_root().join("docs/maintainers/roles.toml")).unwrap();
    let roles = declared_holders(&text);
    let out = xtask()
        .current_dir(repo_root())
        .arg("bus-factor")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut short = false;
    for role in SPEC_ROLES {
        let declared = roles
            .iter()
            .find(|(r, _)| r == role)
            .map_or(0, |(_, h)| h.len());
        let line = stdout
            .lines()
            .find(|l| l.split_whitespace().next() == Some(role))
            .unwrap_or_else(|| panic!("no line for {role}:\n{stdout}\n{stderr}"));
        assert!(line.contains(&format!(" of {declared} declared")), "{line}");
        if declared < 2 {
            short = true;
            assert!(line.ends_with("(VIOLATION)"), "{line}");
            assert!(stderr.contains(&format!("VIOLATION {role}: ")), "{stderr}");
        }
    }
    if short {
        assert!(!out.status.success(), "{stdout}\n{stderr}");
    }
}

#[test]
fn atc_bus_1_workflow_runs_the_xtask_and_opens_a_p0_issue() {
    let wf = std::fs::read_to_string(repo_root().join(".github/workflows/bus-factor.yml")).unwrap();
    assert!(wf.contains("invariant_check:"), "{wf}");
    assert!(wf.contains("cargo xtask bus-factor"), "{wf}");
    assert!(wf.contains("gh issue create"), "{wf}");
    assert!(wf.contains("\"P0\""), "{wf}");
    assert!(wf.contains("schedule:"), "weekly trigger missing");
    assert!(
        !wf.contains("python3"),
        "logic must live in xtask, not inline"
    );
}

// ---------------------------------------------------------------------------
// ATC-BUS-2
// ---------------------------------------------------------------------------

fn rotation(text: &str, today: &str) -> Output {
    let d = TempDir::new().unwrap();
    let f = d.path().join("rotations.md");
    std::fs::write(&f, text).unwrap();
    xtask()
        .arg("rotation-note-check")
        .arg("--file")
        .arg(&f)
        .arg("--today")
        .arg(today)
        .output()
        .unwrap()
}

const NOTES: &str = "# Rotations\n\n## 2026-05-01 - older\n\nx\n\n## 2026-06-01 - newest\n\ny\n";

#[test]
fn atc_bus_2_fresh_note_passes_at_the_boundary() {
    // 2026-06-01 + 35 days = 2026-07-06.
    let out = rotation(NOTES, "2026-07-06");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("35 day(s) old"));
}

#[test]
fn atc_bus_2_stale_note_fails_one_day_past_the_limit() {
    let out = rotation(NOTES, "2026-07-07");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("2026-06-01") && err.contains("36 days old"),
        "{err}"
    );
}

#[test]
fn atc_bus_2_uses_the_newest_note_wherever_it_sits() {
    let out = rotation(
        "## 2026-06-01 - newest, listed first\n\n## 2026-01-01 - old\n",
        "2026-06-20",
    );
    assert!(out.status.success());
}

#[test]
fn atc_bus_2_rejects_missing_notes_and_future_dates() {
    assert!(!rotation("# Rotations\n\nno notes\n", "2026-06-20")
        .status
        .success());
    assert!(!rotation("## not-a-date heading\n", "2026-06-20")
        .status
        .success());
    let future = rotation("## 2026-09-01 - from the future\n", "2026-06-20");
    assert!(!future.status.success());
    assert!(String::from_utf8_lossy(&future.stderr).contains("in the future"));
}

/// The check counts days in UTC, but a maintainer east of UTC dates a note
/// with their local date, which can be one day ahead of UTC (up to UTC+14).
/// That must not block a release; two days ahead is still rejected.
#[test]
fn atc_bus_2_accepts_a_note_dated_one_day_ahead_of_utc() {
    let out = rotation("## 2026-06-21 - written in UTC+9\n", "2026-06-20");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = rotation("## 2026-06-22 - two days ahead\n", "2026-06-20");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("in the future"));
}

#[test]
fn atc_bus_2_missing_file_fails() {
    let out = xtask()
        .args(["rotation-note-check", "--file", "/definitely/not/here.md"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn atc_bus_2_release_workflow_gates_on_the_check_and_the_real_file_parses() {
    let wf = std::fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    assert!(wf.contains("rotation_note_fresh:"), "{wf}");
    assert!(wf.contains("cargo xtask rotation-note-check"), "{wf}");
    assert!(
        wf.contains("needs: rotation_note_fresh"),
        "the build must depend on the gate"
    );
    // The committed file has at least one parseable, non-future note.
    let real = std::fs::read_to_string(repo_root().join("docs/governance/rotations.md")).unwrap();
    let out = rotation(&real, "2026-11-04");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Workflow hygiene
// ---------------------------------------------------------------------------

/// `tools/xtask` is a member of the root workspace, so its build output is in
/// the root `target/`; pointing rust-cache at `tools/xtask` caches nothing.
#[test]
fn workflows_cache_the_root_workspace_for_xtask() {
    for f in ["bus-factor.yml", "release.yml"] {
        let wf = std::fs::read_to_string(repo_root().join(".github/workflows").join(f)).unwrap();
        assert!(
            !wf.contains("workspaces: tools/xtask"),
            "{f}: rust-cache must use the root workspace"
        );
    }
}

#[test]
fn release_rotation_gate_job_is_read_only() {
    let wf = std::fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    let start = wf.find("  rotation_note_fresh:").unwrap();
    let rest = &wf[start..];
    let end = rest.find("\n  build:").unwrap();
    let job = &rest[..end];
    assert!(
        job.contains("permissions:\n      contents: read"),
        "rotation_note_fresh needs an explicit read-only token:\n{job}"
    );
}

/// The P0 issue must not be silently skipped: the label is ensured, a body is
/// written when the report is absent (tooling error), and only a genuine
/// duplicate is tolerated, not every `gh` failure.
#[test]
fn atc_bus_1_workflow_cannot_silently_skip_the_p0_issue() {
    let wf = std::fs::read_to_string(repo_root().join(".github/workflows/bus-factor.yml")).unwrap();
    assert!(wf.contains("gh label create P0"), "{wf}");
    assert!(
        !wf.contains("|| echo"),
        "gh failures must not be swallowed:\n{wf}"
    );
    assert!(wf.contains("gh issue list"), "duplicate detection missing");
    assert!(
        wf.contains("! -s \"${RUNNER_TEMP}/bus-factor-body.md\""),
        "a fallback body is needed when the report was not written"
    );
}
