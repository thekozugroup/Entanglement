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

/// `.github/workflows/bus-factor.yml`, parsed.
fn bus_factor_workflow() -> serde_yaml::Value {
    let text =
        std::fs::read_to_string(repo_root().join(".github/workflows/bus-factor.yml")).unwrap();
    serde_yaml::from_str(&text).unwrap()
}

/// What happened in one simulated run of the `invariant_check` job.
#[derive(Debug)]
struct JobRun {
    /// `(step name or id, ran, exit code)` per `run:` step, in order.
    steps: Vec<(String, bool, Option<i32>)>,
    /// The job's final conclusion.
    failed: bool,
    /// Every `gh` invocation, one line of arguments each.
    gh_calls: Vec<String>,
    /// The `--body-file` contents of `gh issue create`, if it was called.
    issue_body: Option<String>,
}

impl JobRun {
    fn ran(&self, needle: &str) -> bool {
        self.steps
            .iter()
            .any(|(n, ran, _)| *ran && n.contains(needle))
    }
}

/// Run the `invariant_check` job's `run:` steps in `ws` the way GitHub
/// Actions does: `uses:` steps are skipped (checkout, toolchain, cache), a
/// step without `if:` runs while the job has not failed, the only other
/// condition understood is `steps.<id>.outcome == 'failure'` (with the
/// implicit `success() &&`), and `continue-on-error` turns a failed outcome
/// into a successful conclusion. `cargo` and `gh` are stubs on `PATH`: `cargo
/// xtask ...` runs the real xtask binary, `gh` records its arguments, reports
/// `open_issues` open P0 issues, and fails `issue create` when `gh_fails`.
fn simulate_invariant_check(ws: &Path, open_issues: u32, gh_fails: bool) -> JobRun {
    let wf = bus_factor_workflow();
    let steps = wf["jobs"]["invariant_check"]["steps"]
        .as_sequence()
        .expect("invariant_check has steps")
        .clone();
    let sim = TempDir::new().unwrap();
    let bin = sim.path().join("bin");
    let runner_temp = sim.path().join("runner-temp");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&runner_temp).unwrap();
    let stub = |name: &str, body: &str| {
        use std::os::unix::fs::PermissionsExt as _;
        let p = bin.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    stub(
        "cargo",
        "[ \"$1\" = xtask ] || { echo \"unexpected: cargo $*\" >&2; exit 97; }\n\
         shift\nexec \"$XTASK_BIN\" \"$@\"\n",
    );
    stub(
        "gh",
        "printf '%s\\n' \"$*\" >> \"$GH_LOG\"\n\
         [ -n \"$GH_TOKEN\" ] || { echo 'no GH_TOKEN' >&2; exit 4; }\n\
         case \"$1 $2\" in\n\
         'label create') exit 0 ;;\n\
         'issue list') echo \"$GH_OPEN_ISSUES\"; exit 0 ;;\n\
         'issue create')\n\
           [ -z \"$GH_FAIL\" ] || exit 1\n\
           while [ $# -gt 0 ]; do\n\
             [ \"$1\" = --body-file ] && cp \"$2\" \"$GH_BODY\"\n\
             shift\n\
           done\n\
           exit 0 ;;\n\
         esac\n\
         echo \"unexpected: gh $*\" >&2\nexit 98\n",
    );
    let gh_log = sim.path().join("gh.log");
    let gh_body = sim.path().join("issue-body.md");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut outcomes = std::collections::BTreeMap::new();
    let mut failed = false;
    let mut log = Vec::new();
    for step in &steps {
        let Some(script) = step["run"].as_str() else {
            continue;
        };
        let label = step["id"]
            .as_str()
            .or(step["name"].as_str())
            .unwrap_or(script)
            .to_owned();
        let wanted = match step["if"].as_str() {
            None => !failed,
            Some(cond) => {
                let id = cond
                    .strip_prefix("steps.")
                    .and_then(|c| c.strip_suffix(".outcome == 'failure'"))
                    .unwrap_or_else(|| panic!("unsupported condition `{cond}` on {label}"));
                !failed && outcomes.get(id) == Some(&false)
            }
        };
        if !wanted {
            log.push((label, false, None));
            continue;
        }
        let file = sim.path().join("step.sh");
        std::fs::write(&file, script).unwrap();
        let mut cmd = Command::new("bash");
        match step["shell"].as_str() {
            // GitHub's default on Linux runners, and its explicit `bash`.
            None => cmd.arg("-e"),
            Some("bash") => cmd.args(["--noprofile", "--norc", "-eo", "pipefail"]),
            Some(other) => panic!("unsupported shell {other}"),
        };
        isolate_git(&mut cmd);
        if let Some(env) = step["env"].as_mapping() {
            for (k, v) in env {
                let (k, v) = (k.as_str().unwrap(), v.as_str().unwrap());
                // `${{ github.token }}` is a secret the runner substitutes.
                let v = if v.contains("${{") { "stub-token" } else { v };
                cmd.env(k, v);
            }
        }
        let out = cmd
            .arg(&file)
            .current_dir(ws)
            .env("PATH", &path)
            .env("XTASK_BIN", env!("CARGO_BIN_EXE_xtask"))
            .env("RUNNER_TEMP", &runner_temp)
            .env("GITHUB_SERVER_URL", "https://github.example")
            .env("GITHUB_REPOSITORY", "owner/repo")
            .env("GITHUB_RUN_ID", "42")
            .env("GH_LOG", &gh_log)
            .env("GH_BODY", &gh_body)
            .env("GH_OPEN_ISSUES", open_issues.to_string())
            .env("GH_FAIL", if gh_fails { "1" } else { "" })
            .output()
            .unwrap();
        let ok = out.status.success();
        if let Some(id) = step["id"].as_str() {
            outcomes.insert(id.to_owned(), ok);
        }
        if !ok && step["continue-on-error"].as_bool() != Some(true) {
            failed = true;
        }
        log.push((label, true, out.status.code()));
    }
    JobRun {
        steps: log,
        failed,
        gh_calls: std::fs::read_to_string(&gh_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect(),
        issue_body: std::fs::read_to_string(&gh_body).ok(),
    }
}

/// A checkout for the simulated job: a git repository whose merges are the
/// given `(author, days ago)` (relative to the real clock, which the workflow
/// does not override) and whose `docs/maintainers/roles.toml` is `roster`
/// (none when `None`).
fn workflow_checkout(merges: &[(&str, i64)], roster: Option<&str>) -> TempDir {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let emails: Vec<String> = merges
        .iter()
        .map(|(n, _)| format!("{n}@example.com"))
        .collect();
    let entries: Vec<(&str, &str, i64)> = merges
        .iter()
        .zip(&emails)
        .map(|((n, ago), e)| (*n, e.as_str(), now - ago * DAY))
        .collect();
    let repo = fixture_repo(&entries);
    if let Some(r) = roster {
        let dir = repo.path().join("docs/maintainers");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("roles.toml"), r).unwrap();
    }
    repo
}

/// The workflow's shape: weekly schedule, issue permission, and a check step
/// whose failure is recorded (`continue-on-error`, an `id`) rather than
/// stopping the job before the P0 issue step, which is gated on that
/// failure and followed by a step that fails the job.
#[test]
fn atc_bus_1_workflow_is_weekly_and_gates_the_p0_issue_on_the_check() {
    let wf = bus_factor_workflow();
    let crons: Vec<&str> = wf["on"]["schedule"]
        .as_sequence()
        .expect("on.schedule")
        .iter()
        .map(|s| s["cron"].as_str().unwrap())
        .collect();
    assert_eq!(crons.len(), 1, "{crons:?}");
    let f: Vec<&str> = crons[0].split_whitespace().collect();
    assert_eq!(f.len(), 5, "{crons:?}");
    assert!(
        f[0].parse::<u8>().is_ok_and(|m| m < 60),
        "fixed minute: {crons:?}"
    );
    assert!(
        f[1].parse::<u8>().is_ok_and(|h| h < 24),
        "fixed hour: {crons:?}"
    );
    assert_eq!((f[2], f[3]), ("*", "*"), "every week: {crons:?}");
    assert!(
        f[4].parse::<u8>().is_ok_and(|d| d <= 7),
        "exactly one weekday: {crons:?}"
    );
    assert_eq!(wf["permissions"]["issues"].as_str(), Some("write"));

    let job = &wf["jobs"]["invariant_check"];
    for key in ["if", "continue-on-error"] {
        assert!(job.get(key).is_none(), "invariant_check has `{key}`");
    }
    let steps = job["steps"].as_sequence().unwrap();
    let pos = |needle: &str| {
        steps
            .iter()
            .position(|s| s["run"].as_str().is_some_and(|r| r.contains(needle)))
            .unwrap_or_else(|| panic!("no step runs `{needle}`"))
    };
    let (check, issue) = (pos("cargo xtask bus-factor"), pos("gh issue create"));
    let id = steps[check]["id"]
        .as_str()
        .expect("the check step has an id");
    assert_eq!(steps[check]["continue-on-error"].as_bool(), Some(true));
    assert!(steps[check].get("if").is_none());
    assert!(
        steps[check]["run"]
            .as_str()
            .unwrap()
            .contains("--report \"${RUNNER_TEMP}/bus-factor-body.md\""),
        "the check writes the issue body"
    );
    let gate = format!("steps.{id}.outcome == 'failure'");
    assert!(issue > check);
    assert_eq!(steps[issue]["if"].as_str(), Some(gate.as_str()));
    assert!(steps[issue].get("continue-on-error").is_none());
    let fail = steps
        .iter()
        .skip(issue + 1)
        .position(|s| {
            s["if"].as_str() == Some(gate.as_str())
                && s["run"].as_str().is_some_and(|r| r.contains("exit 1"))
        })
        .expect("a step after the issue fails the job on violation");
    assert!(steps[issue + 1 + fail].get("continue-on-error").is_none());
}

/// AND if any role drops below 2, a P0 GitHub issue is opened: the job's own
/// steps, run against a checkout whose roster has one holder per role, open
/// exactly one P0 issue whose body is the xtask's report, and the job fails.
#[test]
fn atc_bus_1_workflow_opens_a_p0_issue_when_a_role_drops_below_two() {
    let single = SPEC_ROLES
        .iter()
        .map(|r| format!("[role.{r}]\nholders = [\"alice\"]\n"))
        .collect::<String>();
    let ws = workflow_checkout(&[("alice", 1)], Some(&single));
    let run = simulate_invariant_check(ws.path(), 0, false);
    assert!(run.ran("check"), "{run:?}");
    assert!(run.ran("Open P0 issue"), "{run:?}");
    assert!(run.failed, "the job must fail on a violation: {run:?}");
    let creates: Vec<_> = run
        .gh_calls
        .iter()
        .filter(|c| c.starts_with("issue create"))
        .collect();
    assert_eq!(creates.len(), 1, "{run:?}");
    assert!(creates[0].contains("--label P0"), "{run:?}");
    assert!(
        creates[0].contains("--title P0: Bus Factor Violation"),
        "{run:?}"
    );
    let body = run.issue_body.as_deref().expect("issue body");
    assert!(
        body.contains("P0: Bus Factor Violation (INV-BUS-1)"),
        "{body}"
    );
    for role in SPEC_ROLES {
        assert!(
            body.contains(&format!("- {role}: 1 active holder(s) of 1 declared")),
            "{body}"
        );
    }

    // An open P0 bus-factor issue already exists: no duplicate, still failed.
    let again = simulate_invariant_check(ws.path(), 1, false);
    assert!(again.ran("Open P0 issue"), "{again:?}");
    assert!(
        !again.gh_calls.iter().any(|c| c.starts_with("issue create")),
        "{again:?}"
    );
    assert!(again.failed, "{again:?}");

    // gh failing to open the issue is not swallowed.
    let broken = simulate_invariant_check(ws.path(), 0, true);
    assert!(
        broken
            .steps
            .iter()
            .any(|(n, ran, code)| *ran && n.contains("Open P0 issue") && *code != Some(0)),
        "{broken:?}"
    );
    assert!(broken.failed, "{broken:?}");
}

/// A tooling error (here: no roster) also opens the P0 issue, with a fallback
/// body; a healthy roster opens nothing and the job passes.
#[test]
fn atc_bus_1_workflow_opens_an_issue_on_tooling_errors_and_none_when_healthy() {
    let broken = workflow_checkout(&[("alice", 1)], None);
    let run = simulate_invariant_check(broken.path(), 0, false);
    assert!(run.failed, "{run:?}");
    let body = run.issue_body.as_deref().expect("issue body");
    assert!(body.contains("failed without producing a report"), "{body}");
    assert!(
        body.contains("https://github.example/owner/repo/actions/runs/42"),
        "{body}"
    );

    let healthy = workflow_checkout(&[("alice", 1), ("bob", 2)], Some(TWO_HOLDERS));
    let run = simulate_invariant_check(healthy.path(), 0, false);
    assert!(!run.failed, "{run:?}");
    assert!(run.ran("check"), "{run:?}");
    assert!(!run.ran("Open P0 issue"), "{run:?}");
    assert!(run.gh_calls.is_empty(), "{run:?}");
    assert!(run.issue_body.is_none(), "{run:?}");
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
