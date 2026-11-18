//! The OS sandbox of the agent subprocess (spec §8.2, §8.5): turns the
//! session's facts — project directory, session directory, the adapter's own
//! state paths, the user's `--sandbox-read` / `--sandbox-write` — into an
//! [`AgentProfile`] and engages it on the command `entangle agent run` is
//! about to spawn.
//!
//! Network egress is not restricted; see `docs/agents.md`.

use anyhow::{bail, Result};
use entangle_agent_host::SandboxPaths;
use entangle_sandbox::{
    agent::install_roots, agent_plan, confine_agent_command, AgentPlan, AgentProfile, HostSupport,
};
use std::path::{Path, PathBuf};

/// Diagnostic override: `no-landlock` makes this process plan as if the
/// kernel had no Landlock, so the degraded path can be exercised (and
/// tested) on a kernel that has it. It can only remove a layer, and the
/// degraded warning is printed as on a real such host.
pub(crate) const PROBE_ENV: &str = "ENTANGLE_AGENT_SANDBOX_PROBE";

/// The user's sandbox choices for one session.
#[derive(Clone, Debug, Default)]
pub(crate) struct SandboxOptions {
    /// `--no-sandbox`.
    pub disabled: bool,
    /// `--require-sandbox`.
    pub required: bool,
    /// `--sandbox-read`.
    pub read: Vec<PathBuf>,
    /// `--sandbox-write`.
    pub write: Vec<PathBuf>,
    /// `--sandbox-max-memory-mb`.
    pub max_memory_mb: Option<u64>,
    /// `--sandbox-max-open-files`.
    pub max_open_files: Option<u64>,
}

/// What this host offers an agent session, with [`PROBE_ENV`] applied.
pub(crate) fn host_support() -> HostSupport {
    let mut host = entangle_sandbox::probe().clone();
    if std::env::var(PROBE_ENV).is_ok_and(|v| v == "no-landlock") {
        host.landlock_abi = None;
    }
    host
}

/// The plan an agent session would get on this host.
pub(crate) fn host_plan() -> AgentPlan {
    agent_plan(&host_support())
}

/// Resolve the agent executable to an absolute path the way a spawn would:
/// a name without a slash is looked up on `PATH`, anything else is taken
/// relative to the current directory. `None` when there is no such
/// executable.
pub(crate) fn resolve_program(bin: &Path) -> Option<PathBuf> {
    if bin.components().count() == 1 && !bin.is_absolute() {
        return entangle_sandbox::probe::find_in_path(&bin.to_string_lossy());
    }
    let abs = if bin.is_absolute() {
        bin.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(bin)
    };
    abs.is_file().then_some(abs)
}

/// The project directory of a session started in `cwd`: the enclosing git
/// work tree when there is one (an agent started in a subdirectory still
/// needs the repository), else `cwd` itself. Never widened to the home
/// directory or the filesystem root — a `.git` there (a dotfiles
/// repository) does not make everything the project.
pub(crate) fn project_dir(cwd: &Path, home: Option<&Path>) -> PathBuf {
    for dir in cwd.ancestors() {
        if dir.parent().is_none() || home.is_some_and(|h| h == dir) {
            break;
        }
        if dir.join(".git").exists() {
            return dir.to_path_buf();
        }
    }
    cwd.to_path_buf()
}

/// For a linked git work tree (`.git` is a file naming a directory under
/// the main repository's `.git/worktrees/`), the main repository's git
/// directory: `git` in the work tree reads and writes objects and refs
/// there. `None` for an ordinary repository or no repository.
pub(crate) fn linked_worktree_git_dir(project: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(project.join(".git")).ok()?;
    let gitdir = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let gitdir = if Path::new(gitdir).is_absolute() {
        PathBuf::from(gitdir)
    } else {
        project.join(gitdir)
    };
    // `<gitdir>/commondir` holds the path of the shared git directory,
    // usually `../..`.
    let common = std::fs::read_to_string(gitdir.join("commondir")).ok()?;
    let common = common.trim();
    let common = if Path::new(common).is_absolute() {
        PathBuf::from(common)
    } else {
        gitdir.join(common)
    };
    std::fs::canonicalize(common).ok()
}

/// The sandbox profile of one session.
pub(crate) fn build_profile(
    program: &Path,
    cwd: &Path,
    session_dir: &Path,
    adapter: &SandboxPaths,
    opts: &SandboxOptions,
) -> Result<AgentProfile> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute());
    let project = project_dir(cwd, home.as_deref());
    let mut p = AgentProfile::new(program, &project);

    // Tools: every directory on PATH, and the trees the agent itself is
    // installed in.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path).filter(|d| d.is_absolute()) {
            p.read_only.push(dir);
        }
    }
    p.read_only.extend(install_roots(program));
    // git reads the user's identity and settings; it never needs to write them.
    if let Some(home) = &home {
        p.read_only.push(home.join(".gitconfig"));
        p.read_only.push(home.join(".config/git"));
    }
    if let Some(git_dir) = linked_worktree_git_dir(&project) {
        p.read_write.push(git_dir);
    }

    // The session directory holds the gateway-routed MCP config.
    if adapter.session_dir_writable {
        p.read_write.push(session_dir.to_path_buf());
    } else {
        p.read_only.push(session_dir.to_path_buf());
    }
    p.read_only.extend(
        adapter
            .read_only
            .iter()
            .map(|x| x.clone().into_std_path_buf()),
    );
    p.read_write.extend(
        adapter
            .read_write
            .iter()
            .map(|x| x.clone().into_std_path_buf()),
    );

    for (list, flag, given) in [
        (&mut p.read_only, "--sandbox-read", &opts.read),
        (&mut p.read_write, "--sandbox-write", &opts.write),
    ] {
        for path in given {
            // A path the user names must exist: a typo would otherwise
            // surface as an unexplained denial inside the agent.
            let abs = std::fs::canonicalize(path).map_err(|e| {
                anyhow::anyhow!(
                    "ENTANGLE-E0682: agent sandbox path {}: {flag} needs an existing path: {e}",
                    path.display()
                )
            })?;
            list.push(abs);
        }
    }

    if let Some(mb) = opts.max_memory_mb {
        p.limits.address_space_bytes = Some(mb.saturating_mul(1024 * 1024));
    }
    if let Some(n) = opts.max_open_files {
        p.limits.open_files = Some(n);
    }
    Ok(p)
}

/// The outcome of [`engage`], for the session-start report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Engaged {
    /// `--no-sandbox`.
    Disabled,
    /// The plan that was applied (possibly degraded).
    Plan {
        /// What the host offered.
        plan: AgentPlan,
        /// The writable roots, for display.
        writable: Vec<PathBuf>,
    },
}

/// Engage the sandbox on `cmd` according to `opts`, or refuse.
///
/// - `--no-sandbox`: nothing is engaged.
/// - `--require-sandbox` on a host that cannot enforce the filesystem
///   allowlist: `ENTANGLE-E0680`, the agent is not started.
/// - Otherwise whatever the host offers is engaged; the caller prints the
///   report, which names every missing layer.
pub(crate) fn engage(
    cmd: &mut std::process::Command,
    profile: &AgentProfile,
    opts: &SandboxOptions,
) -> Result<Engaged> {
    if opts.disabled {
        return Ok(Engaged::Disabled);
    }
    let plan = host_plan();
    if opts.required && !plan.filesystem_confined() {
        bail!(
            "ENTANGLE-E0680: --require-sandbox: this host cannot confine the agent's filesystem \
             access ({}); the agent was not started. See `entangle doctor`",
            plan.describe()
        );
    }
    confine_agent_command(cmd, profile, &plan)?;
    Ok(Engaged::Plan {
        writable: if plan.filesystem_confined() {
            profile.writable_roots()
        } else {
            Vec::new()
        },
        plan,
    })
}

/// Print the sandbox status of a starting session on stderr.
pub(crate) fn report(engaged: &Engaged) {
    match engaged {
        Engaged::Disabled => {
            eprintln!(
                "warning: --no-sandbox: the agent runs WITHOUT the OS sandbox. It can read and \
                 write every file you can (keys and tokens in your home directory included), \
                 not only this project. Tool calls are still routed through the gateway."
            );
        }
        Engaged::Plan { plan, writable } => {
            if !plan.filesystem_confined() {
                eprintln!(
                    "warning: the agent's filesystem access is NOT confined on this host: it can \
                     read and write every file you can. Sandbox: {}. Use --require-sandbox to \
                     refuse to start in this state; see `entangle doctor`.",
                    plan.describe()
                );
                return;
            }
            let shown: Vec<String> = writable.iter().map(|p| p.display().to_string()).collect();
            eprintln!(
                "sandbox: {}; writable: {}",
                plan.describe(),
                shown.join(", ")
            );
            if plan.is_degraded() {
                eprintln!(
                    "warning: the agent sandbox is engaged with reduced isolation on this host \
                     (see the line above and `entangle doctor`)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_dir_is_the_git_work_tree_but_never_home_or_root() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let repo = home.join("work/repo");
        let sub = repo.join("crates/x");
        std::fs::create_dir_all(&sub).unwrap();
        // No repository: the directory itself.
        assert_eq!(project_dir(&sub, Some(&home)), sub);
        std::fs::create_dir(repo.join(".git")).unwrap();
        assert_eq!(project_dir(&sub, Some(&home)), repo);
        assert_eq!(project_dir(&repo, Some(&home)), repo);
        // A dotfiles repository in the home directory does not widen it.
        std::fs::create_dir(home.join(".git")).unwrap();
        let other = home.join("notes");
        std::fs::create_dir(&other).unwrap();
        assert_eq!(project_dir(&other, Some(&home)), other);
        assert_eq!(project_dir(&home, Some(&home)), home);
    }

    #[test]
    fn linked_worktree_finds_the_main_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let main_git = root.join("main/.git");
        let wt_meta = main_git.join("worktrees/wt");
        std::fs::create_dir_all(&wt_meta).unwrap();
        std::fs::write(wt_meta.join("commondir"), "../..\n").unwrap();
        let wt = root.join("wt");
        std::fs::create_dir(&wt).unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", wt_meta.display())).unwrap();
        assert_eq!(linked_worktree_git_dir(&wt), Some(main_git));
        // An ordinary repository (a `.git` directory) and no repository.
        assert_eq!(linked_worktree_git_dir(&root.join("main")), None);
        assert_eq!(linked_worktree_git_dir(&root), None);
    }

    #[test]
    fn profile_carries_session_adapter_and_user_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let (cwd, session, state, extra) = (
            root.join("proj"),
            root.join("sess"),
            root.join("state"),
            root.join("extra"),
        );
        for d in [&cwd, &session, &state, &extra] {
            std::fs::create_dir(d).unwrap();
        }
        let adapter = SandboxPaths {
            read_write: vec![camino::Utf8PathBuf::from_path_buf(state.clone()).unwrap()],
            ..SandboxPaths::default()
        };
        let opts = SandboxOptions {
            write: vec![extra.clone()],
            max_memory_mb: Some(8),
            ..SandboxOptions::default()
        };
        let p = build_profile(Path::new("/bin/sh"), &cwd, &session, &adapter, &opts).unwrap();
        assert_eq!(p.project_dir, cwd);
        assert!(p.read_write.contains(&state) && p.read_write.contains(&extra));
        // The session config is read-only unless the adapter writes there.
        assert!(p.read_only.contains(&session) && !p.read_write.contains(&session));
        assert_eq!(p.limits.address_space_bytes, Some(8 * 1024 * 1024));

        let codex = SandboxPaths {
            session_dir_writable: true,
            ..SandboxPaths::default()
        };
        let p = build_profile(
            Path::new("/bin/sh"),
            &cwd,
            &session,
            &codex,
            &Default::default(),
        )
        .unwrap();
        assert!(p.read_write.contains(&session));

        let bad = SandboxOptions {
            read: vec![root.join("missing")],
            ..SandboxOptions::default()
        };
        let err = build_profile(Path::new("/bin/sh"), &cwd, &session, &adapter, &bad).unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0682"), "{err}");
        assert!(err.to_string().contains("--sandbox-read"), "{err}");
    }

    #[test]
    fn resolve_program_matches_spawn_lookup() {
        assert!(resolve_program(Path::new("sh")).is_some_and(|p| p.is_absolute()));
        assert!(resolve_program(Path::new("/bin/sh")).is_some());
        assert!(resolve_program(Path::new("entangle-no-such-agent-binary")).is_none());
        assert!(resolve_program(Path::new("./no/such/file")).is_none());
    }
}
