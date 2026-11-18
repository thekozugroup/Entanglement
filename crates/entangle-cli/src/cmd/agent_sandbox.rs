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
/// degraded warning is printed as on a real such host. Honoured in debug
/// builds only: in a release build a project's `.envrc` could otherwise
/// switch the filesystem allowlist off.
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
    #[allow(unused_mut)] // mutated in debug builds only
    let mut host = entangle_sandbox::probe().clone();
    #[cfg(debug_assertions)]
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
///
/// The `.git` file and `commondir` are project files the agent of an earlier
/// session could have written, so the answer is trusted only when the
/// layout is the one `git worktree add` creates: `<gitdir>/gitdir` points
/// back to `<project>/.git`, `<gitdir>` lies directly under
/// `<common>/worktrees/`, and `<common>` holds `HEAD`, `objects/` and
/// `refs/`. A directory that equals or contains a [`sensitive_roots`] entry
/// is never returned.
pub(crate) fn linked_worktree_git_dir(project: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let text = std::fs::read_to_string(project.join(".git")).ok()?;
    let gitdir = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let gitdir = if Path::new(gitdir).is_absolute() {
        PathBuf::from(gitdir)
    } else {
        project.join(gitdir)
    };
    let gitdir = std::fs::canonicalize(gitdir).ok()?;
    // `<gitdir>/gitdir` names the work tree's `.git` file.
    let back = std::fs::read_to_string(gitdir.join("gitdir")).ok()?;
    let back = std::fs::canonicalize(back.trim()).ok()?;
    if back != std::fs::canonicalize(project.join(".git")).ok()? {
        return None;
    }
    // `<gitdir>/commondir` holds the path of the shared git directory,
    // usually `../..`.
    let common = std::fs::read_to_string(gitdir.join("commondir")).ok()?;
    let common = common.trim();
    let common = if Path::new(common).is_absolute() {
        PathBuf::from(common)
    } else {
        gitdir.join(common)
    };
    let common = std::fs::canonicalize(common).ok()?;
    if gitdir.parent() != Some(common.join("worktrees").as_path()) {
        return None;
    }
    let looks_like_git = common.join("HEAD").is_file()
        && common.join("objects").is_dir()
        && common.join("refs").is_dir();
    if !looks_like_git || is_sensitive(&common, home) {
        return None;
    }
    Some(common)
}

/// The canonical home directory (`$HOME`, symbolic links resolved), or
/// `None` when it is unset, relative or does not exist.
pub(crate) fn canonical_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .and_then(|h| std::fs::canonicalize(h).ok())
}

/// Locations an implicit grant must never equal or contain: the filesystem
/// root, the home directory, and the directories in it that hold keys,
/// tokens and Entanglement's own state.
pub(crate) fn sensitive_roots(home: Option<&Path>) -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("/")];
    if let Some(h) = home {
        out.push(h.to_path_buf());
        for d in [".entangle", ".ssh", ".aws", ".gnupg"] {
            out.push(h.join(d));
        }
    }
    out
}

/// Whether granting `path` would grant a [`sensitive_roots`] entry (the
/// path equals or contains one). Compared after canonicalisation when the
/// path exists.
pub(crate) fn is_sensitive(path: &Path, home: Option<&Path>) -> bool {
    let p = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    sensitive_roots(home).iter().any(|s| s.starts_with(&p))
}

/// The sandbox profile of one session, and the warnings to print about it
/// (implicit grants that were skipped, explicit grants of sensitive paths).
///
/// Refuses (`ENTANGLE-E0683`) a session whose project directory is the home
/// directory or the filesystem root: the project is writable, so that would
/// make everything writable.
pub(crate) fn build_profile(
    program: &Path,
    cwd: &Path,
    session_dir: &Path,
    adapter: &SandboxPaths,
    opts: &SandboxOptions,
) -> Result<(AgentProfile, Vec<String>)> {
    let home = canonical_home();
    let cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let project = project_dir(&cwd, home.as_deref());
    if project.parent().is_none() || home.as_deref() == Some(project.as_path()) {
        bail!(
            "ENTANGLE-E0683: the sandboxed agent would get write access to {} (the project \
             directory is the {}); cd into a project directory, name what it may write with \
             --sandbox-write <dir>, or pass --no-sandbox",
            project.display(),
            if project.parent().is_none() {
                "filesystem root"
            } else {
                "home directory"
            }
        );
    }
    let mut p = AgentProfile::new(program, &project);
    let mut warnings = Vec::new();
    let mut implicit_read = |p: &mut AgentProfile, dir: PathBuf, why: &str| {
        if is_sensitive(&dir, home.as_deref()) {
            warnings.push(format!(
                "sandbox: not granting read access to {} ({why}): it is or contains your home \
                 directory, the filesystem root or a key directory; use --sandbox-read to grant \
                 it explicitly",
                dir.display()
            ));
        } else {
            p.read_only.push(dir);
        }
    };

    // Tools: every directory on PATH, and the trees the agent itself is
    // installed in.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path).filter(|d| d.is_absolute()) {
            implicit_read(&mut p, dir, "a PATH entry");
        }
    }
    for dir in install_roots(program) {
        implicit_read(&mut p, dir, "the agent's install tree");
    }
    // git reads the user's identity and settings; it never needs to write them.
    if let Some(home) = &home {
        p.read_only.push(home.join(".gitconfig"));
        p.read_only.push(home.join(".config/git"));
    }
    if let Some(git_dir) = linked_worktree_git_dir(&project, home.as_deref()) {
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
            if is_sensitive(&abs, home.as_deref()) {
                warnings.push(format!(
                    "warning: {flag} {}: this is or contains your home directory, the \
                     filesystem root or a key directory; the agent can reach it",
                    abs.display()
                ));
            }
            list.push(abs);
        }
    }

    if let Some(mb) = opts.max_memory_mb {
        p.limits.address_space_bytes = Some(mb.saturating_mul(1024 * 1024));
    }
    if let Some(n) = opts.max_open_files {
        p.limits.open_files = Some(n);
    }
    Ok((p, warnings))
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
/// - `--require-sandbox` on a host that cannot engage every layer (a
///   Landlock allowlist at ABI ≥ 3, the seccomp filter, `no_new_privs`):
///   `ENTANGLE-E0680`, the agent is not started.
/// - Otherwise whatever the host offers is engaged; the caller prints the
///   report, which names every missing layer.
pub(crate) fn engage(
    cmd: &mut std::process::Command,
    profile: Option<&AgentProfile>,
    opts: &SandboxOptions,
) -> Result<Engaged> {
    let Some(profile) = profile.filter(|_| !opts.disabled) else {
        return Ok(Engaged::Disabled);
    };
    let plan = host_plan();
    if opts.required && !plan.enforces_every_layer() {
        bail!(
            "ENTANGLE-E0680: --require-sandbox: this host cannot engage every layer of the agent \
             sandbox (Landlock ABI >= 3, seccomp, no_new_privs): {}; the agent was not started. \
             See `entangle doctor`",
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

/// After a sandboxed agent exited with a non-zero status: one hint that a
/// sandbox denial may be the cause. Claude Code, for one, rewrites
/// `~/.claude.json` through a temporary file in the home directory, which
/// the allowlist does not permit; real agent sessions are untested here.
pub(crate) fn exit_hint(engaged: &Engaged, code: i32) {
    if code == 0 {
        return;
    }
    if let Engaged::Plan { plan, .. } = engaged {
        if plan.filesystem_confined() {
            eprintln!(
                "note: the agent exited with status {code} inside the OS sandbox. If it failed \
                 on a file it may not write, grant that path with --sandbox-write <path>, or run \
                 it with --no-sandbox."
            );
        }
    }
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
            eprintln!(
                "note: the sandbox limits files and socket families; it is not a containment \
                 boundary. Through local sockets (D-Bus, ssh-agent, Docker) and the environment \
                 variables it inherits, the agent can still act as \
                 you. See docs/agents.md."
            );
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

    /// A main repository with a linked work tree, laid out as
    /// `git worktree add` does. Returns (root, main .git, work tree).
    fn worktree_fixture(root: &Path) -> (PathBuf, PathBuf) {
        let main_git = root.join("main/.git");
        let wt_meta = main_git.join("worktrees/wt");
        std::fs::create_dir_all(&wt_meta).unwrap();
        std::fs::create_dir_all(main_git.join("objects")).unwrap();
        std::fs::create_dir_all(main_git.join("refs")).unwrap();
        std::fs::write(main_git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(wt_meta.join("commondir"), "../..\n").unwrap();
        let wt = root.join("wt");
        std::fs::create_dir(&wt).unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", wt_meta.display())).unwrap();
        std::fs::write(
            wt_meta.join("gitdir"),
            format!("{}\n", wt.join(".git").display()),
        )
        .unwrap();
        (main_git, wt)
    }

    #[test]
    fn linked_worktree_finds_the_main_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let (main_git, wt) = worktree_fixture(&root);
        assert_eq!(linked_worktree_git_dir(&wt, None), Some(main_git));
        // An ordinary repository (a `.git` directory) and no repository.
        assert_eq!(linked_worktree_git_dir(&root.join("main"), None), None);
        assert_eq!(linked_worktree_git_dir(&root, None), None);
    }

    /// Finding: a `.git` file written by an earlier session's agent named
    /// any directory as the "common dir" and the next session granted it
    /// read-write.
    #[test]
    fn a_crafted_git_file_grants_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();

        // 1. commondir pointing at the home directory.
        let evil = root.join("evil");
        std::fs::create_dir_all(&evil).unwrap();
        let proj = root.join("proj");
        std::fs::create_dir(&proj).unwrap();
        std::fs::write(evil.join("commondir"), format!("{}\n", home.display())).unwrap();
        std::fs::write(
            evil.join("gitdir"),
            format!("{}\n", proj.join(".git").display()),
        )
        .unwrap();
        std::fs::write(proj.join(".git"), format!("gitdir: {}\n", evil.display())).unwrap();
        assert_eq!(linked_worktree_git_dir(&proj, Some(&home)), None);

        // 2. Even a home directory that looks like a git dir (dotfiles repo)
        //    with a matching worktrees/ entry is never granted.
        for d in ["objects", "refs", "worktrees/x"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::fs::write(home.join("HEAD"), "x").unwrap();
        let meta = home.join("worktrees/x");
        std::fs::write(meta.join("commondir"), "../..\n").unwrap();
        std::fs::write(
            meta.join("gitdir"),
            format!("{}\n", proj.join(".git").display()),
        )
        .unwrap();
        std::fs::write(proj.join(".git"), format!("gitdir: {}\n", meta.display())).unwrap();
        assert_eq!(linked_worktree_git_dir(&proj, Some(&home)), None);

        // 3. A real layout whose back-pointer names another work tree.
        let (_, wt) = worktree_fixture(&root);
        let meta = root.join("main/.git/worktrees/wt");
        std::fs::write(
            meta.join("gitdir"),
            format!("{}\n", proj.join(".git").display()),
        )
        .unwrap();
        assert_eq!(linked_worktree_git_dir(&wt, Some(&home)), None);

        // 4. A common dir that is not a git directory.
        let (main_git, wt2) = {
            let r2 = root.join("r2");
            std::fs::create_dir(&r2).unwrap();
            worktree_fixture(&r2)
        };
        std::fs::remove_dir(main_git.join("objects")).unwrap();
        assert_eq!(linked_worktree_git_dir(&wt2, Some(&home)), None);
    }

    #[test]
    fn sensitive_roots_cover_home_root_and_key_directories() {
        let home = Path::new("/nonexistent-home/u");
        for p in [
            "/",
            "/nonexistent-home",
            "/nonexistent-home/u",
            "/nonexistent-home/u/.ssh",
            "/nonexistent-home/u/.entangle",
            "/nonexistent-home/u/.aws",
            "/nonexistent-home/u/.gnupg",
        ] {
            assert!(is_sensitive(Path::new(p), Some(home)), "{p}");
        }
        for p in [
            "/usr/bin",
            "/nonexistent-home/u/.local/bin",
            "/nonexistent-home/u/proj",
        ] {
            assert!(!is_sensitive(Path::new(p), Some(home)), "{p}");
        }
    }

    #[test]
    fn a_session_in_the_root_or_home_directory_is_refused() {
        let sess = tempfile::tempdir().unwrap();
        let adapter = SandboxPaths::default();
        let err = build_profile(
            Path::new("/bin/sh"),
            Path::new("/"),
            sess.path(),
            &adapter,
            &SandboxOptions::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0683"), "{err}");
        assert!(err.to_string().contains("--no-sandbox"), "{err}");
        if let Some(home) = canonical_home() {
            let err = build_profile(
                Path::new("/bin/sh"),
                &home,
                sess.path(),
                &adapter,
                &SandboxOptions::default(),
            )
            .unwrap_err();
            assert!(err.to_string().contains("home directory"), "{err}");
        }
    }

    /// Nothing in the default profile reads or writes the home directory as
    /// a whole, the root, or a key directory.
    #[test]
    fn default_profile_grants_no_sensitive_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let (cwd, session) = (root.join("proj"), root.join("sess"));
        std::fs::create_dir(&cwd).unwrap();
        std::fs::create_dir(&session).unwrap();
        let (p, _) = build_profile(
            Path::new("/bin/sh"),
            &cwd,
            &session,
            &SandboxPaths::default(),
            &SandboxOptions::default(),
        )
        .unwrap();
        let home = canonical_home();
        for g in p.read_only.iter().chain(&p.read_write) {
            assert!(!is_sensitive(g, home.as_deref()), "granted {}", g.display());
        }
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
        let (p, _) = build_profile(Path::new("/bin/sh"), &cwd, &session, &adapter, &opts).unwrap();
        assert_eq!(p.project_dir, cwd);
        assert!(p.read_write.contains(&state) && p.read_write.contains(&extra));
        // The session config is read-only unless the adapter writes there.
        assert!(p.read_only.contains(&session) && !p.read_write.contains(&session));
        assert_eq!(p.limits.address_space_bytes, Some(8 * 1024 * 1024));

        let codex = SandboxPaths {
            session_dir_writable: true,
            ..SandboxPaths::default()
        };
        let (p, _) = build_profile(
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
