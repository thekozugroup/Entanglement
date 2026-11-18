//! Real enforcement of the agent-session sandbox (`entangle_sandbox::agent`)
//! on Linux: a child confined with the agent profile can write inside its
//! project directory and nowhere outside the allowlist, keeps the network
//! and its process-group calls, and loses raw sockets and namespaces.
//!
//! Directories are created under `CARGO_TARGET_TMPDIR`, not the system
//! temporary directory: `/tmp` is on the agent allowlist, so a file there
//! would not be "outside".
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use entangle_sandbox::{
    agent_plan, confine_agent_command, probe, AgentFilesystem, AgentPlan, AgentProfile,
    HostSupport, InvokeLimits, Platform, Supervisor, SupervisorError,
};

fn testchild() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_entangle-sandbox-testchild"))
}

fn dir() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

async fn call(
    profile: &AgentProfile,
    plan: &AgentPlan,
    req: &str,
) -> Result<Vec<u8>, SupervisorError> {
    let mut cmd = std::process::Command::new(&profile.program);
    confine_agent_command(&mut cmd, profile, plan).expect("confine");
    Supervisor::new("agent-testchild", InvokeLimits::default())
        .invoke(cmd, req.as_bytes())
        .await
}

fn errno(r: Result<Vec<u8>, SupervisorError>) -> i32 {
    match r {
        Err(SupervisorError::PluginError(msg)) => msg
            .strip_prefix("errno=")
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("unexpected error text: {msg}")),
        other => panic!("expected the child to report a denial, got {other:?}"),
    }
}

/// The plan this host supports. The enforcement tests need Landlock; a host
/// without it is covered by `landlock_unavailable_*` below.
fn host_plan() -> Option<AgentPlan> {
    let plan = agent_plan(probe());
    if plan.filesystem_confined() {
        Some(plan)
    } else {
        eprintln!("skipping: {}", plan.describe());
        None
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sandboxed_agent_writes_inside_the_project_and_not_outside_the_allowlist() {
    let Some(plan) = host_plan() else { return };
    let project = dir();
    let outside = dir();
    let profile = AgentProfile::new(testchild(), project.path());

    let inside = project.path().join("src/new.txt");
    std::fs::create_dir(project.path().join("src")).unwrap();
    let out = call(
        &profile,
        &plan,
        &format!("write:{}=hello", inside.display()),
    )
    .await
    .expect("a write inside the project directory must succeed");
    assert_eq!(out, b"written");
    assert_eq!(std::fs::read_to_string(&inside).unwrap(), "hello");

    let target = outside.path().join("escape.txt");
    let e = errno(call(&profile, &plan, &format!("write:{}=x", target.display())).await);
    assert_eq!(e, libc_eacces(), "write outside the allowlist");
    assert!(!target.exists(), "the file must not have been created");

    // An existing file outside is neither writable nor readable.
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "top secret").unwrap();
    let e = errno(call(&profile, &plan, &format!("write:{}=x", secret.display())).await);
    assert_eq!(e, libc_eacces());
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "top secret");
    let e = errno(call(&profile, &plan, &format!("read:{}", secret.display())).await);
    assert_eq!(e, libc_eacces(), "read outside the allowlist");
}

#[tokio::test(flavor = "multi_thread")]
async fn extra_read_write_and_read_only_paths_are_honoured() {
    let Some(plan) = host_plan() else { return };
    let project = dir();
    let state = dir();
    let reference = dir();
    std::fs::write(reference.path().join("doc.txt"), "reference").unwrap();
    let profile = AgentProfile::new(testchild(), project.path())
        .read_write(state.path())
        .read_only(reference.path());

    let f = state.path().join("history.json");
    call(&profile, &plan, &format!("write:{}={{}}", f.display()))
        .await
        .expect("the agent's own state directory is writable");
    let doc = reference.path().join("doc.txt");
    let out = call(&profile, &plan, &format!("read:{}", doc.display()))
        .await
        .expect("a read-only path is readable");
    assert_eq!(out, b"reference");
    let e = errno(call(&profile, &plan, &format!("write:{}=x", doc.display())).await);
    assert_eq!(e, libc_eacces(), "a read-only path is not writable");
}

#[tokio::test(flavor = "multi_thread")]
async fn temp_directories_are_writable() {
    let Some(plan) = host_plan() else { return };
    let project = dir();
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let profile = AgentProfile::new(testchild(), project.path());
    let f = tmp.path().join("scratch");
    call(&profile, &plan, &format!("write:{}=1", f.display()))
        .await
        .expect("/tmp is writable for an agent");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_keeps_the_network_and_sessions_but_not_raw_sockets_or_namespaces() {
    let Some(plan) = host_plan() else { return };
    let project = dir();
    let profile = AgentProfile::new(testchild(), project.path());

    // Network egress is NOT restricted: a loopback connection succeeds.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let out = call(&profile, &plan, &format!("connect:{addr}"))
        .await
        .expect("an agent may open TCP connections");
    assert_eq!(out, b"connected");

    // Shells need sessions and process groups (refused for native plugins).
    let out = call(&profile, &plan, "setsid").await.expect("setsid");
    assert_eq!(out, b"escaped");

    if plan.seccomp {
        let e = errno(call(&profile, &plan, "raw").await);
        assert_eq!(e, libc_eacces(), "raw IP socket");
        let e = errno(call(&profile, &plan, "unshare").await);
        assert_eq!(e, 1, "unshare(CLONE_NEWUSER|CLONE_NEWNET) must be EPERM");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_started_by_root_holds_no_capabilities() {
    let Some(plan) = host_plan() else { return };
    let project = dir();
    let profile = AgentProfile::new(testchild(), project.path());
    let out = call(&profile, &plan, "caps").await.expect("caps probe");
    let text = String::from_utf8_lossy(&out).into_owned();
    // Effective, permitted, inheritable and ambient sets are empty (the
    // bounding set can only be emptied by a process that had CAP_SETPCAP).
    assert!(
        text.starts_with("eff=0 prm=0 inh=0 ") && text.ends_with("amb=0"),
        "expected empty capability sets, got {text}"
    );
}

/// The degraded mode: no Landlock. Nothing confines the filesystem — and
/// the plan says so — while the socket filter still applies.
#[tokio::test(flavor = "multi_thread")]
async fn landlock_unavailable_runs_degraded_with_the_remaining_layers() {
    let host = HostSupport {
        platform: Platform::Linux,
        landlock_abi: None,
        user_namespaces: false,
        seccomp: probe().seccomp,
        bubblewrap: None,
        sandbox_exec: None,
    };
    let plan = agent_plan(&host);
    assert!(matches!(
        plan.filesystem,
        AgentFilesystem::NotConfined { .. }
    ));
    assert!(plan.is_degraded());
    assert!(plan.describe().contains("NO filesystem allowlist"));

    let project = dir();
    let outside = dir();
    let profile = AgentProfile::new(testchild(), project.path());
    // Not confined: the write outside the project succeeds. This is what the
    // warning printed by `entangle agent run` is about.
    let target = outside.path().join("unconfined.txt");
    call(&profile, &plan, &format!("write:{}=x", target.display()))
        .await
        .expect("without Landlock the filesystem is not confined");
    assert!(target.exists());
    if plan.seccomp {
        let e = errno(call(&profile, &plan, "raw").await);
        assert_eq!(e, libc_eacces(), "the socket filter still applies");
    }
}

/// A plan that engages nothing (what other platforms get) leaves the
/// command untouched.
#[tokio::test(flavor = "multi_thread")]
async fn a_plan_that_engages_nothing_changes_nothing() {
    let host = HostSupport {
        platform: Platform::MacOs,
        landlock_abi: None,
        user_namespaces: false,
        seccomp: false,
        bubblewrap: None,
        sandbox_exec: None,
    };
    let plan = agent_plan(&host);
    assert!(!plan.engages_anything());
    let project = dir();
    let profile = AgentProfile::new(testchild(), project.path());
    let out = call(&profile, &plan, "echo:hi").await.unwrap();
    assert_eq!(out, b"hi");
}

#[test]
fn a_missing_project_directory_fails_before_spawn() {
    let Some(plan) = host_plan() else { return };
    let profile = AgentProfile::new(testchild(), Path::new("/no/such/project/dir"));
    let mut cmd = std::process::Command::new(testchild());
    let err = confine_agent_command(&mut cmd, &profile, &plan).unwrap_err();
    assert!(err.to_string().starts_with("ENTANGLE-E0682"), "{err}");
}

fn libc_eacces() -> i32 {
    13
}
