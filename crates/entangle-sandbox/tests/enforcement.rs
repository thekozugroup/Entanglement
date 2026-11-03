//! Real sandbox enforcement on Linux: a child engaged under the plan this
//! host supports must be denied what its profile does not grant.
//!
//! Every test asserts the *property* (the read fails, the connection fails)
//! so it holds whichever mechanism the host offers — Landlock + user/net
//! namespace + seccomp here, Landlock + seccomp + Landlock TCP rules on
//! Ubuntu 24.04 where unprivileged user namespaces are restricted. Where a
//! property depends on one specific layer (UDP needs a namespace or seccomp,
//! Unix sockets need seccomp) the test checks the plan first and says so.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use entangle_sandbox::{
    plan, probe, sandboxed_command, InvokeLimits, Mechanism, NetworkIsolation, Plan, Policy,
    SandboxProfile, Supervisor, SupervisorError,
};

fn testchild() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_entangle-sandbox-testchild"))
}

fn profile() -> SandboxProfile {
    SandboxProfile::new(testchild())
}

fn host_plan(p: &SandboxProfile) -> Plan {
    let host = probe();
    assert!(
        host.has_primitive(),
        "this Linux host offers no sandbox primitive ({}); the enforcement tests need one",
        host.describe()
    );
    plan(p, host, Policy::default()).unwrap_or_else(|e| panic!("no plan on this host: {e}"))
}

async fn call_with(
    p: &SandboxProfile,
    req: &str,
    limits: InvokeLimits,
) -> Result<Vec<u8>, SupervisorError> {
    let plan = host_plan(p);
    let cmd = sandboxed_command(p, &plan).expect("command");
    Supervisor::new("testchild", limits)
        .invoke(cmd, req.as_bytes())
        .await
}

async fn call(p: &SandboxProfile, req: &str) -> Result<Vec<u8>, SupervisorError> {
    call_with(p, req, InvokeLimits::default()).await
}

fn denied_errno(r: Result<Vec<u8>, SupervisorError>) -> i32 {
    match r {
        Err(SupervisorError::PluginError(msg)) => {
            let n = msg
                .strip_prefix("errno=")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("unexpected error text: {msg}"));
            n
        }
        other => panic!("expected the child to report a denial, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn child_cannot_read_outside_its_scope() {
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "top secret").unwrap();
    let scope = tempfile::tempdir().unwrap();

    let p = profile().read_write(scope.path());
    // Control: this process can read it, so a failure is the sandbox's doing.
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "top secret");

    let errno = denied_errno(call(&p, &format!("read:{}", secret.display())).await);
    match host_plan(&p).mechanism {
        Mechanism::Landlock { .. } => {
            assert_eq!(errno, libc::EACCES, "Landlock denies with EACCES")
        }
        Mechanism::Bubblewrap { .. } => assert_eq!(errno, libc::ENOENT, "not mounted under bwrap"),
        other => panic!("unexpected mechanism {other:?}"),
    }

    // Writing outside is denied too.
    let target = outside.path().join("planted");
    let errno = denied_errno(call(&p, &format!("write:{}=x", target.display())).await);
    assert!(
        errno == libc::EACCES || errno == libc::ENOENT,
        "errno {errno}"
    );
    assert!(!target.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn child_can_read_and_write_inside_its_scope() {
    let scope = tempfile::tempdir().unwrap();
    let file = scope.path().join("state.txt");
    let p = profile().read_write(scope.path());

    let out = call(&p, &format!("write:{}=hello sandbox", file.display()))
        .await
        .expect("write inside scope");
    assert_eq!(out, b"written");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "hello sandbox");

    let out = call(&p, &format!("read:{}", file.display()))
        .await
        .expect("read inside scope");
    assert_eq!(out, b"hello sandbox");

    // Files the plugin creates keep this process's ownership (identity
    // uid/gid mapping in the user namespace, or no namespace at all).
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!(meta.uid(), unsafe { libc::getuid() });
}

#[tokio::test(flavor = "multi_thread")]
async fn read_only_scope_cannot_be_written() {
    let scope = tempfile::tempdir().unwrap();
    std::fs::write(scope.path().join("asset"), "data").unwrap();
    let p = profile().read_only(scope.path());
    let out = call(
        &p,
        &format!("read:{}", scope.path().join("asset").display()),
    )
    .await
    .unwrap();
    assert_eq!(out, b"data");
    let errno = denied_errno(
        call(
            &p,
            &format!("write:{}=x", scope.path().join("asset").display()),
        )
        .await,
    );
    assert!(
        errno == libc::EACCES || errno == libc::EROFS,
        "errno {errno}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn child_cannot_open_a_tcp_connection_without_network() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Control: with the network granted the same request connects, so the
    // listener is reachable and a denial below is the sandbox's doing.
    let granted = profile().allow_network(true);
    assert_eq!(host_plan(&granted).network, NetworkIsolation::Granted);
    let out = call(&granted, &format!("connect:{addr}"))
        .await
        .expect("granted connect");
    assert_eq!(out, b"connected");

    let denied = profile();
    let plan = host_plan(&denied);
    assert!(
        matches!(
            plan.network,
            NetworkIsolation::Denied | NetworkIsolation::TcpOnly
        ),
        "{}",
        plan.describe()
    );
    let errno = denied_errno(call(&denied, &format!("connect:{addr}")).await);
    // EACCES: seccomp socket filter or Landlock TCP rule; ENETUNREACH: the
    // fresh network namespace has no usable interface.
    assert!(
        errno == libc::EACCES || errno == libc::ENETUNREACH || errno == libc::EPERM,
        "unexpected errno {errno} ({})",
        plan.describe()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn child_cannot_send_udp_when_network_is_fully_denied() {
    let p = profile();
    let plan = host_plan(&p);
    if plan.network != NetworkIsolation::Denied {
        // TcpOnly hosts (Landlock TCP rules alone) cannot stop UDP; the plan
        // says so and `plan::tests` pins that this is reported as reduced.
        eprintln!("skipping UDP check: {}", plan.describe());
        return;
    }
    let errno = denied_errno(call(&p, "udp:127.0.0.1:9").await);
    assert!(
        errno == libc::EACCES || errno == libc::ENETUNREACH || errno == libc::EPERM,
        "unexpected errno {errno}"
    );
}

/// Path-addressed Unix sockets are outside Landlock's reach; the seccomp
/// filter is what keeps e.g. the daemon's RPC socket away from a plugin.
#[tokio::test(flavor = "multi_thread")]
async fn child_cannot_reach_a_unix_socket_unless_granted() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

    // The directory is even in scope: the filesystem layer is not what stops it.
    let p = profile().read_write(dir.path());
    let plan = host_plan(&p);
    if !plan.seccomp {
        eprintln!("skipping: no seccomp on this host ({})", plan.describe());
        return;
    }
    let errno = denied_errno(call(&p, &format!("unix:{}", sock.display())).await);
    assert_eq!(errno, libc::EACCES);

    let granted = profile().read_write(dir.path()).allow_unix_sockets(true);
    let out = call(&granted, &format!("unix:{}", sock.display()))
        .await
        .unwrap();
    assert_eq!(out, b"connected");
}

#[tokio::test(flavor = "multi_thread")]
async fn environment_is_exactly_what_the_profile_sets() {
    std::env::set_var("ENTANGLE_SANDBOX_TEST_LEAK", "parent-secret");
    let p = profile().env("ENTANGLE_PLUGIN_ID", "abc/test@0.1.0");
    assert_eq!(
        call(&p, "env:ENTANGLE_PLUGIN_ID").await.unwrap(),
        b"abc/test@0.1.0"
    );
    let r = call(&p, "env:ENTANGLE_SANDBOX_TEST_LEAK").await;
    assert!(
        matches!(r, Err(SupervisorError::PluginError(ref m)) if m == "unset"),
        "{r:?}"
    );
    let r = call(&p, "env:PATH").await;
    assert!(
        matches!(r, Err(SupervisorError::PluginError(ref m)) if m == "unset"),
        "{r:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_kills_the_child() {
    let limits = InvokeLimits {
        timeout: Duration::from_millis(400),
        ..InvokeLimits::default()
    };
    let started = Instant::now();
    let r = call_with(&profile(), "sleep:30000", limits).await;
    assert!(
        matches!(r, Err(SupervisorError::Timeout { timeout_ms: 400 })),
        "{r:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_output_is_rejected_from_the_header() {
    let limits = InvokeLimits {
        max_output_bytes: 1024,
        ..InvokeLimits::default()
    };
    let r = call_with(&profile(), "big:10000000", limits).await;
    match r {
        Err(SupervisorError::OutputTooLarge { limit, announced }) => {
            assert_eq!(limit, 1024);
            assert_eq!(announced, 10_000_000);
        }
        other => panic!("expected OutputTooLarge, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_child_that_lingers_after_answering_is_killed() {
    let limits = InvokeLimits {
        exit_grace: Duration::from_millis(200),
        ..InvokeLimits::default()
    };
    let started = Instant::now();
    let out = call_with(&profile(), "linger", limits).await.unwrap();
    assert_eq!(out, b"lingering");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread")]
async fn exit_without_answer_reports_status_and_stderr() {
    let r = call(&profile(), "exit:7").await;
    match r {
        Err(SupervisorError::NoResponse {
            status,
            stderr_tail,
        }) => {
            assert!(status.contains('7'), "{status}");
            assert!(stderr_tail.contains("exiting with 7"), "{stderr_tail}");
        }
        other => panic!("expected NoResponse, got {other:?}"),
    }
}

#[test]
fn trial_engagement_enforces_on_this_host() {
    match entangle_sandbox::trial::run_trial(Policy::default()) {
        entangle_sandbox::trial::TrialOutcome::Enforced { plan } => {
            assert!(!matches!(plan.mechanism, Mechanism::Unsandboxed));
        }
        other => panic!("trial engagement did not enforce: {other:?}"),
    }
}

#[test]
fn landlock_is_detected_via_the_abi_syscall() {
    // This container runs kernel 6.18 with Landlock; CI's ubuntu-24.04 runs
    // 6.8. Both must be detected — the old /proc probe found neither.
    let host = probe();
    if let Some(abi) = host.landlock_abi {
        assert!(abi >= 1);
        assert!(host.describe().contains("Landlock ABI"));
    }
}

/// Each network layer must deny TCP *on its own*, so that hosts offering only
/// a subset (Ubuntu 24.04: no unprivileged user namespaces) stay safe. The
/// real host's support is narrowed to one layer at a time and run for real.
#[tokio::test(flavor = "multi_thread")]
async fn each_network_layer_alone_denies_tcp() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let real = probe().clone();
    let abi = real.landlock_abi.expect("Landlock needed for this test");

    let variants = [
        // (name, user namespaces, seccomp, expected isolation)
        ("namespace only", true, false, NetworkIsolation::Denied),
        ("seccomp only", false, true, NetworkIsolation::Denied),
        (
            "Landlock TCP rules only",
            false,
            false,
            NetworkIsolation::TcpOnly,
        ),
    ];
    let mut exercised = 0;
    for (name, userns, seccomp, expected) in variants {
        if (userns && !real.user_namespaces)
            || (seccomp && !real.seccomp)
            || (expected == NetworkIsolation::TcpOnly && abi < 4)
        {
            eprintln!("host lacks the layer for variant {name:?}; skipped");
            continue;
        }
        let host = entangle_sandbox::HostSupport {
            user_namespaces: userns,
            seccomp,
            bubblewrap: None,
            ..real.clone()
        };
        let p = profile();
        let plan = plan(&p, &host, Policy::default()).expect("plan");
        assert_eq!(plan.network, expected, "{name}: {}", plan.describe());
        assert_eq!(plan.net_namespace, userns, "{name}");
        assert_eq!(plan.seccomp, seccomp, "{name}");
        let cmd = sandboxed_command(&p, &plan).unwrap();
        let r = Supervisor::new("testchild", InvokeLimits::default())
            .invoke(cmd, format!("connect:{addr}").as_bytes())
            .await;
        let errno = denied_errno(r);
        assert!(
            errno == libc::EACCES || errno == libc::ENETUNREACH,
            "{name}: unexpected errno {errno}"
        );
        exercised += 1;
    }
    assert!(
        exercised >= 1,
        "no network layer could be exercised on this host"
    );
}
