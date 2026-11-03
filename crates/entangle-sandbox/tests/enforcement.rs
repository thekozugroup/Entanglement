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

/// `socketpair()` is the other way to obtain a Unix socket: a datagram pair
/// can `sendto` any path-named socket the uid can reach, bypassing the
/// `socket(AF_UNIX)` denial (and relaying data out of a network-denied
/// plugin). It must be filtered by family exactly like `socket()`.
#[tokio::test(flavor = "multi_thread")]
async fn child_cannot_reach_a_unix_socket_through_socketpair_unless_granted() {
    let outside = tempfile::tempdir().unwrap();
    let sock = outside.path().join("listener.sock");
    let listener = std::os::unix::net::UnixDatagram::bind(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();

    let p = profile();
    let plan = host_plan(&p);
    if !plan.seccomp {
        eprintln!("skipping: no seccomp on this host ({})", plan.describe());
        return;
    }
    let errno = denied_errno(call(&p, &format!("unix-dgram:{}", sock.display())).await);
    assert_eq!(errno, libc::EACCES, "{}", plan.describe());
    let mut buf = [0u8; 64];
    assert!(
        listener.recv(&mut buf).is_err(),
        "a datagram from the sandbox reached the outside listener"
    );

    // Control: with Unix sockets granted the same request is delivered, so
    // the denial above is the filter's doing.
    let granted = profile().allow_unix_sockets(true);
    let out = call(&granted, &format!("unix-dgram:{}", sock.display()))
        .await
        .unwrap();
    assert_eq!(out, b"sent");
    listener.set_nonblocking(false).unwrap();
    let n = listener.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"escaped");
}

/// A plugin must not create namespaces of its own (a fresh user namespace
/// gives it every capability there, reaching CAP_NET_ADMIN-gated kernel
/// code), whether or not it was granted the network. Threads (`clone3` is
/// answered with ENOSYS, libc falls back to `clone`) keep working.
#[tokio::test(flavor = "multi_thread")]
async fn child_cannot_create_namespaces() {
    for p in [profile(), profile().allow_network(true)] {
        let plan = host_plan(&p);
        if !plan.seccomp {
            eprintln!("skipping: no seccomp on this host ({})", plan.describe());
            return;
        }
        assert_eq!(call(&p, "thread").await.unwrap(), b"joined");
        let errno = denied_errno(call(&p, "unshare").await);
        assert_eq!(errno, libc::EPERM, "{}", plan.describe());
    }
}

/// Soft "Max open files" limit and nice value of `pid`, from `/proc`.
fn nofile_and_nice(pid: u32) -> (String, String) {
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let nofile = limits
        .lines()
        .find(|l| l.starts_with("Max open files"))
        .and_then(|l| l.split_whitespace().nth(3))
        .unwrap()
        .to_owned();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    // Field 19 (nice); fields after the parenthesised comm start at 3.
    let after_comm = &stat[stat.rfind(')').unwrap() + 2..];
    let nice = after_comm.split_whitespace().nth(16).unwrap().to_owned();
    (nofile, nice)
}

/// Without a PID namespace the plugin shares the daemon's uid, and neither
/// Landlock nor the namespaces stop `prlimit`/`setpriority` on another
/// process: a plugin could set the daemon's RLIMIT_CPU to 1 (the kernel then
/// kills it) or RLIMIT_NOFILE to 0. Calls on the plugin itself still work.
#[tokio::test(flavor = "multi_thread")]
async fn child_cannot_change_another_processs_limits_or_priority() {
    let mut victim = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn victim");
    let pid = victim.id();
    let before = nofile_and_nice(pid);
    assert_ne!(before.0, "123");

    for p in [profile(), profile().allow_network(true)] {
        let plan = host_plan(&p);
        if !plan.seccomp {
            eprintln!("skipping: no seccomp on this host ({})", plan.describe());
            break;
        }
        let r = call(&p, &format!("prlimit:{pid}")).await;
        let r2 = call(&p, &format!("renice:{pid}")).await;
        let after = nofile_and_nice(pid);
        assert_eq!(
            after,
            before,
            "victim changed by {}: {r:?} {r2:?}",
            plan.describe()
        );
        assert_eq!(denied_errno(r), libc::EPERM);
        assert_eq!(denied_errno(r2), libc::EPERM);
        // On itself the same calls are fine.
        assert_eq!(call(&p, "prlimit:0").await.unwrap(), b"set");
        assert_eq!(call(&p, "renice:0").await.unwrap(), b"reniced");
    }
    let _ = victim.kill();
    let _ = victim.wait();
}

/// The session keyring is inherited across fork and exec, and Landlock,
/// namespaces and the socket filter do not cover keyrings: a plugin must not
/// be able to read secrets the daemon (or the user's login session, under
/// the CLI's local kernel) keeps there.
///
/// Single-threaded runtime: the keyring is per thread's credentials, so the
/// key is added and the child spawned from the same thread.
#[tokio::test(flavor = "current_thread")]
async fn child_cannot_read_the_parents_session_keyring() {
    const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;
    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    // A private anonymous session keyring for this test thread, so nothing
    // outlives the test.
    let r = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<libc::c_char>(),
        )
    };
    if r < 0 {
        eprintln!(
            "skipping: no keyrings here ({})",
            std::io::Error::last_os_error()
        );
        return;
    }
    let secret = b"s3cr3t-daemon-key";
    let id = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            c"user".as_ptr(),
            c"entangle-test-secret".as_ptr(),
            secret.as_ptr(),
            secret.len(),
            KEY_SPEC_SESSION_KEYRING,
        )
    };
    assert!(id > 0, "add_key: {}", std::io::Error::last_os_error());

    // The host's plans, plus one without seccomp: the fresh session keyring
    // must hold on its own where the key syscalls cannot be filtered.
    let no_seccomp = entangle_sandbox::HostSupport {
        seccomp: false,
        ..probe().clone()
    };
    let p = profile();
    let mut plans = vec![
        (p.clone(), host_plan(&p)),
        (
            profile().allow_network(true),
            host_plan(&profile().allow_network(true)),
        ),
    ];
    if let Ok(plan) = plan(&p, &no_seccomp, Policy::default()) {
        plans.push((p, plan));
    }
    for (p, plan) in plans {
        let cmd = sandboxed_command(&p, &plan).unwrap();
        let r = Supervisor::new("testchild", InvokeLimits::default())
            .invoke(cmd, b"keyring:entangle-test-secret")
            .await;
        assert!(
            matches!(&r, Err(SupervisorError::PluginError(m)) if m.starts_with("errno=")),
            "{}: the child read the parent's keyring: {r:?}",
            plan.describe()
        );
    }
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
