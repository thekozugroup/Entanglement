//! Real Seatbelt engagement on macOS (`sandbox-exec -p <generated SBPL>`).
//!
//! Compiled only on macOS; CI's macos-14 runner has `/usr/bin/sandbox-exec`.
//! The profile *text* is unit-tested on every platform in `seatbelt.rs`.
#![cfg(target_os = "macos")]

use std::path::PathBuf;

use entangle_sandbox::{
    plan, probe, sandboxed_command, InvokeLimits, Mechanism, Policy, SandboxProfile, Supervisor,
    SupervisorError,
};

fn testchild() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_entangle-sandbox-testchild"))
}

#[test]
fn trial_engagement_enforces_under_seatbelt() {
    if probe().sandbox_exec.is_none() {
        eprintln!("sandbox-exec not present; nothing to smoke-test");
        return;
    }
    match entangle_sandbox::trial::run_trial(Policy::default()) {
        entangle_sandbox::trial::TrialOutcome::Enforced { plan } => {
            assert!(matches!(plan.mechanism, Mechanism::Seatbelt { .. }));
        }
        other => panic!("Seatbelt trial did not enforce: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_runs_under_seatbelt_and_is_confined() {
    if probe().sandbox_exec.is_none() {
        eprintln!("sandbox-exec not present; nothing to smoke-test");
        return;
    }
    let scope = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    std::fs::write(&secret, "x").unwrap();

    let p = SandboxProfile::new(testchild()).read_write(scope.path());
    let pl = plan(&p, probe(), Policy::default()).unwrap();
    let run = |req: String| {
        let cmd = sandboxed_command(&p, &pl).unwrap();
        async move {
            Supervisor::new("testchild", InvokeLimits::default())
                .invoke(cmd, req.as_bytes())
                .await
        }
    };

    assert_eq!(run("echo:hi".into()).await.unwrap(), b"hi");

    let inside = std::fs::canonicalize(scope.path()).unwrap().join("f");
    assert_eq!(
        run(format!("write:{}=ok", inside.display())).await.unwrap(),
        b"written"
    );

    match run(format!("read:{}", secret.display())).await {
        Err(SupervisorError::PluginError(msg)) => assert!(msg.starts_with("errno="), "{msg}"),
        other => panic!("read outside the profile was not denied: {other:?}"),
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    match run(format!("connect:{addr}")).await {
        Err(SupervisorError::PluginError(msg)) => assert!(msg.starts_with("errno="), "{msg}"),
        other => panic!("network was not denied: {other:?}"),
    }
}
