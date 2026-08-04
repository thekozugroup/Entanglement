//! Integration tests for per-invocation resource limits and timeouts.
//!
//! Uses the pre-built `stress.wasm` fixture (see
//! `crates/entangle-host/fixtures-src/stress/`), whose behavior is selected
//! by the input bytes:
//! - `grow`      — allocate 1 MiB chunks forever until the host limiter trips.
//! - `spin:<ms>` — busy-loop for `<ms>` wall-clock milliseconds, return `spun`.
//! - other       — echo the input back.
//!
//! To rebuild the fixture run:
//!   bash crates/entangle-host/fixtures-src/stress/build.sh

use entangle_host::state::ResourceLimits;
use entangle_host::{HostEngine, HostError, LoadedPlugin};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use std::time::{Duration, Instant};

fn load_stress(engine: &HostEngine) -> LoadedPlugin {
    let bytes = include_bytes!("fixtures/stress.wasm");
    let plugin_id: PluginId = "aabbccddeeff00112233445566778899/stress@0.1.0"
        .parse()
        .unwrap();
    LoadedPlugin::from_bytes(engine, bytes, plugin_id, Tier::Pure).expect("compile stress fixture")
}

/// A `memory.grow` loop is stopped by the store limiter: the invocation fails
/// fast with `ResourceExhausted` (E0506) instead of ballooning host RSS or
/// running until the wall-clock timeout.
#[tokio::test(flavor = "multi_thread")]
async fn memory_grow_loop_fails_fast_with_resource_exhausted() {
    let engine = HostEngine::new().expect("engine");
    let plugin = load_stress(&engine);

    // 32 MiB cap bounds host RSS for this invocation; the 30s timeout proves
    // the failure comes from the limiter, not the deadline.
    let limits = ResourceLimits {
        memory_bytes: 32 * 1024 * 1024,
        ..ResourceLimits::default()
    };
    let started = Instant::now();
    let result = plugin
        .run_one_shot_with_limits(&engine, b"grow", 30_000, limits)
        .await;
    let elapsed = started.elapsed();

    match result {
        Err(HostError::ResourceExhausted(_)) => {}
        other => panic!("expected ResourceExhausted, got: {other:?}"),
    }
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.starts_with("ENTANGLE-E0506"),
        "expected E0506 code, got: {msg}"
    );
    // "Fails fast": nowhere near the 30s timeout (growing 32 MiB takes
    // milliseconds; be generous for slow CI).
    assert!(
        elapsed < Duration::from_secs(15),
        "grow loop took {elapsed:?}; limiter did not stop it promptly"
    );
}

/// Two concurrent invocations with different timeouts do not cancel each
/// other: the short one times out with E0504 while the long-running one keeps
/// executing past that moment and completes.
///
/// Regression test for the previous design where each call spawned a one-shot
/// timer that bumped the SHARED engine epoch (deadline 1 on every store), so
/// any single timeout trapped every in-flight invocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_timeouts_do_not_cross_cancel() {
    let engine = HostEngine::new().expect("engine");
    let plugin = load_stress(&engine);

    // Long invocation: ~600ms of guest execution, generous 5s timeout.
    let long = {
        let engine = engine.clone();
        let plugin = plugin.clone();
        tokio::spawn(async move { plugin.run_one_shot(&engine, b"spin:600", 5_000).await })
    };
    // Give the long invocation a head start so it is mid-spin when the short
    // one's deadline fires.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Short invocation: guest wants 10s but is capped at 100ms.
    let short = {
        let engine = engine.clone();
        let plugin = plugin.clone();
        tokio::spawn(async move { plugin.run_one_shot(&engine, b"spin:10000", 100).await })
    };

    let short_result = short.await.expect("short task join");
    match short_result {
        Err(HostError::Timeout(100)) => {}
        other => panic!("expected Timeout(100) for short invocation, got: {other:?}"),
    }
    let msg = short_result.unwrap_err().to_string();
    assert!(
        msg.starts_with("ENTANGLE-E0504"),
        "expected E0504 code, got: {msg}"
    );

    // The long invocation must survive the short one's timeout.
    let long_result = long.await.expect("long task join");
    match long_result {
        Ok(run) => assert_eq!(run.output, b"spun"),
        Err(e) => panic!("long invocation was disturbed by concurrent timeout: {e:?}"),
    }
}

/// A failing instantiation (initial memory denied by the limiter) does not
/// disturb a concurrent invocation.
///
/// Regression test for the timer leak in the previous design: error paths
/// returned early without aborting the per-call timer, which later bumped the
/// shared epoch and trapped whatever else was running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failing_instantiate_does_not_disturb_concurrent_invocation() {
    let engine = HostEngine::new().expect("engine");
    let plugin = load_stress(&engine);

    // Long-running invocation with a generous timeout.
    let long = {
        let engine = engine.clone();
        let plugin = plugin.clone();
        tokio::spawn(async move { plugin.run_one_shot(&engine, b"spin:500", 10_000).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 64 KiB (one wasm page) is far below the guest's initial memory, so
    // instantiation itself fails at the limiter — while `long` is mid-spin.
    let tiny = ResourceLimits {
        memory_bytes: 64 * 1024,
        ..ResourceLimits::default()
    };
    let failing = plugin
        .run_one_shot_with_limits(&engine, b"spin:1", 100, tiny)
        .await;
    match failing {
        Err(HostError::ResourceExhausted(_)) => {}
        other => panic!("expected ResourceExhausted at instantiation, got: {other:?}"),
    }

    // The concurrent invocation completes untouched.
    let long_result = long.await.expect("long task join");
    match long_result {
        Ok(run) => assert_eq!(run.output, b"spun"),
        Err(e) => panic!("long invocation was disturbed by failing instantiate: {e:?}"),
    }
}

/// Sanity: the stress fixture echoes unrecognized input, proving the fixture
/// itself works under default limits (guards against the other tests passing
/// for the wrong reason).
#[tokio::test(flavor = "multi_thread")]
async fn stress_fixture_echoes_input_under_default_limits() {
    let engine = HostEngine::new().expect("engine");
    let plugin = load_stress(&engine);
    let result = plugin
        .run_one_shot(&engine, b"echo-me", 30_000)
        .await
        .expect("run");
    assert_eq!(result.output, b"echo-me");
}
