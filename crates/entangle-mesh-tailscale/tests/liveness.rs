//! Liveness state machine, poll loop (virtual clock) and fake-CLI tests.
//!
//! Time is virtual: the poll loop is driven by a [`VirtualClock`] whose
//! `sleep` advances `now` instantly, so 5-minute cadences cost nothing. (The
//! brief suggested `tokio::time::pause()`, which needs tokio's `test-util`
//! feature; enabling it would force a workspace-wide rebuild of tokio and all
//! its dependents, so the clock is injected instead.)

use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use entangle_mesh_tailscale::{
    spawn_liveness, CliStatusSource, Clock, LivenessConfig, LivenessMachine, Observation,
    StatusSource, TailnetState, Transition,
};

const S: fn(u64) -> Duration = Duration::from_secs;

fn stopped(r: &str) -> TailnetState {
    TailnetState::Stopped { reason: r.into() }
}

// ---------------------------------------------------------------- machine --

#[test]
fn first_observation_is_adopted_immediately() {
    let mut m = LivenessMachine::new(LivenessConfig::default());
    let t = m.observe(S(0), TailnetState::Active).unwrap();
    assert_eq!(t.from, None);
    assert_eq!(t.to, TailnetState::Active);
    assert_eq!(m.next_delay(), S(5));
}

#[test]
fn single_blip_does_not_fire() {
    let mut m = LivenessMachine::new(LivenessConfig::default());
    m.observe(S(0), TailnetState::Active);
    assert!(m.observe(S(5), stopped("Stopped")).is_none());
    assert!(m.observe(S(10), TailnetState::Active).is_none());
    // Even after the blip clears, a later single blip still needs the full
    // confirmation (counter was reset).
    assert!(m.observe(S(15), stopped("Stopped")).is_none());
    assert!(m.observe(S(20), TailnetState::Active).is_none());
    assert_eq!(m.current(), Some(&TailnetState::Active));
}

#[test]
fn leaving_active_waits_for_the_30s_grace() {
    let mut m = LivenessMachine::new(LivenessConfig::default());
    m.observe(S(0), TailnetState::Active);
    // Bad from t=5. Two polls confirmed at t=10 but grace not elapsed.
    for t in [5, 10, 15, 20, 25, 30, 34] {
        assert!(m.observe(S(t), stopped("NeedsLogin")).is_none(), "t={t}");
    }
    let tr = m
        .observe(S(35), stopped("NeedsLogin"))
        .expect("30s elapsed");
    assert_eq!(tr.from, Some(TailnetState::Active));
    assert_eq!(tr.to, stopped("NeedsLogin"));
}

#[test]
fn grace_restarts_after_a_recovery() {
    let mut m = LivenessMachine::new(LivenessConfig::default());
    m.observe(S(0), TailnetState::Active);
    for t in [5, 10, 15, 20, 25] {
        assert!(m.observe(S(t), stopped("Stopped")).is_none());
    }
    assert!(m.observe(S(30), TailnetState::Active).is_none()); // came back
                                                               // New outage: clock starts again at t=35.
    for t in [35, 40, 45, 50, 55, 60, 64] {
        assert!(m.observe(S(t), stopped("Stopped")).is_none(), "t={t}");
    }
    assert!(m.observe(S(65), stopped("Stopped")).is_some());
}

#[test]
fn recovery_to_active_needs_only_two_polls() {
    let mut m = LivenessMachine::new(LivenessConfig::default());
    m.observe(S(0), stopped("Stopped"));
    assert!(m.observe(S(5), TailnetState::Active).is_none());
    let tr = m.observe(S(10), TailnetState::Active).unwrap();
    assert_eq!(tr.to, TailnetState::Active);
}

#[test]
fn steady_state_produces_no_further_transitions() {
    let mut m = LivenessMachine::new(LivenessConfig::default());
    let mut fired = 0;
    for i in 0..100 {
        if m.observe(S(i * 5), stopped("Stopped")).is_some() {
            fired += 1;
        }
    }
    assert_eq!(fired, 1, "only the initial adoption");
}

#[test]
fn uninstalled_switches_to_five_minute_cadence_and_back() {
    let mut m = LivenessMachine::new(LivenessConfig::default());
    m.observe(S(0), TailnetState::Active);
    let mut t = 0;
    let mut fired: Option<Transition> = None;
    while fired.is_none() {
        t += 5;
        fired = m.observe(S(t), TailnetState::Uninstalled);
    }
    assert_eq!(fired.unwrap().to, TailnetState::Uninstalled);
    assert_eq!(m.next_delay(), S(300));
    // Still uninstalled: stays slow.
    assert!(m.observe(S(t + 300), TailnetState::Uninstalled).is_none());
    assert_eq!(m.next_delay(), S(300));
    // They reinstalled it: first sighting drops to fast cadence to confirm.
    assert!(m.observe(S(t + 600), TailnetState::Active).is_none());
    assert_eq!(m.next_delay(), S(5));
    let tr = m.observe(S(t + 605), TailnetState::Active).unwrap();
    assert_eq!(tr.from, Some(TailnetState::Uninstalled));
    assert_eq!(m.next_delay(), S(5));
}

#[test]
fn stopped_to_uninstalled_is_hysteresis_only() {
    let mut m = LivenessMachine::new(LivenessConfig::default());
    m.observe(S(0), stopped("Stopped"));
    assert!(m.observe(S(5), TailnetState::Uninstalled).is_none());
    assert!(m.observe(S(10), TailnetState::Uninstalled).is_some());
}

#[test]
fn an_outage_whose_reason_keeps_changing_still_leaves_active() {
    // tailscaled crash-looping: polls alternate between "daemon unreachable"
    // and a backend state. That is one outage (state `stopped`), not a
    // series of different states, so the 2-poll / 30 s rule still applies.
    let mut m = LivenessMachine::new(LivenessConfig::default());
    m.observe(S(0), TailnetState::Active);
    let reasons = ["daemon unreachable: connection refused", "NoState"];
    let mut fired = None;
    for i in 1..=20u64 {
        let r = reasons[(i % 2) as usize];
        if let Some(t) = m.observe(S(i * 5), stopped(r)) {
            fired = Some((i * 5, t));
            break;
        }
    }
    let (at, t) = fired.expect("a 100 s outage must leave active");
    assert_eq!(
        at, 35,
        "first bad poll at t=5, so the 30 s grace ends at t=35"
    );
    assert_eq!(t.from, Some(TailnetState::Active));
    assert_eq!(t.to.label(), "stopped");
}

#[test]
fn a_reason_change_while_stopped_is_not_a_transition() {
    let mut m = LivenessMachine::new(LivenessConfig::default());
    m.observe(S(0), stopped("Stopped"));
    for t in [5, 10, 15, 20] {
        assert!(m.observe(S(t), stopped("NeedsLogin")).is_none(), "t={t}");
    }
    // The reason is still tracked, just without a transition.
    assert_eq!(m.current(), Some(&stopped("NeedsLogin")));
}

// ------------------------------------------------------------- poll loop --

/// Virtual clock: `sleep` advances time immediately and records the request.
struct VirtualClock {
    now_ms: AtomicU64,
    sleeps: Mutex<Vec<Duration>>,
}

impl VirtualClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            now_ms: AtomicU64::new(0),
            sleeps: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl Clock for VirtualClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.now_ms.load(Ordering::SeqCst))
    }
    async fn sleep(&self, d: Duration) {
        self.sleeps.lock().unwrap().push(d);
        self.now_ms
            .fetch_add(d.as_millis() as u64, Ordering::SeqCst);
        // Let the test task observe the watch channel between polls.
        tokio::task::yield_now().await;
    }
}

/// Source whose answer is a function of virtual time.
struct Scripted {
    clock: Arc<VirtualClock>,
    script: Vec<(Duration, TailnetState)>,
}

#[async_trait::async_trait]
impl StatusSource for Scripted {
    async fn observe(&self) -> Observation {
        let now = self.clock.now();
        let state = self
            .script
            .iter()
            .rev()
            .find(|(from, _)| *from <= now)
            .map(|(_, s)| s.clone())
            .unwrap();
        Observation {
            state,
            status: None,
        }
    }
}

async fn next_state(
    rx: &mut tokio::sync::watch::Receiver<entangle_mesh_tailscale::LivenessSnapshot>,
) -> entangle_mesh_tailscale::LivenessSnapshot {
    tokio::time::timeout(Duration::from_secs(5), rx.changed())
        .await
        .expect("a transition should arrive")
        .unwrap();
    rx.borrow_and_update().clone()
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Buf {
        self.clone()
    }
}

#[tokio::test]
async fn poll_loop_publishes_each_transition_once_and_logs_once() {
    let logs = Buf::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );

    let clock = VirtualClock::new();
    let script = vec![
        (S(0), TailnetState::Active),
        // blip: one poll only, must be invisible
        (S(20), stopped("Stopped")),
        (S(25), TailnetState::Active),
        // real outage from t=100
        (S(100), stopped("NeedsLogin")),
        // recovery at t=400
        (S(400), TailnetState::Active),
    ];
    let source = Arc::new(Scripted {
        clock: clock.clone(),
        script,
    });
    let handle = spawn_liveness(source, clock.clone(), LivenessConfig::default());
    let mut rx = handle.state();

    let s1 = next_state(&mut rx).await;
    assert_eq!(s1.state, Some(TailnetState::Active));
    assert_eq!(s1.transitions, 1);

    let s2 = next_state(&mut rx).await;
    assert_eq!(s2.state, Some(stopped("NeedsLogin")));
    assert_eq!(s2.transitions, 2, "the blip at t=20 must not have fired");
    assert!(!s2.is_active());
    // Confirmed no earlier than 30 s after the outage began.
    assert!(clock.now() >= S(130), "now={:?}", clock.now());

    let s3 = next_state(&mut rx).await;
    assert_eq!(s3.state, Some(TailnetState::Active));
    assert_eq!(s3.transitions, 3);

    handle.shutdown();
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let events = text
        .lines()
        .filter(|l| l.contains("mesh.tailscale state transition"))
        .count();
    assert_eq!(events, 3, "one event per transition, not per poll:\n{text}");
    assert!(text.contains("NeedsLogin"));
}

#[tokio::test]
async fn poll_loop_publishes_a_new_stop_reason_without_a_transition() {
    let logs = Buf::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );
    let clock = VirtualClock::new();
    let source = Arc::new(Scripted {
        clock: clock.clone(),
        script: vec![
            (S(0), stopped("Stopped")),
            // `tailscale down` then `tailscale logout`.
            (S(100), stopped("NeedsLogin")),
        ],
    });
    let handle = spawn_liveness(source, clock.clone(), LivenessConfig::default());
    let mut rx = handle.state();
    let first = next_state(&mut rx).await;
    assert_eq!(first.state, Some(stopped("Stopped")));
    let second = next_state(&mut rx).await;
    assert_eq!(second.state, Some(stopped("NeedsLogin")));
    assert_eq!(second.transitions, 1, "a reason change is not a transition");
    assert_eq!(second.since, first.since);
    handle.shutdown();
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let warnings = text
        .lines()
        .filter(|l| l.contains("mesh.tailscale state transition"))
        .count();
    assert_eq!(warnings, 1, "{text}");
}

#[tokio::test]
async fn poll_loop_uses_five_minute_cadence_when_uninstalled() {
    let clock = VirtualClock::new();
    let source = Arc::new(Scripted {
        clock: clock.clone(),
        script: vec![(S(0), TailnetState::Uninstalled)],
    });
    let handle = spawn_liveness(source, clock.clone(), LivenessConfig::default());
    let mut rx = handle.state();
    let s = next_state(&mut rx).await;
    assert_eq!(s.state, Some(TailnetState::Uninstalled));
    // Let the loop run a few more iterations.
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    handle.shutdown();
    let sleeps = clock.sleeps.lock().unwrap().clone();
    assert!(sleeps.len() >= 3);
    assert!(
        sleeps.iter().all(|d| *d == S(300)),
        "first adoption is immediate, so every sleep is the slow cadence: {sleeps:?}"
    );
}

// ----------------------------------------------------------------- fake CLI --

#[cfg(unix)]
mod fake_cli {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// Serialises "write executable then spawn it" across tests: a concurrent
    /// fork while a script is still open for writing yields ETXTBSY.
    static SPAWN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    const RUNNING: &str = r#"{"BackendState":"Running","Self":{"Online":true,"DNSName":"me.t.ts.net.","TailscaleIPs":["100.64.0.1"]},"Peer":{}}"#;
    const LOGIN: &str = r#"{"BackendState":"NeedsLogin","Self":null,"Peer":null}"#;

    struct Fake {
        dir: tempfile::TempDir,
    }

    impl Fake {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let script = dir.path().join("tailscale");
            let mut f = std::fs::File::create(&script).unwrap();
            f.write_all(
                br#"#!/bin/sh
d=$(dirname "$0")
case "$1" in
  version) [ -f "$d/no-version" ] && exit 3; echo 1.76.0 ;;
  status)  [ -f "$d/down" ] && { echo "failed to connect to local tailscaled" >&2; exit 1; }
           cat "$d/status.json" ;;
esac
"#,
            )
            .unwrap();
            f.sync_all().unwrap();
            drop(f);
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            let me = Self { dir };
            me.set_status(RUNNING);
            me
        }
        fn cli(&self) -> String {
            self.dir.path().join("tailscale").display().to_string()
        }
        fn set_status(&self, json: &str) {
            std::fs::write(self.dir.path().join("status.json"), json).unwrap();
        }
        fn flag(&self, name: &str, on: bool) {
            let p = self.dir.path().join(name);
            if on {
                std::fs::write(p, "").unwrap();
            } else {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    #[tokio::test]
    async fn cli_source_classifies_running_needslogin_down_and_missing() {
        let _g = SPAWN.lock().await;
        let fake = Fake::new();
        let src = CliStatusSource::new(fake.cli());

        let o = src.observe().await;
        assert_eq!(o.state, TailnetState::Active);
        assert_eq!(o.status.unwrap().self_node.unwrap().dns_name, "me.t.ts.net");

        fake.set_status(LOGIN);
        assert_eq!(src.observe().await.state, stopped("NeedsLogin"));

        // Daemon unreachable: status fails, but `version` works -> stopped.
        fake.flag("down", true);
        let o = src.observe().await;
        assert!(
            o.state.reason().unwrap().contains("daemon unreachable"),
            "{:?}",
            o.state
        );

        // Both failing: binary exists but is unhealthy -> still stopped.
        fake.flag("no-version", true);
        assert!(src
            .observe()
            .await
            .state
            .reason()
            .unwrap()
            .contains("unhealthy"));

        // Binary gone entirely (and no tailscaled socket) -> uninstalled.
        let gone = CliStatusSource::new("/nonexistent/dir/tailscale")
            .with_daemon_socket(fake.dir.path().join("no-such.sock"));
        assert_eq!(gone.observe().await.state, TailnetState::Uninstalled);
    }

    #[tokio::test]
    async fn poll_loop_follows_a_fake_cli_whose_output_changes_between_polls() {
        let _g = SPAWN.lock().await;
        let fake = Arc::new(Fake::new());

        // Virtual clock that flips the fake CLI's state as time passes.
        struct SwitchingClock {
            inner: Arc<VirtualClock>,
            fake: Arc<Fake>,
        }
        #[async_trait::async_trait]
        impl Clock for SwitchingClock {
            fn now(&self) -> Duration {
                self.inner.now()
            }
            async fn sleep(&self, d: Duration) {
                self.inner.sleep(d).await;
                let t = self.inner.now();
                if t >= S(60) {
                    self.fake.set_status(LOGIN);
                }
                if t >= S(200) {
                    self.fake.set_status(RUNNING);
                }
            }
        }

        let vc = VirtualClock::new();
        let clock = Arc::new(SwitchingClock {
            inner: vc,
            fake: fake.clone(),
        });
        let handle = spawn_liveness(
            Arc::new(CliStatusSource::new(fake.cli())),
            clock,
            LivenessConfig::default(),
        );
        let mut rx = handle.state();
        assert_eq!(next_state(&mut rx).await.state, Some(TailnetState::Active));
        assert_eq!(next_state(&mut rx).await.state, Some(stopped("NeedsLogin")));
        let last = next_state(&mut rx).await;
        assert_eq!(last.state, Some(TailnetState::Active));
        assert_eq!(last.transitions, 3);
        handle.shutdown();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_hanging_cli_is_timed_out_and_killed() {
        let _g = SPAWN.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("tailscale");
        let pidfile = dir.path().join("pid");
        let body = format!(
            "#!/bin/sh\ncase \"$1\" in\n  status) echo $$ > {}; exec sleep 30 ;;\n  version) echo 1.76.0 ;;\nesac\n",
            pidfile.display()
        );
        {
            // Written and closed before the first spawn (ETXTBSY otherwise).
            let mut f = std::fs::File::create(&script).unwrap();
            f.write_all(body.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let src = CliStatusSource::new(script.display().to_string())
            .with_timeout(Duration::from_millis(300));
        let started = std::time::Instant::now();
        let o = src.observe().await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        let reason = o.state.reason().expect("stopped").to_owned();
        assert!(reason.contains("timed out"), "{reason}");
        // kill_on_drop: the hung `status` child does not outlive the poll.
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        let proc_dir = std::path::PathBuf::from(format!("/proc/{}", pid.trim()));
        let mut gone = false;
        for _ in 0..40 {
            let zombie_or_gone = std::fs::read_to_string(proc_dir.join("stat"))
                .map(|s| s.split_whitespace().nth(2) == Some("Z"))
                .unwrap_or(true);
            if zombie_or_gone {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(gone, "the timed-out CLI process {pid} is still running");
    }
}

// ------------------------------------------------------- uninstalled rule --

#[tokio::test]
async fn a_missing_cli_with_a_daemon_socket_is_stopped_not_uninstalled() {
    // Spec §6.1.1: uninstalled = binary not on $PATH AND no socket at the
    // platform default path. tailscaled running from a tarball whose CLI is
    // not on the service's PATH is therefore *not* uninstalled.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("tailscaled.sock");
    std::fs::write(&sock, b"").unwrap();
    let src = CliStatusSource::new("/nonexistent/dir/tailscale").with_daemon_socket(&sock);
    let o = src.observe().await;
    assert_eq!(o.state.label(), "stopped", "{:?}", o.state);
    let reason = o.state.reason().unwrap();
    assert!(reason.contains("not found"), "{reason}");
    assert!(reason.contains("tailscaled.sock"), "{reason}");

    // Neither binary nor socket: uninstalled.
    let gone = CliStatusSource::new("/nonexistent/dir/tailscale")
        .with_daemon_socket(dir.path().join("absent.sock"));
    assert_eq!(gone.observe().await.state, TailnetState::Uninstalled);
}
