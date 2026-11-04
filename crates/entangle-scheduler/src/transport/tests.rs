//! Router unit tests over scripted links: ordering, availability, fallback
//! and the never-retry rule. The same propositions are checked over real
//! loopback transports in `tests/multi_transport.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use entangle_mesh_iroh::{
    duplex_pair, FramedStream, IrohPeer, DEFAULT_DUPLEX_BUFFER, MAX_FRAME_BYTES,
};
use entangle_mesh_tailscale::TailscalePeer;

use super::*;

fn peer_key(b: u8) -> [u8; 32] {
    [b; 32]
}

fn peer(b: u8) -> PeerId {
    PeerId::from_public_key_bytes(&peer_key(b))
}

type Script = Box<dyn Fn() -> Result<Vec<u8>, LinkError> + Send + Sync>;

/// A link that knows exactly one peer and answers by script.
struct Scripted {
    kind: TransportKind,
    down: Option<String>,
    knows: PeerId,
    script: Script,
    /// Never finishes connecting (a blackholed address): requests and
    /// stream opens neither answer nor fail.
    silent: bool,
    /// Connects at once, then takes this long to answer (a running task).
    runs_for: Option<Duration>,
    /// Takes this long to connect (a relayed dial), then answers.
    connects_after: Option<Duration>,
    calls: AtomicUsize,
    /// The far ends of the streams it opened, kept open.
    far_ends: Mutex<Vec<FramedStream>>,
}

impl std::fmt::Debug for Scripted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Scripted({})", self.kind)
    }
}

impl Scripted {
    fn new(
        kind: TransportKind,
        knows: PeerId,
        script: impl Fn() -> Result<Vec<u8>, LinkError> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            kind,
            down: None,
            knows,
            script: Box::new(script),
            silent: false,
            runs_for: None,
            connects_after: None,
            calls: AtomicUsize::new(0),
            far_ends: Mutex::new(Vec::new()),
        })
    }

    fn connecting_after(kind: TransportKind, knows: PeerId, time: Duration) -> Arc<Self> {
        Arc::new(Self {
            connects_after: Some(time),
            ..Arc::into_inner(Self::answering(kind, knows)).unwrap()
        })
    }

    fn running_for(kind: TransportKind, knows: PeerId, time: Duration) -> Arc<Self> {
        Arc::new(Self {
            runs_for: Some(time),
            ..Arc::into_inner(Self::answering(kind, knows)).unwrap()
        })
    }

    fn silent(kind: TransportKind, knows: PeerId) -> Arc<Self> {
        Arc::new(Self {
            silent: true,
            ..Arc::into_inner(Self::answering(kind, knows)).unwrap()
        })
    }

    fn answering(kind: TransportKind, knows: PeerId) -> Arc<Self> {
        Self::new(kind, knows, move || Ok(kind.as_str().as_bytes().to_vec()))
    }

    fn down(kind: TransportKind, knows: PeerId, why: &str) -> Arc<Self> {
        Arc::new(Self {
            down: Some(why.into()),
            ..Arc::into_inner(Self::answering(kind, knows)).unwrap()
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Link for Scripted {
    fn kind(&self) -> TransportKind {
        self.kind
    }
    fn availability(&self) -> Availability {
        self.down
            .clone()
            .map_or(Availability::Ready, Availability::Down)
    }
    fn target(&self, peer: &PeerId) -> Option<DialTarget> {
        if *peer != self.knows {
            return None;
        }
        let key = (0..=255u8)
            .map(peer_key)
            .find(|k| PeerId::from_public_key_bytes(k) == *peer)?;
        let addr = "127.0.0.1:9".parse().ok()?;
        Some(match self.kind {
            TransportKind::Tailscale => DialTarget::Tailscale(TailscalePeer::new(key, addr)),
            _ => DialTarget::Iroh(IrohPeer::new(key, addr)),
        })
    }
    async fn request(
        &self,
        _target: &DialTarget,
        _payload: &[u8],
        connecting: &Connecting,
    ) -> Result<Vec<u8>, LinkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.silent {
            std::future::pending::<()>().await;
        }
        if let Some(time) = self.connects_after {
            tokio::time::sleep(time).await;
            connecting.connected();
        }
        if let Some(time) = self.runs_for {
            connecting.connected();
            tokio::time::sleep(time).await;
        }
        (self.script)()
    }
    /// Opens an in-memory stream to the target's key, or fails as the
    /// script fails.
    async fn open_stream(&self, target: &DialTarget) -> Result<StreamIo, LinkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.silent {
            std::future::pending::<()>().await;
        }
        (self.script)()?;
        let key = match target {
            DialTarget::Iroh(p) => p.public_key,
            DialTarget::Tailscale(p) => p.public_key,
        };
        let (ours, theirs) = duplex_pair(peer_key(0), key, MAX_FRAME_BYTES, DEFAULT_DUPLEX_BUFFER);
        self.far_ends.lock().push(theirs);
        Ok(StreamIo::from(ours).with_transport(self.kind))
    }
}

fn router(links: &[Arc<Scripted>]) -> TransportRouter {
    links.iter().fold(TransportRouter::new(peer(0)), |r, l| {
        r.with_link(Arc::clone(l) as Arc<dyn Link>)
    })
}

#[test]
fn the_default_order_is_local_tailscale_iroh_and_preferred_moves_to_the_front() {
    let p = peer(1);
    assert_eq!(
        RoutePolicy::new().order_for(&p),
        [
            TransportKind::Local,
            TransportKind::Tailscale,
            TransportKind::Iroh
        ]
    );
    assert_eq!(
        RoutePolicy::new()
            .with_preferred(Some(TransportKind::Iroh))
            .order_for(&p),
        [
            TransportKind::Iroh,
            TransportKind::Local,
            TransportKind::Tailscale
        ]
    );
    let o = RoutePolicy::new()
        .with_preferred(Some(TransportKind::Iroh))
        .with_override(
            p,
            vec![
                TransportKind::Tailscale,
                TransportKind::Tailscale,
                TransportKind::Local,
            ],
        );
    assert_eq!(
        o.order_for(&p),
        [TransportKind::Tailscale, TransportKind::Local],
        "an override is exact, deduplicated, and beats preferred"
    );
    assert_eq!(o.order_for(&peer(2))[0], TransportKind::Iroh);
    assert!(!o.clone().with_override(p, vec![]).has_override(&p));
}

#[test]
fn kinds_parse_and_print_their_config_spelling() {
    for k in TransportKind::NEGOTIATION_ORDER {
        assert_eq!(k.as_str().parse::<TransportKind>().unwrap(), k);
        assert!(TRANSPORT_LABELS.contains(&k.as_str()));
    }
    let err = "wifi".parse::<TransportKind>().unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0434");
    assert_eq!(TransportKind::label(None), "none");
}

#[tokio::test]
async fn a_peer_known_on_several_transports_uses_the_negotiation_order() {
    let p = peer(1);
    let iroh = Scripted::answering(TransportKind::Iroh, p);
    let ts = Scripted::answering(TransportKind::Tailscale, p);
    // Added in the "wrong" order: the router orders by policy, not by
    // insertion.
    let r = router(&[iroh.clone(), ts.clone()]);
    let (answer, kind) = r.request(p, b"x", None).await.unwrap();
    assert_eq!(
        (answer.as_slice(), kind),
        (&b"tailscale"[..], TransportKind::Tailscale)
    );
    assert_eq!((ts.calls(), iroh.calls()), (1, 0));
    let rec = r.last_route(&p).expect("the choice is recorded");
    assert_eq!(rec.transport, TransportKind::Tailscale);
    let plan = r.plan(&p);
    assert_eq!(
        plan.candidates
            .iter()
            .map(|c| c.transport)
            .collect::<Vec<_>>(),
        [TransportKind::Tailscale, TransportKind::Iroh]
    );
    assert!(plan
        .skipped
        .iter()
        .any(|s| s.transport == TransportKind::Local && s.reason.contains("not running")));
}

#[tokio::test]
async fn a_down_transport_is_skipped_with_its_reason() {
    let p = peer(1);
    let iroh = Scripted::answering(TransportKind::Iroh, p);
    let ts = Scripted::down(TransportKind::Tailscale, p, "tailnet stopped (NeedsLogin)");
    let r = router(&[ts.clone(), iroh.clone()]);
    let (_, kind) = r.request(p, b"x", None).await.unwrap();
    assert_eq!(kind, TransportKind::Iroh);
    assert_eq!(ts.calls(), 0, "a down transport is never dialled");
    assert!(r
        .plan(&p)
        .skipped
        .iter()
        .any(|s| s.transport == TransportKind::Tailscale && s.reason.contains("NeedsLogin")));

    // Reachable only over the down transport: no route, nothing dialled.
    let only = router(&[Scripted::down(
        TransportKind::Tailscale,
        p,
        "tailnet stopped (x)",
    )]);
    let err = only.request(p, b"x", None).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0430", "{err}");
    assert!(err.to_string().contains("tailnet stopped"), "{err}");
    assert_eq!(err.transport(), None);
}

#[tokio::test]
async fn a_connect_failure_falls_back_to_the_next_candidate() {
    let p = peer(1);
    let ts = Scripted::new(TransportKind::Tailscale, p, || {
        Err(LinkError::Connect("connection refused".into()))
    });
    let iroh = Scripted::answering(TransportKind::Iroh, p);
    let r = router(&[ts.clone(), iroh.clone()]);
    let (answer, kind) = r.request(p, b"x", None).await.unwrap();
    assert_eq!(
        (answer.as_slice(), kind),
        (&b"iroh"[..], TransportKind::Iroh)
    );
    assert_eq!((ts.calls(), iroh.calls()), (1, 1));

    // Every candidate fails to connect: one error naming each attempt.
    let bad_iroh = Scripted::new(TransportKind::Iroh, p, || {
        Err(LinkError::Connect("timed out".into()))
    });
    let r = router(&[ts.clone(), bad_iroh]);
    let err = r.request(p, b"x", None).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0431");
    let text = err.to_string();
    assert!(
        text.contains("tailscale: connection refused") && text.contains("iroh: timed out"),
        "{text}"
    );
    assert_eq!(err.transport(), Some(TransportKind::Iroh));
}

/// A candidate that never finishes connecting (a stale or spoofed mDNS
/// sighting, a blackholed address) must not hold the request: it gets a
/// connect deadline of its own, and the next candidate is tried.
#[tokio::test]
async fn a_candidate_that_never_connects_does_not_hold_the_request() {
    let p = peer(1);
    let local = Scripted::silent(TransportKind::Local, p);
    let ts = Scripted::answering(TransportKind::Tailscale, p);
    let r = router(&[local.clone(), ts.clone()]);
    let (answer, kind) = tokio::time::timeout(Duration::from_secs(10), r.request(p, b"x", None))
        .await
        .expect("a silent first candidate held the request past its connect deadline")
        .unwrap();
    assert_eq!(
        (answer.as_slice(), kind),
        (&b"tailscale"[..], TransportKind::Tailscale)
    );
    assert_eq!((local.calls(), ts.calls()), (1, 1));

    // With a budget, the candidates with a fallback share what is left of
    // it: here half of 1 s, well inside the 5 s cap. (A fresh router: this
    // one now tries the silent candidate last.)
    let r = router(&[Scripted::silent(TransportKind::Local, p), ts.clone()]);
    let started = tokio::time::Instant::now();
    let (_, kind) = tokio::time::timeout(
        Duration::from_secs(1),
        r.request_tracked(
            p,
            b"x",
            None,
            &AttemptCell::default(),
            Some(Duration::from_secs(1)),
        ),
    )
    .await
    .expect("the fallback ran inside the budget")
    .unwrap();
    assert_eq!(kind, TransportKind::Tailscale);
    assert!(started.elapsed() >= Duration::from_millis(450));

    // The last candidate has no router deadline (its transport's own
    // timeouts bound it), so a peer known on one transport only is dialled
    // exactly as before.
    let only = router(&[Scripted::silent(TransportKind::Iroh, p)])
        .with_connect_timeout(Duration::from_millis(10));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), only.request(p, b"x", None))
            .await
            .is_err(),
        "the only candidate is not cut at the connect deadline"
    );

    // Streams: every candidate with a fallback gets the deadline too.
    let local = Scripted::silent(TransportKind::Local, p);
    let ts = Scripted::answering(TransportKind::Tailscale, p);
    let r = router(&[local.clone(), ts.clone()]).with_connect_timeout(Duration::from_millis(50));
    let mut task = StreamingTask::with_defaults(
        "0123456789abcdef0123456789abcdef/demo@1.0.0"
            .parse()
            .unwrap(),
        Vec::new(),
    );
    task.integrity = entangle_types::task::IntegrityPolicy::TrustedExecutor { allowlist: vec![p] };
    let handle = tokio::time::timeout(
        Duration::from_secs(5),
        r.open_stream(p, &task, StreamOptions::default()),
    )
    .await
    .expect("a silent first candidate held the stream open past its connect deadline")
    .unwrap();
    assert_eq!(handle.executor(), p);
    assert_eq!(
        r.last_route(&p).map(|rec| rec.transport),
        Some(TransportKind::Tailscale)
    );
    assert_eq!((local.calls(), ts.calls()), (1, 1));
}

/// A candidate that just failed to connect is not dialled first again on
/// the next request: it moves behind the others for a while, so a dead
/// route does not stall every request to that peer.
#[tokio::test]
async fn a_transport_that_just_failed_to_connect_is_tried_last_for_a_while() {
    let p = peer(1);
    let local = Scripted::new(TransportKind::Local, p, || {
        Err(LinkError::Connect("connection refused".into()))
    });
    let ts = Scripted::answering(TransportKind::Tailscale, p);
    let r = router(&[local.clone(), ts.clone()]);
    assert_eq!(
        r.request(p, b"x", None).await.unwrap().1,
        TransportKind::Tailscale
    );
    assert_eq!((local.calls(), ts.calls()), (1, 1));
    assert_eq!(
        r.request(p, b"x", None).await.unwrap().1,
        TransportKind::Tailscale
    );
    assert_eq!(
        (local.calls(), ts.calls()),
        (1, 2),
        "the candidate that just failed to connect is not dialled first again"
    );
    let order = |r: &TransportRouter| {
        r.plan(&p)
            .candidates
            .iter()
            .map(|c| c.transport)
            .collect::<Vec<_>>()
    };
    assert_eq!(order(&r), [TransportKind::Tailscale, TransportKind::Local]);

    // Demoted, not dropped: when the others fail it is still tried, and a
    // success over it restores its place. Local fails its first dial only;
    // tailscale answers its first request only.
    let first_fails = |kind: TransportKind, fail_first: bool| {
        let calls = AtomicUsize::new(0);
        Scripted::new(kind, p, move || {
            let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
            if first == fail_first {
                Err(LinkError::Connect("no route to host".into()))
            } else {
                Ok(kind.as_str().as_bytes().to_vec())
            }
        })
    };
    let local = first_fails(TransportKind::Local, true);
    let ts = first_fails(TransportKind::Tailscale, false);
    let r = router(&[local.clone(), ts.clone()]);
    assert_eq!(
        r.request(p, b"x", None).await.unwrap().1,
        TransportKind::Tailscale
    );
    assert_eq!(order(&r), [TransportKind::Tailscale, TransportKind::Local]);
    assert_eq!(
        r.request(p, b"x", None).await.unwrap().1,
        TransportKind::Local,
        "tailscale failed; the demoted local route is still tried"
    );
    assert_eq!((local.calls(), ts.calls()), (2, 2));
    assert_eq!(order(&r), [TransportKind::Local, TransportKind::Tailscale]);
    let ts = Scripted::answering(TransportKind::Tailscale, p);

    // The back-off runs out.
    let local = Scripted::new(TransportKind::Local, p, || {
        Err(LinkError::Connect("refused".into()))
    });
    let r = router(&[local.clone(), ts.clone()]).with_connect_backoff(Duration::from_millis(50));
    r.request(p, b"x", None).await.unwrap();
    assert_eq!(order(&r), [TransportKind::Tailscale, TransportKind::Local]);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(order(&r), [TransportKind::Local, TransportKind::Tailscale]);

    // A diagnostic attempt pinned to one transport (`only`) neither
    // demotes nor is demoted.
    let r = router(&[local.clone(), ts.clone()]);
    let before = local.calls();
    assert!(r
        .request(p, b"x", Some(TransportKind::Local))
        .await
        .is_err());
    assert_eq!(local.calls(), before + 1);
    assert_eq!(order(&r), [TransportKind::Local, TransportKind::Tailscale]);
}

/// The connect deadline only makes room for the next candidate. When every
/// other candidate fails, one it cut short — slow to connect, not refused,
/// e.g. a relayed iroh dial — gets the rest of the budget, as the last
/// candidate would have; it is not given up on.
#[tokio::test]
async fn a_slow_candidate_cut_at_its_deadline_is_tried_again_when_the_rest_fail() {
    let p = peer(1);
    let slow = Scripted::connecting_after(TransportKind::Iroh, p, Duration::from_millis(300));
    let refused = Scripted::new(TransportKind::Local, p, || {
        Err(LinkError::Connect("connection refused".into()))
    });
    let r = router(&[slow.clone(), refused.clone()])
        .with_policy(RoutePolicy::new().with_preferred(Some(TransportKind::Iroh)))
        .with_connect_timeout(Duration::from_millis(100));
    let (answer, kind) = r.request(p, b"x", None).await.unwrap();
    assert_eq!(
        (answer.as_slice(), kind),
        (&b"iroh"[..], TransportKind::Iroh)
    );
    assert_eq!((slow.calls(), refused.calls()), (2, 1));

    // But a candidate the deadline cut short is not retried while another
    // first-time candidate is still to be tried, nor when one answered.
    let slow = Scripted::connecting_after(TransportKind::Iroh, p, Duration::from_millis(300));
    let ts = Scripted::answering(TransportKind::Tailscale, p);
    let r = router(&[slow.clone(), ts.clone()])
        .with_policy(RoutePolicy::new().with_preferred(Some(TransportKind::Iroh)))
        .with_connect_timeout(Duration::from_millis(100));
    assert_eq!(
        r.request(p, b"x", None).await.unwrap().1,
        TransportKind::Tailscale
    );
    assert_eq!((slow.calls(), ts.calls()), (1, 1));
}

/// The connect deadline bounds connection setup only: an attempt whose link
/// has connected (and may have sent the request) runs to its end, however
/// long the task takes, and is never re-sent elsewhere.
#[tokio::test]
async fn a_connected_attempt_is_not_cut_at_the_connect_deadline() {
    let p = peer(1);
    let local = Scripted::running_for(TransportKind::Local, p, Duration::from_millis(300));
    let iroh = Scripted::answering(TransportKind::Iroh, p);
    let r = router(&[local.clone(), iroh.clone()]).with_connect_timeout(Duration::from_millis(20));
    let (answer, kind) = r.request(p, b"x", None).await.unwrap();
    assert_eq!(
        (answer.as_slice(), kind),
        (&b"local"[..], TransportKind::Local)
    );
    assert_eq!((local.calls(), iroh.calls()), (1, 0));
}

#[tokio::test]
async fn a_failure_after_the_request_was_sent_is_never_retried_elsewhere() {
    let p = peer(1);
    let ts = Scripted::new(TransportKind::Tailscale, p, || {
        Err(LinkError::Transport("reset mid-response".into()))
    });
    let iroh = Scripted::answering(TransportKind::Iroh, p);
    let r = router(&[ts.clone(), iroh.clone()]);
    let err = r.request(p, b"x", None).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0432", "{err}");
    assert_eq!((ts.calls(), iroh.calls()), (1, 0));
    assert_eq!(err.transport(), Some(TransportKind::Tailscale));

    let big = Scripted::new(TransportKind::Tailscale, p, || {
        Err(LinkError::FrameTooLarge {
            declared: 9,
            max: 1,
        })
    });
    let r = router(&[big, iroh.clone()]);
    let err = r.request(p, b"x", None).await.unwrap_err();
    assert!(matches!(
        err,
        RouteError::FrameTooLarge {
            declared: 9,
            max: 1,
            ..
        }
    ));
    assert_eq!(iroh.calls(), 0);
}

fn stream_task(p: PeerId) -> StreamingTask {
    let mut task = StreamingTask::with_defaults(
        "0123456789abcdef0123456789abcdef/demo@1.0.0"
            .parse()
            .unwrap(),
        Vec::new(),
    );
    task.integrity = entangle_types::task::IntegrityPolicy::TrustedExecutor { allowlist: vec![p] };
    task
}

/// Stream opens follow the one-shot rules: a connect failure falls back
/// (and is counted under the transport that carried the stream), while a
/// failure once the connection was up is never retried elsewhere.
#[tokio::test]
async fn a_stream_open_falls_back_on_connect_failure_but_is_never_retried_after_it_started() {
    let p = peer(1);
    let registry = entangle_observability::Registry::new();
    let ts = Scripted::new(TransportKind::Tailscale, p, || {
        Err(LinkError::Connect("refused".into()))
    });
    let iroh = Scripted::answering(TransportKind::Iroh, p);
    let r = router(&[ts.clone(), iroh.clone()]).with_metrics(registry.clone());
    let handle = r
        .open_stream(p, &stream_task(p), StreamOptions::default())
        .await
        .expect("iroh carries the stream");
    assert_eq!(handle.executor(), p);
    assert_eq!((ts.calls(), iroh.calls()), (1, 1));
    assert_eq!(
        r.last_route(&p).map(|rec| rec.transport),
        Some(TransportKind::Iroh)
    );
    let opens = |outcome: &str, transport: &str| {
        registry
            .value(
                entangle_observability::catalog::names::REMOTE_STREAM_OPENS,
                &[("outcome", outcome), ("transport", transport)],
            )
            .unwrap_or(0.0)
    };
    assert_eq!(opens("ok", "iroh"), 1.0);
    assert_eq!(opens("ok", "tailscale"), 0.0);

    // The connection was up when it failed: the Open frame may have been
    // delivered, so the second transport is never offered the stream.
    let ts = Scripted::new(TransportKind::Tailscale, p, || {
        Err(LinkError::Transport("reset after Open".into()))
    });
    let iroh = Scripted::answering(TransportKind::Iroh, p);
    let r = router(&[ts.clone(), iroh.clone()]);
    let err = r
        .open_stream(p, &stream_task(p), StreamOptions::default())
        .await
        .map(|_| ())
        .expect_err("a transport failure after connecting is an error");
    assert!(err.to_string().contains("ENTANGLE-E0432"), "{err}");
    assert_eq!((ts.calls(), iroh.calls()), (1, 0));
}

/// A stream cut before the executor's signed End is an interruption, never
/// a clean completion.
#[tokio::test]
async fn a_stream_cut_before_its_end_is_interrupted_not_complete() {
    let p = peer(1);
    let ts = Scripted::answering(TransportKind::Tailscale, p);
    let r = router(std::slice::from_ref(&ts));
    let mut handle = r
        .open_stream(p, &stream_task(p), StreamOptions::default())
        .await
        .unwrap();
    // The far end goes away without sending End.
    ts.far_ends.lock().clear();
    let _ = handle.finish_input().await;
    let result = tokio::time::timeout(Duration::from_secs(5), handle.collect())
        .await
        .expect("a cut stream ends");
    assert!(
        matches!(result.outcome, crate::stream::StreamOutcome::Interrupted(_)),
        "{:?}",
        result.outcome
    );
}

#[tokio::test]
async fn preferred_and_overrides_pick_the_first_candidate() {
    let p = peer(1);
    let local = Scripted::answering(TransportKind::Local, p);
    let ts = Scripted::answering(TransportKind::Tailscale, p);
    let iroh = Scripted::answering(TransportKind::Iroh, p);
    let links = [local.clone(), ts.clone(), iroh.clone()];

    let r = router(&links);
    assert_eq!(
        r.request(p, b"", None).await.unwrap().1,
        TransportKind::Local
    );

    let r =
        router(&links).with_policy(RoutePolicy::new().with_preferred(Some(TransportKind::Iroh)));
    assert_eq!(
        r.request(p, b"", None).await.unwrap().1,
        TransportKind::Iroh
    );

    // A one-transport override forces it, even over `preferred`, and the
    // others are not fallbacks for that peer.
    let failing_ts = Scripted::new(TransportKind::Tailscale, p, || {
        Err(LinkError::Connect("refused".into()))
    });
    let r = router(&[local.clone(), failing_ts, iroh.clone()]).with_policy(
        RoutePolicy::new()
            .with_preferred(Some(TransportKind::Iroh))
            .with_override(p, vec![TransportKind::Tailscale]),
    );
    let before = (local.calls(), iroh.calls());
    let err = r.request(p, b"", None).await.unwrap_err();
    assert_eq!(err.code(), "ENTANGLE-E0431");
    assert_eq!((local.calls(), iroh.calls()), before);
    assert!(r
        .plan(&p)
        .skipped
        .iter()
        .any(|s| s.transport == TransportKind::Iroh && s.reason.contains("overrides")));

    // `only` pins one transport (diagnostics, traceparent resend).
    let r = router(&links);
    assert_eq!(
        r.request(p, b"", Some(TransportKind::Iroh))
            .await
            .unwrap()
            .1,
        TransportKind::Iroh
    );
}

#[tokio::test]
async fn a_restricted_diagnostic_request_leaves_the_chosen_transport_alone() {
    let p = peer(1);
    let iroh = Scripted::answering(TransportKind::Iroh, p);
    let ts = Scripted::answering(TransportKind::Tailscale, p);
    let r = router(&[iroh.clone(), ts.clone()]);
    r.request(p, b"x", None).await.unwrap();
    let before = r.last_route(&p).expect("chosen");
    assert_eq!(before.transport, TransportKind::Tailscale);

    // `diag mesh --probe` pins the iroh path: it answers, but dispatch did
    // not choose it.
    let (_, kind) = r
        .request(p, b"probe", Some(TransportKind::Iroh))
        .await
        .unwrap();
    assert_eq!(kind, TransportKind::Iroh);
    let after = r.last_route(&p).expect("still chosen");
    assert_eq!(after.transport, TransportKind::Tailscale);
    assert_eq!(after.at, before.at, "the record was not rewritten");
}

#[tokio::test]
async fn an_unknown_peer_has_no_route_and_says_which_books_were_checked() {
    let r = router(&[Scripted::answering(TransportKind::Iroh, peer(1))]);
    let err = r.request(peer(2), b"", None).await.unwrap_err();
    let text = err.to_string();
    assert!(text.starts_with("ENTANGLE-E0430"), "{text}");
    assert!(text.contains("address book"), "{text}");
    assert!(text.contains("tailscale: not running"), "{text}");
}
