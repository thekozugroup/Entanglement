//! Router unit tests over scripted links: ordering, availability, fallback
//! and the never-retry rule. The same propositions are checked over real
//! loopback transports in `tests/multi_transport.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};

use entangle_mesh_iroh::IrohPeer;
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
    calls: AtomicUsize,
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
            calls: AtomicUsize::new(0),
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
    async fn request(&self, _target: &DialTarget, _payload: &[u8]) -> Result<Vec<u8>, LinkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.script)()
    }
    async fn open_stream(&self, _target: &DialTarget) -> Result<StreamIo, LinkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(LinkError::Connect("scripted links carry no streams".into()))
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
async fn an_unknown_peer_has_no_route_and_says_which_books_were_checked() {
    let r = router(&[Scripted::answering(TransportKind::Iroh, peer(1))]);
    let err = r.request(peer(2), b"", None).await.unwrap_err();
    let text = err.to_string();
    assert!(text.starts_with("ENTANGLE-E0430"), "{text}");
    assert!(text.contains("address book"), "{text}");
    assert!(text.contains("tailscale: not running"), "{text}");
}
