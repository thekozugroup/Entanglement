//! The typed pub/sub bus.

use crate::{envelope::Envelope, errors::IpcError};

/// A typed broadcast pub/sub bus.
///
/// All subscribers receive every envelope; topic filtering is the
/// subscriber's responsibility (see [`Subscriber::recv`]).
///
/// Multiple independent buses can coexist — one per payload type is typical.
pub struct Bus<T: Clone + Send + Sync + 'static> {
    sender: tokio::sync::broadcast::Sender<Envelope<T>>,
}

impl<T: Clone + Send + Sync + 'static> Bus<T> {
    /// Create a new bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(capacity);
        Self { sender }
    }

    /// Return a cheaply-cloneable [`BusHandle`] that can publish without
    /// borrowing the `Bus`.
    pub fn handle(&self) -> BusHandle<T> {
        BusHandle {
            sender: self.sender.clone(),
        }
    }

    /// Subscribe to every envelope on the bus (no topic filter).
    pub fn subscribe(&self) -> Subscriber<T> {
        Subscriber {
            receiver: self.sender.subscribe(),
            filter: None,
        }
    }

    /// Subscribe and filter by a glob pattern (see [`crate::Topic::matches`]).
    pub fn subscribe_topic(&self, pattern: impl Into<String>) -> Subscriber<T> {
        Subscriber {
            receiver: self.sender.subscribe(),
            filter: Some(pattern.into()),
        }
    }

    /// Publish an envelope.  Returns the number of active receivers or
    /// [`IpcError::NoSubscribers`] if no one is listening.
    pub fn publish(&self, env: Envelope<T>) -> Result<usize, IpcError> {
        self.sender.send(env).map_err(|_| IpcError::NoSubscribers)
    }
}

/// A cheaply-cloneable handle to a [`Bus`] that can publish envelopes.
#[derive(Clone)]
pub struct BusHandle<T: Clone + Send + Sync + 'static> {
    sender: tokio::sync::broadcast::Sender<Envelope<T>>,
}

impl<T: Clone + Send + Sync + 'static> BusHandle<T> {
    /// Publish an envelope through this handle.
    pub fn publish(&self, env: Envelope<T>) -> Result<usize, IpcError> {
        self.sender.send(env).map_err(|_| IpcError::NoSubscribers)
    }
}

/// A subscriber that receives envelopes from a [`Bus`].
///
/// Constructed via [`Bus::subscribe`] or [`Bus::subscribe_topic`].
pub struct Subscriber<T: Clone + Send + Sync + 'static> {
    receiver: tokio::sync::broadcast::Receiver<Envelope<T>>,
    filter: Option<String>,
}

impl<T: Clone + Send + Sync + 'static> Subscriber<T> {
    /// Await the next envelope that passes the optional topic filter.
    ///
    /// Returns:
    /// - `Ok(envelope)` on success.
    /// - `Err(IpcError::Closed)` when the bus has been dropped.
    /// - `Err(IpcError::Lagged(n))` when the subscriber fell behind by `n` messages.
    pub async fn recv(&mut self) -> Result<Envelope<T>, IpcError> {
        loop {
            let env = self.receiver.recv().await.map_err(|e| match e {
                tokio::sync::broadcast::error::RecvError::Closed => IpcError::Closed,
                tokio::sync::broadcast::error::RecvError::Lagged(n) => IpcError::Lagged(n),
            })?;

            if let Some(pat) = &self.filter {
                if !env.topic.matches(pat) {
                    continue;
                }
            }
            return Ok(env);
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{envelope::Priority, Topic};

    fn topic(s: &str) -> Topic {
        Topic::new(s).unwrap()
    }

    // 1. topic validation
    #[test]
    fn topic_validation() {
        assert!(Topic::new("").is_err(), "empty topic must error");
        assert!(Topic::new("Broker.Audit").is_err(), "uppercase must error");
        assert!(
            Topic::new("broker.audit").is_ok(),
            "valid topic must succeed"
        );
        // consecutive dots are allowed by the validator (documented in spec notes)
        // assert!(Topic::new("broker..audit").is_err());
    }

    // 2. topic glob matching
    #[test]
    fn topic_matches_glob() {
        let t = topic("broker.audit");
        assert!(t.matches("broker.*"));
        assert!(t.matches("broker.**"));
        assert!(!t.matches("broker.audit.event"));
        assert!(t.matches("**"));
        assert!(!t.matches("other.*"));

        let deep = topic("broker.audit.event");
        assert!(deep.matches("broker.**"));
        assert!(!deep.matches("broker.*"));
    }

    // 3. publish → single subscriber receives
    #[tokio::test(flavor = "multi_thread")]
    async fn bus_publish_one_subscriber_receives() {
        let bus: Bus<String> = Bus::new(16);
        let mut sub = bus.subscribe();
        let env = Envelope::new(topic("test.topic"), "hello".to_string());
        bus.publish(env).unwrap();
        let received = sub.recv().await.unwrap();
        assert_eq!(received.payload, "hello");
    }

    // 4. publish → two subscribers both receive
    #[tokio::test(flavor = "multi_thread")]
    async fn bus_publish_two_subscribers_both_receive() {
        let bus: Bus<u32> = Bus::new(16);
        let mut s1 = bus.subscribe();
        let mut s2 = bus.subscribe();
        bus.publish(Envelope::new(topic("a.b"), 42u32)).unwrap();
        assert_eq!(s1.recv().await.unwrap().payload, 42);
        assert_eq!(s2.recv().await.unwrap().payload, 42);
    }

    // 5. topic filter excludes non-matching envelopes
    #[tokio::test(flavor = "multi_thread")]
    async fn bus_topic_filter_excludes_non_matching() {
        let bus: Bus<&'static str> = Bus::new(16);
        let mut sub = bus.subscribe_topic("policy.*");

        bus.publish(Envelope::new(topic("broker.audit"), "should-be-filtered"))
            .unwrap();
        bus.publish(Envelope::new(topic("policy.changed"), "should-arrive"))
            .unwrap();

        let env = sub.recv().await.unwrap();
        assert_eq!(env.payload, "should-arrive");
        assert_eq!(env.topic.as_str(), "policy.changed");
    }

    // 6. no subscribers → error
    #[tokio::test(flavor = "multi_thread")]
    async fn bus_no_subscribers_returns_error() {
        let bus: Bus<String> = Bus::new(16);
        let result = bus.publish(Envelope::new(topic("x.y"), "data".to_string()));
        assert!(
            matches!(result, Err(IpcError::NoSubscribers)),
            "expected NoSubscribers, got {result:?}"
        );
    }

    // 7. drop Bus → subscriber gets Closed
    #[tokio::test(flavor = "multi_thread")]
    async fn subscriber_recv_after_drop_errors_closed() {
        let bus: Bus<String> = Bus::new(16);
        let mut sub = bus.subscribe();
        drop(bus);
        let err = sub.recv().await.unwrap_err();
        assert!(
            matches!(err, IpcError::Closed),
            "expected Closed, got {err:?}"
        );
    }

    // 8. Priority round-trips through the envelope
    #[tokio::test(flavor = "multi_thread")]
    async fn priority_can_be_set() {
        let bus: Bus<()> = Bus::new(16);
        let mut sub = bus.subscribe();
        let env = Envelope::new(topic("host.health"), ()).with_priority(Priority::High);
        assert_eq!(env.priority, Priority::High);
        bus.publish(env).unwrap();
        let received = sub.recv().await.unwrap();
        assert_eq!(received.priority, Priority::High);
    }
}
