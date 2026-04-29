//! Typed message envelopes carried by the IPC bus.

use std::time::SystemTime;

/// Opaque unique identifier for an [`Envelope`].
pub type EnvelopeId = uuid::Uuid;

/// Delivery priority hint.
///
/// Higher-priority messages should be handled first by consumers that
/// multiplex multiple topics; the bus itself does not reorder messages.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// Best-effort traces, sampled telemetry.
    Low,
    /// Normal lifecycle/audit messages.
    Normal,
    /// Health, watchdog, urgent fault.
    High,
}

/// A typed message envelope sent through a [`Bus`](crate::Bus).
#[derive(Clone, Debug)]
pub struct Envelope<T> {
    /// Unique identifier for this envelope.
    pub id: EnvelopeId,
    /// Topic on which the envelope was published.
    pub topic: crate::Topic,
    /// Delivery priority.
    pub priority: Priority,
    /// Wall-clock time when the envelope was created.
    pub created_at: SystemTime,
    /// Caller-supplied payload.
    pub payload: T,
}

impl<T> Envelope<T> {
    /// Create a new envelope with [`Priority::Normal`] and the current time.
    pub fn new(topic: crate::Topic, payload: T) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            topic,
            priority: Priority::Normal,
            created_at: SystemTime::now(),
            payload,
        }
    }

    /// Override the priority (builder-style).
    pub fn with_priority(mut self, p: Priority) -> Self {
        self.priority = p;
        self
    }
}
