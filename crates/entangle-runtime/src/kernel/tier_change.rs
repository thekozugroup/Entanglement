//! A live tier transaction holds the plugin registry stable from review through commit.
use super::*;
use entangle_broker::AuditEvent;

impl Kernel {
    /// Review a proposed ceiling under an exclusive load/unload reservation.
    pub async fn reserve_tier_change(&self, target: Tier) -> Result<TierChange<'_>, RuntimeError> {
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
        let reservation = wait_for_drain(deadline, self.lifecycle_gate.write()).await?;
        let mut affected: Vec<_> = self
            .plugins
            .read()
            .iter()
            .filter(|(_, record)| record.effective_tier > target)
            .map(|(id, record)| (id.clone(), record.effective_tier))
            .collect();
        affected.sort_by_key(|(id, _)| id.to_string());
        Ok(TierChange {
            kernel: self,
            deadline,
            _reservation: reservation,
            target,
            affected,
        })
    }

    /// Restore the stored disabled set before loading startup packages.
    pub fn restore_disabled_plugins(&mut self, disabled: &[String]) {
        *self.disabled.get_mut() = disabled.iter().cloned().collect();
    }
}

/// A stable view of the plugins affected by a proposed ceiling.
pub struct TierChange<'a> {
    kernel: &'a Kernel,
    deadline: tokio::time::Instant,
    _reservation: tokio::sync::RwLockWriteGuard<'a, ()>,
    target: Tier,
    affected: Vec<(PluginId, Tier)>,
}

impl TierChange<'_> {
    /// Current live ceiling.
    pub fn current(&self) -> Tier {
        self.kernel.broker.policy().max_tier_allowed
    }

    /// Generation of the registry and live policy.
    pub fn generation(&self) -> u64 {
        self.kernel.generation.load(Ordering::Relaxed)
    }

    /// Affected plugin IDs and their verified tiers.
    pub fn affected(&self) -> &[(PluginId, Tier)] {
        &self.affected
    }

    /// Record a cancellation after the caller successfully restores the old config.
    pub fn cancelled(&self) {
        self.kernel.generation.fetch_add(1, Ordering::Relaxed);
        self.audit("ENTANGLE-I0216", self.current(), None);
    }

    fn audit(&self, code: &'static str, previous: Tier, plugin: Option<PluginId>) {
        self.kernel
            .broker
            .audit_log()
            .record(AuditEvent::TierCeiling {
                code,
                previous,
                proposed: self.target,
                plugin,
                at: SystemTime::now(),
            });
    }

    /// Drain affected invocations, persist the approved policy, then commit the live change.
    /// A failed write or cancelled drain leaves every gate and the registry intact.
    pub async fn apply(
        self,
        disabled: BTreeSet<String>,
        persist: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let previous = self.current();
        let gates: Vec<_> = {
            let records = self.kernel.plugins.read();
            self.affected
                .iter()
                .map(|(id, _)| records[id].invocation_gate.clone())
                .collect()
        };
        let mut drained = Vec::with_capacity(gates.len());
        for gate in gates {
            drained.push(wait_for_drain(self.deadline, gate.write_owned()).await?);
        }
        persist()?;
        let mut records = self.kernel.plugins.write();
        for ((id, _), guard) in self.affected.iter().zip(&mut drained) {
            **guard = false;
            self.kernel
                .release_record(id, records.remove(id).expect("reserved plugin"));
            self.audit("ENTANGLE-W0214", previous, Some(id.clone()));
        }
        *self.kernel.disabled.write() = disabled;
        self.kernel.broker.set_max_tier(self.target);
        self.kernel.generation.fetch_add(1, Ordering::Relaxed);
        self.audit("ENTANGLE-I0215", previous, None);
        Ok(())
    }
}
