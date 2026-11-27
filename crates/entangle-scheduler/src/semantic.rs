//! Submitter-only verification of three independent signed semantic replicas.
use crate::{
    dispatcher::{DispatchError, DispatchResult, Dispatcher},
    work_unit::{Policy, REPLICAS},
};
use entangle_types::{errors::EntangleError, peer_id::PeerId, task::OneShotTask};
use std::collections::HashSet;

impl Dispatcher {
    pub(crate) async fn semantic(
        &self,
        task: &OneShotTask,
        name: &str,
        threshold: f32,
    ) -> Result<DispatchResult, DispatchError> {
        if !(0.0..=1.0).contains(&threshold) {
            return Err(DispatchError::Integrity(
                "semantic threshold must be finite and in [0, 1]".into(),
            ));
        }
        let id = name
            .parse()
            .map_err(|_| DispatchError::Integrity("invalid metric plugin ID".into()))?;
        // Verification and immutable CID pinning precede any dispatch or guest instantiation.
        let metric = self.kernel.prepare_metric(&id)?;
        let remote = self.remote.as_ref().ok_or_else(|| {
            DispatchError::Integrity("three distinct remote workers are required".into())
        })?;
        let policy = Policy::new(&id, metric.cid, metric.publisher, threshold);
        let (hash, frame) = remote.signed_request(task, policy)?;
        let mut selected = HashSet::from([self.local_peer_id]);
        let mut placements = Vec::with_capacity(REPLICAS);
        for _ in 0..REPLICAS {
            let (choice, reservation) = self.workers.choose(
                self.worker_ttl,
                &task.resources,
                &task.plugin,
                task.input.len(),
                None,
                |p| !selected.contains(p),
            )?;
            selected.insert(choice.peer_id);
            placements.push((choice, reservation));
        }
        // Negotiate *every* worker before any of them receives the task payload.
        let negotiate = |i: usize| remote.negotiate_signed(placements[i].0.peer_id);
        let (x, y, z) = tokio::try_join!(negotiate(0), negotiate(1), negotiate(2))?;
        let (a, b, c) = tokio::join!(
            remote.signed_replica(task, &x, &hash, &frame),
            remote.signed_replica(task, &y, &hash, &frame),
            remote.signed_replica(task, &z, &hash, &frame),
        );
        let mut outputs = Vec::with_capacity(REPLICAS);
        for (index, result) in [a, b, c].into_iter().enumerate() {
            if let Err(DispatchError::OutputSizeExceeded(EntangleError::OutputSizeExceeded {
                declared,
                actual,
                ..
            })) = &result
            {
                self.penalize_oversize(placements[index].0.peer_id, *declared, *actual);
            }
            outputs.push(result);
        }
        // Check every worker's ceiling before *any* comparison, including earlier valid peers.
        let outputs = outputs.into_iter().collect::<Result<Vec<_>, _>>()?;
        let mut agreements = [0u8; REPLICAS];
        let mut pairs = 0;
        for i in 0..outputs.len() {
            for j in i + 1..outputs.len() {
                let distance = metric
                    .compare(&outputs[i], &outputs[j], task.timeout_ms)
                    .await?;
                if distance.is_finite() && distance >= 0.0 && distance < f64::from(threshold) {
                    agreements[i] += 1;
                    agreements[j] += 1;
                    pairs += 1;
                }
            }
        }
        // Agreement with either other replica supplies positive evidence. If no pair
        // agrees there is no reference result with which to attribute individual fault.
        if pairs >= 2 {
            for ((choice, _), count) in placements.iter().zip(agreements) {
                self.workers.observe_semantic(&choice.peer_id, count > 0);
            }
        }
        if pairs < 2 {
            return Err(DispatchError::Integrity(
                "semantic replica quorum did not agree".into(),
            ));
        }
        // Prefer the output supported by the largest number of comparisons.
        let winner = (0..REPLICAS)
            .max_by_key(|&i| (agreements[i], std::cmp::Reverse(i)))
            .expect("three replicas");
        Ok(DispatchResult {
            chosen: placements.swap_remove(winner).0,
            output: outputs
                .into_iter()
                .nth(winner)
                .expect("corresponding replica"),
        })
    }

    fn penalize_oversize(&self, peer: PeerId, declared: u64, actual: u64) {
        self.workers.observe_semantic(&peer, false);
        tracing::warn!(peer_id=%peer,declared,actual,"OutputSizeExceededWarning");
        self.kernel.metrics().inc_counter(
            "entangle_semantic_oversized_results_total",
            "Semantic replica outputs rejected before metric instantiation",
            &[],
            1.0,
        );
    }
}
