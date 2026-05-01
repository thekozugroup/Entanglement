//! Greedy multi-criteria placement algorithm.
//!
//! Score = w_fit * resource_fit
//!       + w_local * locality
//!       + w_bw * bandwidth_match
//!       + w_load * (1 - load)
//!       - w_cost * cost
//!
//! Where:
//! - `resource_fit` = 1.0 if all required resources are present and sufficient; 0.0 otherwise.
//! - `locality` = 1.0 if rtt_ms < 5 (LAN); decays linearly to 0 at rtt_ms = 200.
//! - `bandwidth_match` = clamp(actual_bw / required_bw, 0, 1).
//! - `load` = current load reported by worker.
//! - `cost` = relative cost factor.

use crate::worker::WorkerInfo;
use entangle_types::peer_id::PeerId;
use entangle_types::resource::{GpuBackend, ResourceSpec};

/// The result of a successful placement decision.
#[derive(Clone, Debug)]
pub struct PlacementChoice {
    /// The peer chosen to execute the task.
    pub peer_id: PeerId,
    /// Computed score for the chosen worker.
    pub score: f32,
    /// Human-readable explanation of why this worker was chosen.
    pub reason: String,
}

/// Errors that can arise during placement.
#[derive(Clone, Debug, thiserror::Error)]
pub enum PlacementError {
    /// The worker pool had no live workers at all.
    #[error("no live workers in pool")]
    NoWorkers,
    /// Workers exist but none satisfies the resource spec.
    #[error("no worker satisfies the resource spec: {0}")]
    NoMatch(String),
}

/// Choose the best worker for `spec` using a greedy multi-criteria score.
///
/// Returns [`PlacementError::NoWorkers`] when the slice is empty, or
/// [`PlacementError::NoMatch`] when no worker meets the hard constraints.
pub fn choose(
    workers: &[WorkerInfo],
    spec: &ResourceSpec,
) -> Result<PlacementChoice, PlacementError> {
    if workers.is_empty() {
        return Err(PlacementError::NoWorkers);
    }

    let candidates: Vec<&WorkerInfo> = workers.iter().filter(|w| satisfies(w, spec)).collect();

    if candidates.is_empty() {
        return Err(PlacementError::NoMatch(format!("{spec:?}")));
    }

    let (w_fit, w_local, w_bw, w_load, w_cost) = (1.0_f32, 0.6, 0.4, 0.5, 0.3);

    let scored: Vec<(f32, &&WorkerInfo)> = candidates
        .iter()
        .map(|w| {
            let fit = 1.0_f32; // already filtered by satisfies()
            let locality = if w.rtt_ms < 5 {
                1.0
            } else if w.rtt_ms >= 200 {
                0.0
            } else {
                1.0 - (w.rtt_ms.saturating_sub(5) as f32) / 195.0
            };
            let bw = if spec.network_bandwidth_bps == 0 {
                1.0
            } else {
                (w.network_bandwidth_bps as f32 / spec.network_bandwidth_bps as f32).min(1.0)
            };
            let load_term = (1.0 - w.load).max(0.0);
            let score =
                w_fit * fit + w_local * locality + w_bw * bw + w_load * load_term - w_cost * w.cost;
            (score, w)
        })
        .collect();

    let (top_score, top_worker) = scored
        .iter()
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
        .copied()
        .expect("candidates is non-empty");

    Ok(PlacementChoice {
        peer_id: top_worker.peer_id,
        score: top_score,
        reason: format!(
            "fit ok, rtt={}ms, bw={} bps, load={:.2}, cost={:.2}",
            top_worker.rtt_ms, top_worker.network_bandwidth_bps, top_worker.load, top_worker.cost,
        ),
    })
}

/// Returns `true` if `w` meets all hard resource constraints in `spec`.
fn satisfies(w: &WorkerInfo, spec: &ResourceSpec) -> bool {
    if w.cpu_cores < spec.cpu_cores {
        return false;
    }
    if w.memory_bytes < spec.memory_bytes {
        return false;
    }
    if let Some(req) = &spec.gpu {
        let Some(have) = &w.gpu else {
            return false;
        };
        if have.vram_min_bytes < req.vram_min_bytes {
            return false;
        }
        if !backend_matches(have.backend, req.backend) {
            return false;
        }
    }
    if let Some(req) = &spec.npu {
        let Some(have) = &w.npu else {
            return false;
        };
        if !req.vendor.is_empty() && !req.vendor.eq_ignore_ascii_case(&have.vendor) {
            return false;
        }
    }
    true
}

/// Returns `true` if `have` satisfies the `req` backend constraint.
fn backend_matches(have: GpuBackend, req: GpuBackend) -> bool {
    matches!(req, GpuBackend::Any) || have == req
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::WorkerInfo;
    use entangle_types::resource::{GpuBackend, GpuRequirement, NpuRequirement, ResourceSpec};

    fn peer(byte: u8) -> PeerId {
        PeerId::from_public_key_bytes(&[byte; 32])
    }

    #[allow(clippy::too_many_arguments)]
    fn worker(
        peer_id: PeerId,
        rtt_ms: u32,
        load: f32,
        cpu_cores: f32,
        memory_bytes: u64,
        gpu: Option<GpuRequirement>,
        npu: Option<NpuRequirement>,
        cost: f32,
    ) -> WorkerInfo {
        WorkerInfo {
            peer_id,
            display_name: "node".into(),
            cpu_cores,
            memory_bytes,
            gpu,
            npu,
            network_bandwidth_bps: 1_000_000_000,
            rtt_ms,
            load,
            cost,
        }
    }

    fn basic_spec() -> ResourceSpec {
        ResourceSpec {
            cpu_cores: 1.0,
            memory_bytes: 1024,
            ..ResourceSpec::default()
        }
    }

    #[test]
    fn choose_picks_lowest_rtt_when_resources_equal() {
        let p1 = peer(1);
        let p2 = peer(2);
        let workers = vec![
            worker(p1, 100, 0.1, 4.0, 8 * 1024 * 1024 * 1024, None, None, 1.0),
            worker(p2, 2, 0.1, 4.0, 8 * 1024 * 1024 * 1024, None, None, 1.0),
        ];
        let result = choose(&workers, &basic_spec()).unwrap();
        assert_eq!(result.peer_id, p2, "low-rtt worker should win");
    }

    #[test]
    fn choose_filters_workers_lacking_gpu_when_required() {
        let p1 = peer(1); // no GPU
        let p2 = peer(2); // has GPU
        let workers = vec![
            worker(p1, 1, 0.0, 4.0, 8 * 1024 * 1024 * 1024, None, None, 1.0),
            worker(
                p2,
                5,
                0.0,
                4.0,
                8 * 1024 * 1024 * 1024,
                Some(GpuRequirement {
                    vram_min_bytes: 4 * 1024 * 1024 * 1024,
                    backend: GpuBackend::Metal,
                }),
                None,
                1.0,
            ),
        ];
        let spec = ResourceSpec {
            cpu_cores: 1.0,
            memory_bytes: 1024,
            gpu: Some(GpuRequirement {
                vram_min_bytes: 2 * 1024 * 1024 * 1024,
                backend: GpuBackend::Metal,
            }),
            ..ResourceSpec::default()
        };
        let result = choose(&workers, &spec).unwrap();
        assert_eq!(result.peer_id, p2, "only GPU worker should be chosen");
    }

    #[test]
    fn choose_filters_workers_with_insufficient_memory() {
        let p1 = peer(1); // 512 MiB
        let p2 = peer(2); // 8 GiB
        let workers = vec![
            worker(p1, 1, 0.0, 4.0, 512 * 1024 * 1024, None, None, 1.0),
            worker(p2, 2, 0.0, 4.0, 8 * 1024 * 1024 * 1024, None, None, 1.0),
        ];
        let spec = ResourceSpec {
            cpu_cores: 1.0,
            memory_bytes: 2 * 1024 * 1024 * 1024, // require 2 GiB
            ..ResourceSpec::default()
        };
        let result = choose(&workers, &spec).unwrap();
        assert_eq!(result.peer_id, p2);
    }

    #[test]
    fn choose_filters_workers_with_wrong_gpu_backend() {
        let p1 = peer(1); // CUDA
        let p2 = peer(2); // Metal
        let workers = vec![
            worker(
                p1,
                1,
                0.0,
                4.0,
                8 * 1024 * 1024 * 1024,
                Some(GpuRequirement {
                    vram_min_bytes: 4 * 1024 * 1024 * 1024,
                    backend: GpuBackend::Cuda,
                }),
                None,
                1.0,
            ),
            worker(
                p2,
                2,
                0.0,
                4.0,
                8 * 1024 * 1024 * 1024,
                Some(GpuRequirement {
                    vram_min_bytes: 4 * 1024 * 1024 * 1024,
                    backend: GpuBackend::Metal,
                }),
                None,
                1.0,
            ),
        ];
        let spec = ResourceSpec {
            cpu_cores: 1.0,
            memory_bytes: 1024,
            gpu: Some(GpuRequirement {
                vram_min_bytes: 1024,
                backend: GpuBackend::Metal,
            }),
            ..ResourceSpec::default()
        };
        let result = choose(&workers, &spec).unwrap();
        assert_eq!(
            result.peer_id, p2,
            "only Metal worker should match Metal spec"
        );
    }

    #[test]
    fn choose_returns_no_match_when_pool_empty_after_filter() {
        let p1 = peer(1); // 256 MiB — below threshold
        let workers = vec![worker(p1, 1, 0.0, 4.0, 256 * 1024 * 1024, None, None, 1.0)];
        let spec = ResourceSpec {
            cpu_cores: 1.0,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            ..ResourceSpec::default()
        };
        assert!(matches!(
            choose(&workers, &spec),
            Err(PlacementError::NoMatch(_))
        ));
    }

    #[test]
    fn choose_prefers_low_load_among_equal_locality() {
        let p1 = peer(1); // load 0.9
        let p2 = peer(2); // load 0.1
                          // Same rtt_ms (both LAN) so locality is identical; load should decide.
        let workers = vec![
            worker(p1, 1, 0.9, 4.0, 8 * 1024 * 1024 * 1024, None, None, 1.0),
            worker(p2, 1, 0.1, 4.0, 8 * 1024 * 1024 * 1024, None, None, 1.0),
        ];
        let result = choose(&workers, &basic_spec()).unwrap();
        assert_eq!(result.peer_id, p2, "low-load worker should win");
    }

    #[test]
    fn gpu_any_backend_matches_metal_and_cuda() {
        // Both Metal and CUDA workers must pass the GpuBackend::Any filter.
        // Use rtt=1 vs rtt=100 so locality strongly separates them.
        let p_metal = peer(1);
        let p_cuda = peer(2);
        let workers = vec![
            worker(
                p_metal,
                1, // LAN — locality 1.0
                0.0,
                4.0,
                8 * 1024 * 1024 * 1024,
                Some(GpuRequirement {
                    vram_min_bytes: 4 * 1024 * 1024 * 1024,
                    backend: GpuBackend::Metal,
                }),
                None,
                1.0,
            ),
            worker(
                p_cuda,
                100, // WAN — locality ~0.49
                0.0,
                4.0,
                8 * 1024 * 1024 * 1024,
                Some(GpuRequirement {
                    vram_min_bytes: 4 * 1024 * 1024 * 1024,
                    backend: GpuBackend::Cuda,
                }),
                None,
                1.0,
            ),
        ];
        let spec = ResourceSpec {
            cpu_cores: 1.0,
            memory_bytes: 1024,
            gpu: Some(GpuRequirement {
                vram_min_bytes: 1024,
                backend: GpuBackend::Any,
            }),
            ..ResourceSpec::default()
        };
        // Both satisfy GpuBackend::Any; p_metal wins on locality.
        let result = choose(&workers, &spec).unwrap();
        assert_eq!(
            result.peer_id, p_metal,
            "GpuBackend::Any should accept both Metal and CUDA"
        );
    }
}
