# Four-client local dispatch on fixed CPUs

The candidate's median paired p95 was **1.13% lower** across 16 fresh pairs. Its 95% paired-bootstrap interval ran from **5.96% lower to 7.87% higher**. The interval excludes the approximately 20% increases observed in both earlier mixed-topology comparisons and crosses the diagnostic's 5% threshold. A smaller material tail regression remains unresolved in this configuration. The throughput interval stayed above the predeclared −5% boundary. The original seven-row gate and the two earlier controls retain their published results. [Preregistration](preregistration.md) · [Seven-row comparison](../../performance.md) · [Earlier controls](../results.md)

| Four-client metric | Baseline arm median | Candidate arm median | Median within-pair change | 95% paired-bootstrap interval |
| --- | ---: | ---: | ---: | ---: |
| p95 latency | 0.7372 ms | 0.7108 ms | −1.13% | −5.96% to +7.87% |
| Throughput | 7,985 requests/s | 7,944 requests/s | −0.71% | −3.53% to +3.25% |

The estimator computes the ratio within each matched pair and takes the median of those 16 ratios. Intervals resample complete pairs 50,000 times with a fixed seed. Each arm started a fresh signed two-daemon fixture, checked readiness and verified the first local and remote results. After 1,024 local warm-ups, four Rust clients submitted 4,096 timed challenges on the local UDS path. All 131,072 timed responses matched both the exact greeting and the expected worker identity. The client process ran on CPUs 0–1 and the two daemon processes on CPUs 2–3. Each daemon used two Tokio workers and two Rayon threads. The Linux VM had five available CPUs and a four-core cgroup quota. The diagnostic started at 03:52:56 UTC and finished at 03:53:23 UTC on 2026-11-27. [Run metadata and ELF hashes](run.json) · [Every per-request duration and original process counters](raw.json.gz)

Seven out of 16 pairs had higher candidate p95. The median paired p95 ratio was 0.950 when the baseline ran first and 1.035 when the candidate ran first. The individual extremes were 0.848 in pair 14 and 1.143 in pair 6. All observations were retained. Across the 32 timed intervals the host cgroup reported zero throttled periods. Median worker process CPU was 86.5 ticks for baseline and 85 ticks for candidate at 100 ticks/s. The process monitor sampled every 0.75 seconds and can miss shorter processes. Fixed affinity, concentrated local warm-up and 4,096 measured calls differ from the primary benchmark. The additional sample estimates only this controlled deployment. [All paired values and uncertainty calculations](summary.json)

The production source changes between these revisions concern daemon transport assembly and Tailscale recovery. The fixture selected direct Iroh, and every timed request executed locally. It did not enter the Tailscale supervisor. The measured p95 interval and process counters do not identify an execution-level defect that warrants a code change. [Fixture routing](../../../../../../../crates/entangle-bin/tests/daemon_compute.rs) · [Listener choice](../../../../../../../crates/entangle-bin/src/remote/routes.rs)

## Reproduction

Use the frozen 761485d7 source with Rust 1.91.1 and its Cargo-built debug integration test. Pass the corresponding `daemon_compute-<hash>` ELF so the build helper selects the precise client dependency artifacts recorded in its Cargo fingerprint. Set the two daemon paths to the verified optimized 864ae27b and 761485d7 ELFs. Linux CPU IDs 0–3 must be available. Write new observations to an empty output directory.

```sh
python3 build-driver.py "$entanglement_root" "$daemon_compute_test" "$scratch"
python3 run.py "$scratch/local-four-driver" "$baseline_entangled" "$candidate_entangled" "$output"
python3 analyze.py "$output"
```

The build helper copies the existing two-daemon fixture into the scratch directory. It reuses the production Rust client artifacts, exact greeting generator, per-response assertions and four-client sampling logic, removes unrelated integration tests and changes the timed loop to record only local/4. The candidate source and release binaries remain as recorded in the seven-row comparison. [Diagnostic builder](build-driver.py) · [Matched-pair runner](run.py) · [Analysis](analyze.py)
