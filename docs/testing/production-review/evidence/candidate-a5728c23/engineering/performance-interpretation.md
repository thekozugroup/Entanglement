# Integrated Linux dispatch performance

Five of seven routes met both prespecified engineering limits against c19ef758. At one local greeting client, one of three pairs exceeded the p95 limit. At four local clients, all three pairs exceeded it, including both run orders. All seven routes met the throughput limit by the prescribed ratio of medians. The comparison used integrated commit a5728c230e5049556b806cae8597fe823dd67987, source a43296d2, on November 27, 2026. [Primary observations](../performance.json) · [Recorded plan](plan.md)

| Route | Primary p95 / throughput ratio | Trial 1 | Trial 2 | Trial 3 | Primary limits |
|---|---:|---:|---:|---:|---|
| local / 1 | 1.055 / 0.955 | 1.035 / 1.035 | 2.064 / 0.807 | 0.905 / 1.089 | Miss |
| local / 4 | 1.068 / 0.963 | 1.068 / 0.973 | 2.098 / 0.609 | 1.114 / 1.077 | Miss |
| remote / 1 | 0.995 / 0.971 | 1.053 / 0.982 | 0.995 / 0.943 | 1.009 / 1.022 | Pass |
| remote / 4 | 0.966 / 0.998 | 0.949 / 1.032 | 1.074 / 0.950 | 0.745 / 1.060 | Pass |
| image local | 1.020 / 1.048 | 1.178 / 0.966 | 0.851 / 1.098 | 1.135 / 0.916 | Pass |
| image one_remote | 0.939 / 1.128 | 0.936 / 1.080 | 0.700 / 1.256 | 1.047 / 1.058 | Pass |
| image three_remote | 0.817 / 1.030 | 1.031 / 0.991 | 0.687 / 1.289 | 0.693 / 1.155 | Pass |

Ratios are integrated candidate divided by baseline. For greetings the trials were adjacent fresh-cluster pairs, with baseline first in pairs 1 and 3 and candidate first in pair 2. Images used a single fresh cluster per build, candidate first, with three rotated trials per topology. Each image trial column compares the same within-cluster ordinal. The primary limits use separately calculated three-trial medians, p95 at most 1.05 and throughput at least 0.95.

## Local greetings

| Clients | Pair | Baseline → candidate p95 (ms) | Baseline → candidate throughput (calls/s) |
|---:|---:|---:|---:|
| 1 | 1 | 0.481 → 0.498 | 2,936.6 → 3,039.3 |
| 1 | 2 | 0.472 → 0.974 | 3,182.5 → 2,567.2 |
| 1 | 3 | 0.401 → 0.363 | 3,791.6 → 4,130.3 |
| 4 | 1 | 0.850 → 0.908 | 7,255.7 → 7,060.2 |
| 4 | 2 | 0.964 → 2.022 | 7,330.3 → 4,463.2 |
| 4 | 3 | 0.734 → 0.818 | 8,072.6 → 8,692.9 |

The candidate-first pair contained the largest p95 for each local client count. Both were more than double their paired baseline. For one client the median of paired p95 ratios was 1.035, while the prescribed ratio of medians was 1.055 (+0.026 ms). For four clients the corresponding ratios were 1.114 and 1.068 (+0.058 ms). Both baseline-first four-client pairs exceeded the p95 limit. Throughput direction changed by pair at both client counts. [Primary observations](../performance.json)

## Comparison with earlier controls

| Paired experiment | One-client local p95 median (range) | Four-client local p95 median (range) |
|---|---:|---:|
| 296b / c19, four pairs | 1.399 (0.814–2.239) | 1.115 (0.922–1.241) |
| Identical 296b daemon in that window, four pairs | 0.966 (0.566–1.171) | 1.015 (0.340–2.977) |
| Isolated 4dd / 296b, eight pairs | 0.935 (0.307–2.396) | 0.614 (0.299–2.276) |
| Identical 296b daemon in the 4dd window, four pairs | 0.913 (0.819–1.025) | 0.890 (0.620–1.172) |

The earlier 296b/c19 four-client comparison also exceeded the p95 limit in three of four pairs. The isolated handle comparison treated these local greeting routes as descriptive, and its paired intervals included equal performance for both. Identical-daemon comparisons establish substantial variation on this host. They cannot assign a cause to any particular integrated trial. [296b paired controls](../../candidate-296b427a/performance-diagnostic/paired-summary.json) · [Isolated 4dd paired controls](../handle-layout/isolated-4dd03c64/paired-summary.json)

The run covered 09:31:03–09:31:45 UTC on five visible vCPUs sharing a four-core CPU quota. None of the 38 process samples recorded a known build. The receipt contains no per-call CPU scheduling delay, hypervisor steal measurement, or cgroup-throttling deltas for these pairs. The observations support a recurring four-client local tail and a variable single-client tail. The available measurements do not establish a code or cloud-interference cause. The nominated comparator remains an engineering baseline. [Original data and host samples](../performance.json) · [Sampling implementation](monitor.py)
