# Ordinary signed workload measurements

4 of seven routes passed both limits against the preceding a5728c23 engineering release. Each route required candidate median p95 at most 1.05 times the comparator and candidate median rate at least 0.95 times the comparator. The production operator has yet to approve a baseline. [Registered plan](plan.md) · [Primary observations](../performance.json)

| Route | Median p95 ratio | Median rate ratio | Trial 1 p95 / rate | Trial 2 p95 / rate | Trial 3 p95 / rate | Both limits |
|---|---:|---:|---:|---:|---:|---|
| local / 1 | 1.018 | 1.130 | 0.758 / 1.529 | 0.939 / 1.350 | 1.589 / 0.631 | Pass |
| local / 4 | 0.679 | 1.399 | 0.679 / 1.346 | 0.359 / 1.766 | 0.924 / 1.054 | Pass |
| remote / 1 | 1.063 | 0.959 | 1.016 / 0.738 | 1.147 / 0.899 | 0.933 / 1.080 | Miss |
| remote / 4 | 0.914 | 1.109 | 0.739 / 1.202 | 1.035 / 1.053 | 1.005 / 0.957 | Pass |
| image local | 1.065 | 1.158 | 1.305 / 0.928 | 1.263 / 0.932 | 0.921 / 1.172 | Miss |
| image one_remote | 1.080 | 1.037 | 0.957 / 1.179 | 1.091 / 1.034 | 0.874 / 1.038 | Miss |
| image three_remote | 0.941 | 1.029 | 1.160 / 0.873 | 0.706 / 1.053 | 0.941 / 1.070 | Pass |

Greeting trials used adjacent fresh clusters in AB, BA and AB order. Each arm checked 1,024 signed responses per route. Image trials compared the same within-version ordinal across three repetitions per route. Each version used one separately created cluster, with the candidate suite first. The prescribed verdict divides three-trial medians from the two versions. Trial columns retain the individual ratios.

Both image batches produced the same ordered SHA-256 digest of all 24 outputs, `cc355f03ea0cd50472e113b2b92509bca56458ad637152b33f5fbb28eeac441b`. The candidate and comparator obtained three-worker versus one-worker rates of 0.944× and 0.952× on the shared host. Four concurrent clients shared its CPU allocation.

The host monitor captured 39 samples. Known build processes observed were none. Cgroup throttled time increased by 401326 µs from the pre-series to post-series snapshots. The entire series used one shared Linux VM. Image timing includes other work within the same cluster. These three-trial comparisons can fluctuate with host load and trial order.

## Interpretation

All seven primary rates met the throughput limit. The single-client remote greeting missed the p95 limit by 1.3 percentage points. The local and one-remote image tails missed by 1.5 and 3.0 percentage points. All other route medians passed both bounds. This first series is the final candidate result. The previous candidate’s separate 36-arm greeting diagnostic used a different daemon ELF and supplies historical visibility into run-to-run variation. The source diff adds a one-shot operator link flow, moves the same Tailscale node address predicate, and revises the host capability text and probe called by doctor and print-platform. The signed job fixtures use explicit loopback Iroh workers and do not invoke those CLI commands or run the Tailscale adapter. These timings do not identify a new operation in ordinary warm dispatch. [Verified source paths](../tailnet-link-latency/callpath.json) · [Historical diagnostic](../../candidate-90beded5/greeting-sensitivity/README.md)
