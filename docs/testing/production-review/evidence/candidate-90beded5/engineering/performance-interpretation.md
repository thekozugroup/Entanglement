# Ordinary signed workload measurements

1 of seven routes passed both limits against the preceding a5728c23 engineering release. Each route required candidate median p95 at most 1.05 times the comparator and candidate median rate at least 0.95 times the comparator. The production operator has yet to approve a baseline. [Registered plan](plan.md) · [Primary observations](../performance.json)

| Route | Median p95 ratio | Median rate ratio | Trial 1 p95 / rate | Trial 2 p95 / rate | Trial 3 p95 / rate | Both limits |
|---|---:|---:|---:|---:|---:|---|
| local / 1 | 1.353 | 0.829 | 1.007 / 0.964 | 1.420 / 0.708 | 1.109 / 0.967 | Miss |
| local / 4 | 1.179 | 0.947 | 0.924 / 1.031 | 1.197 / 0.947 | 1.031 / 0.951 | Miss |
| remote / 1 | 1.082 | 0.957 | 0.887 / 1.008 | 1.137 / 0.972 | 1.554 / 0.927 | Miss |
| remote / 4 | 1.442 | 0.851 | 1.458 / 0.822 | 1.198 / 0.905 | 2.591 / 0.543 | Miss |
| image local | 1.060 | 0.966 | 0.742 / 1.103 | 1.443 / 0.773 | 1.060 / 0.985 | Miss |
| image one_remote | 1.174 | 0.851 | 1.031 / 0.996 | 1.639 / 0.680 | 1.233 / 0.964 | Miss |
| image three_remote | 0.986 | 0.973 | 0.959 / 0.990 | 1.555 / 0.731 | 0.986 / 0.974 | Pass |

Greeting trials used adjacent fresh clusters in AB, BA and AB order. Each arm checked 1,024 signed responses per route. Image trials compared the same within-version ordinal across three repetitions per route. Each version used one separately created cluster, with the candidate suite first. The prescribed verdict divides three-trial medians from the two versions. Trial columns retain the individual ratios.

Both image batches produced the same ordered SHA-256 digest of all 24 outputs, `cc355f03ea0cd50472e113b2b92509bca56458ad637152b33f5fbb28eeac441b`. The candidate and comparator obtained three-worker versus one-worker rates of 1.003× and 0.877× on the shared host. Four concurrent clients shared its CPU allocation.

The host monitor captured 38 samples. Known build processes observed were none. Cgroup throttled time increased by 272318 µs from the pre-series to post-series snapshots. The entire series used one shared Linux VM. Image timing includes other work within the same cluster. These three-trial comparisons can fluctuate with host load and trial order.
