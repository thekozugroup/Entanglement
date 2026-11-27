# Three missed primary p95 limits

The 4/7 score uses the ratio of independently computed three-trial medians. Here each image cell retains the corresponding within-cluster trial ordinal. Absolute UTC was recorded at suite launch, and each image trial records its own wall duration. The driver does not report absolute UTC at individual image completion. [Primary](../performance.json) · [Raw logs](../engineering/raw/)

| Route / ordinal | Comparator p95 ms | Candidate p95 ms | p95 ratio | Rate ratio | Candidate slower requests | Median same-input latency ratio | p95 input index A / B |
|---|---:|---:|---:|---:|---:|---:|---|
| local / 1 | 147.876 | 192.996 | 1.305 | 0.928 | 11/24 | 0.989 | 15 / 5 |
| local / 2 | 124.676 | 157.500 | 1.263 | 0.932 | 12/24 | 1.006 | 8 / 3 |
| local / 3 | 162.500 | 149.666 | 0.921 | 1.172 | 8/24 | 0.895 | 15 / 20 |
| one_remote / 1 | 167.114 | 159.895 | 0.957 | 1.179 | 8/24 | 0.767 | 10 / 17 |
| one_remote / 2 | 148.046 | 161.513 | 1.091 | 1.034 | 11/24 | 0.940 | 8 / 12 |
| one_remote / 3 | 136.420 | 119.280 | 0.874 | 1.038 | 11/24 | 0.980 | 10 / 0 |

Each batch has 24 unique images and four closed-loop clients. The empirical p95 is the 23rd ordered image latency. Candidate p95 need not correspond to the same image as the comparator’s p95; the index column is zero-based. Individual image latencies within an arm share worker and sequence context. Treat these descriptive counts as correlated observations.

The image suites ran their nine rotated batches candidate first and comparator second. Local images had two adverse ordinal p95 ratios followed by an improvement. One-remote images had one adverse ordinal p95 ratio and two improvements. All image rate medians exceeded comparator rates. No new operation was found in the warm signed dispatch or static-loopback route on this source. The preregistered crossover with same-daemon controls can test whether differences recur independently of the single cluster/order.

| Single-client remote greeting pair | Order | Comparator p95 ms | Candidate p95 ms | p95 ratio | Rate ratio |
|---:|---|---:|---:|---:|---:|
| 1 | AB | 2.808 | 2.852 | 1.016 | 0.738 |
| 2 | BA | 2.452 | 2.813 | 1.147 | 0.899 |
| 3 | AB | 2.646 | 2.470 | 0.933 | 1.080 |

One greeting pair exceeded the 1.05 tail limit. Neither its direction nor its magnitude is consistent in both baseline-first pairs. The previous 90beded5 diagnostic’s 12 B/A and six A/A pairs are historical evidence about instrument variability. That diagnostic uses a different daemon and supplies no f499e3ed grade or proof of equivalence. [Separate earlier source](../../candidate-90beded5/greeting-sensitivity/README.md)
