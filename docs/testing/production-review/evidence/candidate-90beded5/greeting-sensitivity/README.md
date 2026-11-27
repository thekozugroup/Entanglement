# Supplemental signed greeting replication

Six scheduled blocks completed in 131.8 seconds. Each block contained one A-first pair, one B-first pair and one pair of identical A daemons. A is the previous a5728c23 release, and B is the 90beded5 release. Each route has 12 B/A and six identical-daemon Y/X comparisons. All 147,456 measured replies passed the driver’s peer and output checks. Configuration order and warmup match the primary series. The 95% intervals use 20,000 resamples of the six matched blocks. The primary seven-route grade remains 1/7. [Registered plan](plan.md) · [All arm measurements](samples.jsonl) · [Observed CPU](cpu-samples.jsonl)

| Route | Metric | B/A median [95% interval] | Y/X control [95% interval] | A-first / B-first | Slower candidate pairs | Diagnostic criterion |
|---|---|---|---|---|---:|---|
| local / 1 | p95_ms | 1.249 [0.961–1.349] | 1.198 [0.939–2.892] | 1.257 / 1.218 | 9/12 | Open |
| local / 1 | rate | 0.847 [0.748–1.050] | 0.867 [0.691–1.105] | 0.861 / 0.827 | 9/12 | Open |
| local / 4 | p95_ms | 1.025 [0.935–1.197] | 0.833 [0.745–2.757] | 1.104 / 0.935 | 7/12 | Open |
| local / 4 | rate | 0.969 [0.743–1.119] | 1.039 [0.671–1.211] | 0.919 / 1.122 | 6/12 | Open |
| remote / 1 | p95_ms | 0.964 [0.926–1.010] | 1.002 [0.664–1.086] | 0.926 / 0.998 | 4/12 | Open |
| remote / 1 | rate | 0.988 [0.974–1.029] | 0.998 [0.957–1.144] | 1.012 / 0.984 | 7/12 | Open |
| remote / 4 | p95_ms | 1.002 [0.884–1.070] | 1.109 [0.618–1.293] | 0.997 / 1.034 | 6/12 | Open |
| remote / 4 | rate | 1.012 [0.980–1.047] | 0.957 [0.941–1.844] | 1.000 / 1.012 | 5/12 | Open |

Values above 1 indicate a higher candidate latency or throughput, as labeled. The control uses the same executable in both positions. For a metric to meet the diagnostic criterion, its B/A interval had to lie wholly beyond the engineering bound, the two build-order medians had to show the adverse direction, and the A/A interval had to include 1 with its median within 5% of parity. With six blocks these intervals are sensitivity estimates.

The CPU monitor collected 119 samples. Active compilers observed were none. The total cgroup throttled duration across measured arms increased by 0.068 s. Kernel CPU pressure stall information was unavailable in this VM. The raw samples retain arm and route boundaries, child CPU time, context switches and additional cgroup counters. [Full analysis](results.json) · [Primary chronology and binary layout](primary-analysis.md)

## Interpretation

None of the eight route/metric comparisons met the registered adverse-effect criterion. Remote/4 supplied the most consistent warning in the primary series. Here only six of 12 paired candidate tails were slower. Its median p95 ratio was 1.002 (interval 0.884–1.070) and rate ratio 1.012 (0.980–1.047). The identical-daemon p95 control was 1.109, with substantial dispersion. Local/1 retained an adverse point estimate in both build orders, with nine of 12 pairs showing a higher candidate tail. Its paired intervals include parity, and the identical-daemon control also had a 1.198 median p95 ratio and 0.867 rate ratio. Local/4 changed tail direction with build order. For remote/1 the B/A median tail was lower than parity.

Median child CPU across a full four-route arm was 6.585 s for A and 6.527 s for B; medians for identical A controls X and Y were 6.446 s and 6.705 s. These aggregate values include setup, both daemons and the client. They cannot identify individual queue or network delays. Three-trial image measurements remain a separate finding. This replication and the inspected source do not identify a causal dispatch change or justify a product modification. The six original misses remain in the published primary table.
