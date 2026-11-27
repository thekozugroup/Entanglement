# Ordinary dispatch performance diagnosis

The primary release comparison met the engineering limits on three of seven routes. In a separately preregistered diagnostic all four primary misses also exceeded a reference limit when summarized by median paired ratio. The clearest recurring observations were higher local-image and four-client remote-greeting p95. Four pairs per comparison, large movements under identical binaries, and a substantial build-order effect on single-client local greetings limit attribution. [Primary result](../performance.json) · [Preregistered diagnostic](plan.md) · [Paired calculations](paired-summary.json)

| Route | Primary candidate/baseline p95 / rate | Follow-up candidate/baseline p95 / rate | Follow-up identical daemon labels p95 / rate | A/B pairs satisfying both reference limits |
|---|---:|---:|---:|---:|
| Local images | 1.110 / 0.975 | 1.138 / 0.928 | 0.841 / 1.004 | 1/4 |
| One remote image worker | 0.873 / 1.200 | 1.041 / 1.043 | 0.992 / 1.042 | 2/4 |
| Three remote image workers | 0.938 / 1.005 | 0.970 / 1.028 | 1.075 / 1.001 | 3/4 |
| Local greetings, one client | 1.061 / 0.916 | 1.399 / 0.832 | 0.966 / 1.057 | 2/4 |
| Local greetings, four clients | 1.092 / 0.926 | 1.115 / 0.927 | 1.015 / 1.060 | 1/4 |
| Remote greetings, one client | 0.839 / 1.086 | 1.252 / 0.945 | 1.253 / 0.938 | 0/4 |
| Remote greetings, four clients | 1.129 / 0.941 | 1.127 / 0.960 | 0.732 / 1.072 | 1/4 |

The primary statistic is the ratio of the two three-trial medians. Follow-up values are medians of four adjacent fresh-cluster ratios. Every follow-up arm checked 4,096 signed greeting responses and 216 image outputs. Across 16 arms this is 65,536 greetings and 3,456 images. Each of the 16 clusters used the same CLI, image corpus and signed component, with the monitored workload restricted to the same local VM. The 212.46 s run saw 105 throttled cgroup periods totaling 1.85 s. A one-second process monitor recorded one Docker daemon observation at 0.18 CPU cores and observed no compiler above its 0.15-core reporting threshold. [All observations and CPU samples](results.json) · [Driver](run.py)

## What the comparisons distinguish

- Local-image p95 exceeded the limit in three of four build pairs and both order medians (1.064 when baseline ran first, 1.138 when candidate ran first). At four remote greeting clients, three of four pairs exceeded it and both order medians were also high (1.060 and 1.127). Both are recurring engineering concerns. Identical candidate binaries under different labels also produced sizable shifts in the favorable direction on those two routes, with p95 medians of 0.841 and 0.732. These controls demonstrate temporal variation on the same routes.
- Single-client local greeting p95 followed build order. Both baseline-first pairs were high (1.818, 2.239) and both candidate-first pairs were below 1.0 (0.980, 0.814). Four-client local greeting p95 also missed on three build pairs, but identical-daemon p95 ratios across its four pairs ranged from 0.340 to 2.977. The follow-up remote single-client slowdown was almost identical in the same-daemon control. [Individual ratios and order medians](paired-summary.json)
- Previous a0926c6e and c19ef758 comparisons used the same two daemon hashes and greeting driver. Between these windows the local single-client p95 ratio changed from 0.800 to 1.235, remote four-client p95 from 0.900 to 1.124, and local-image p95 from 1.369 to 0.997. Four-client local greetings had elevated p95 in both prior windows, against a different pair of builds. An earlier 761485d7 identical-daemon control also missed local-image and three-remote-image limits. [a0926c6e](../../candidate-a0926c6e/performance.json) · [c19ef758](../../candidate-c19ef758/performance.json) · [761485d7 identical control](../../candidate-761485d7/performance-controls/identical.json)

## Changed implementation

The Rust chooser for these successful routes is unchanged. Typed remote rejection data is formatted on the error path. Ordinary components retain the PluginPre clone and skip libtest capture, identity validation and result stamping. The new libtest variant does enlarge the shared LoadedPlugin enum handle. Using Cargo dependency fingerprints rooted at both exact archived ELF hashes, size_of compiled to **144 bytes for c19ef758 and 208 bytes for 296b427a**. Kernel invocation clones this handle under its registry read. This size measurement establishes the layout change. Copies executed for the ordinary variant and any effect on call latency remain unmeasured. [Layout receipt](handle-layout.json) · [Host](../../../../../../crates/entangle-host/src/plugin.rs) · [Kernel](../../../../../../crates/entangle-runtime/src/kernel.rs) · [RPC error handling](../../../../../../crates/entangle-bin/src/methods.rs)

A narrow follow-up could move the optional identity into storage exclusive to the libtest variant, verify the ordinary handle size, and measure that single alteration on the repeatedly affected routes. Neither comparison supplies an operator-approved production baseline or estimates for physical workload hardware.
