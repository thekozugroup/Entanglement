# Counterbalanced local and one-remote image observations

The first fixed series completed 20 of 20 fresh arms and 10 of 10 matched pairs in 153.9 seconds. Each completed arm rendered 144 verified PNGs, spread across three batches of 24 inputs on each of two routes. Four clients ran concurrently. Every completed arm checks the same input hashes and ordered PNG outputs as the primary experiment. [Plan](plan.md) · [All raw trials](raw/)

| Route | Measure | B/A median [range] | Identical A Y/X median [range] | A-first / B-first medians | Adverse B/A | Criterion |
|---|---|---|---|---|---:|---|
| local | p95_ms | 0.775 [0.692–1.114] | 0.923 [0.744–1.378] | 0.770 / 0.779 | 1/6 | Open |
| local | images_s | 1.154 [0.898–1.407] | 0.983 [0.938–1.012] | 1.336 / 0.998 | 1/6 | Open |
| one_remote | p95_ms | 1.067 [0.873–1.365] | 0.883 [0.742–1.002] | 1.064 / 1.069 | 4/6 | Open |
| one_remote | images_s | 1.059 [0.849–1.217] | 1.056 [0.874–1.131] | 1.075 / 1.058 | 2/6 | Open |

B/A compares f499e3ed with a5728c23. Y/X uses the identical a5728c23 executable in two fresh clusters. Each arm value is the median of three trial p95 or rate values. Ranges show the individual paired extrema, and adverse counts denote B/A past 1.05 for p95 or below 0.95 for rate. The preregistration required all six adverse B/A pairs, stable same-daemon controls and an absence of observed competing compilers.

Sampler observations 140. Active compiler names were none. The cgroup gained 2.460 s throttled time. The independent seven-route primary grade remains four of seven under the original ratio-of-medians limits. [Ordered pair data](results.json) · [Source and binary identities](receipt.json)
