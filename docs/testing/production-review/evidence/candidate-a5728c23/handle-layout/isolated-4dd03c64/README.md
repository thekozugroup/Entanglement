# Compact WASI test command handle

The Linux handle shrank from 208 to 136 bytes. This fixed series did not establish faster ordinary dispatch. The local-image rate fell 2.9% by median paired ratio and four-client remote greeting rate rose 6.5%. All four latency and rate intervals for these two preregistered routes include equal performance.

The private change is 4dd03c6471394d62a0d3d4b5ea8479165ddb87f2, source sha256:81e0cb3a860d3dc5f3ad1405940811362512774bcbc64e1b45ce98e19974b454. Its parent is 296b427a3bb2d60615ea3c56b9779f97039c6e24. The private optimized daemon SHA-256 is 1b8ea0af4ca7f2c3c05be776ba359cccd0e3676538ebb7c7cd820d0e72b6d6bf. Both builds used the same locked release command. All arms used the same verified 296b CLI for setup. The c19 archive is included for layout provenance. [Private build](release-build.json) · [296b archive manifest](296b427a-linux-archive.json) · [c19 archive manifest](c19ef758-linux-archive.json)

## Observed results

| Preregistered route | Compact/base p95 (descriptive 95% interval) | Compact/base throughput (interval) | Same-base p95 / throughput | Pairs with lower p95 / higher throughput |
|---|---:|---:|---:|---:|
| Local image | 0.972 (0.874–1.158) | 0.971 (0.930–1.057) | 1.054 / 0.964 | 6/8 / 3/8 |
| Four-client remote greeting | 0.914 (0.621–1.271) | 1.065 (0.913–1.228) | 0.892 / 1.039 | 5/8 / 6/8 |

The four-client remote result depended on order. The p95 median was 0.781 when baseline ran first and 1.026 when compact ran first. The corresponding throughput medians were 1.149 and 0.959. Each targeted median sits within the previous engineering reference bounds, with material uncertainty in eight independent matched pairs. No route triggered another timing run. [All paired observations and order medians](paired-summary.json)

| Other routes, descriptive | Compact/base p95 / throughput | Same-base p95 / throughput |
|---|---:|---:|
| Local greeting, one client | 0.935 / 1.039 | 0.913 / 1.057 |
| Local greeting, four clients | 0.614 / 1.226 | 0.890 / 1.136 |
| Remote greeting, one client | 1.093 / 1.017 | 0.848 / 1.021 |
| One remote image worker | 0.935 / 0.980 | 1.100 / 0.947 |
| Three remote image workers | 0.994 / 0.987 | 1.007 / 1.011 |

The 24-arm series ran from 09:04:58 to 09:10:13 UTC on November 27, 2026. Eight compact/base pairs and four separately interleaved same-base pairs ran in four randomized blocks. Each block included both build orders. The eight-pair percentile intervals resample entire matched pairs, with 20,000 draws per metric. The driver validated 98,304 greeting calls and 5,184 independently checked images. The shared Linux VM had five visible CPUs and a four-core quota. The cgroup recorded 190 throttled periods and 3.741 s throttled CPU time. No compiler exceeded the monitor's 0.15-core reporting threshold. [Preregistration and exact schedule](preregistration.json) · [Complete observations and CPU samples, gzip](results.json.gz)

## Evidence and scope

The frozen and private Wasmtime host metadata came from the Cargo fingerprint graph rooted at each exact optimized ELF. The size probe produced 144 bytes for c19, 208 bytes for 296b and 136 bytes for 4dd. The change shares a command binding and signed identity in one allocation after a successful WASI command load. Clones share it. The ordinary WIT plugin retains its in-place compiled handle. Signed affinity and terminal rejection regressions, standalone embedding, independent ordinary concurrent calls after original handle drop, 142 Rust tests, 28 Python tests and strict host Clippy were checked. One Rust test was already ignored. [Release-bound layout](release-layout.json) · [Focused checks](focused-verification.json)

Run `python3 -B verify-observations.py` here to recheck the archived 24 arms, guest-verified output digest lists, per-arm medians, all pair ratios and total counts without the network, binaries or source tree. The compressed arm file retains all individual image latencies and greeting summaries. It includes the digests of each original log. The evidence contains no executables, private keys, packaged plugins, source photos, or image output. [Structured arms](arm-observations.json.gz) · [Measurement driver](measure.py) · [Summary driver](summarize.py)

The measurement driver records the private lab paths used during the run. A separate `verify-final-layout.py` accepts explicit checkout, release target, canonical archive and manifest inputs for scoring a different integrated release from its own graph. This isolated two-commit comparison cannot establish the performance of an integrated transport change, a physical network, or an operator-approved production baseline.
