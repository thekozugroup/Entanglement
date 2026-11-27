# Local regression diagnostic

The frozen comparison reported a 34.8% local single-greeting p95 increase and a 48.0% local image p95 increase. A six-pair follow-up on the same release binaries found no individual layer with a p95 regression that met all three preregistered criteria: at least 10%, at least 10 µs and worse in at least four of six pairs. The frozen results and their failed score remain in [performance.md](performance.md).

| Operation | Baseline p95 ms | Candidate p95 ms | Change | Pairs with higher candidate p95 | Throughput change | Mean guest wall time change |
|---|---:|---:|---:|---:|---:|---:|
| version | 0.143 | 0.136 | -4.5% | 3/6 | +5.2% | — |
| hello direct | 0.306 | 0.248 | -18.9% | 3/6 | +10.2% | -6.5% |
| hello scheduled | 0.290 | 0.243 | -16.3% | 2/6 | +8.5% | -11.0% |
| image direct | 156.878 | 150.412 | -4.1% | 2/6 | -3.9% | +7.9% |
| image scheduled | 135.437 | 160.400 | +18.4% | 3/6 | +10.0% | -20.2% |

Each binary ran one separately initialized daemon with the same signed hello-pong and catalog image-resize packages loaded throughout. Both daemons used four Tokio and Rayon threads. Requests went over fresh Unix sockets and included existing production authorizations. Six alternating pairs rotated the operation order. Each block ran 384 sequential calls for each small operation and 24 JPEG resizes per image operation across four concurrent clients. Each image used the original corpus and its independent Pillow reference. The client verified all output digests and scheduled peer identities outside the timed interval. Guest time came from the per-daemon invocation histogram, excluding the RPC and lifecycle work. The original frozen Rust greeting driver and fresh-cluster image comparisons used different process lifetimes and client implementations from this diagnostic.

The scheduled image p95 was higher in three of six paired blocks. Across the six blocks, median throughput rose 10.0% and median worker CPU per image fell 12.8%. The candidate used a median of 3.26 cores during scheduled image batches, compared with 3.47 for the baseline. The baseline and candidate both showed substantial within-build variation in guest time and available concurrency. All 26 one-second host samples were free of live compilers during the diagnostic. The process monitor does not measure unrelated hypervisor load.

Source inspection found no new ordinary local trust-file read or signature verification. The candidate’s entire JSON-RPC dispatch future occupies 3,472 bytes on this release toolchain. This diagnostic does not establish the cause of the original regression, and the observed image tail variation remains a production qualification issue. [Per-block results and live CPU samples](local-regression-diagnostic.json)
