# Rust RPC client isolation

The stock and modified Rust clients dispatched the same signed jobs against the frozen daemon. The modified client serializes the typed request directly and moves the owned result into the typed decoder. Both clients used the original JSON-RPC methods, identifiers, errors and framing. Each of six balanced, alternating pairs included 1,024 sequential greetings and 48 image resizes with four concurrent callers. All 12,288 greetings and 576 PNGs matched their expected bytes and worker IDs. The intrinsic image corpus, signed components and Pillow checks matched the candidate diagnostic.

| Workload | Measure | Stock | Modified | Change |
|---|---|---:|---:|---:|
| hello | p50_ms | 0.164 | 0.163 | -1.2% |
| hello | p95_ms | 0.284 | 0.295 | +4.1% |
| hello | rate | 5290.307 | 5160.419 | -2.5% |
| hello | cpu_ms_per_job | 0.034 | 0.029 | -14.3% |
| image | p50_ms | 105.863 | 108.389 | +2.4% |
| image | p95_ms | 224.793 | 192.805 | -14.2% |
| image | rate | 30.639 | 32.176 | +5.0% |
| image | cpu_ms_per_job | 10.938 | 4.583 | -58.1% |

The preregistered limits required at least 5% lower image p95, at least 20% less client CPU per image, image throughput within 5% of stock or higher, and both tiny greeting p95 and throughput within 5% of stock or better. 5 of 5 limits passed. 20 RPC tests and doctests passed with the isolated patch. These tests reuse one warm worker, with request construction outside the timings. The frozen daemon qualification used different client and process lifetimes, and its original grade stands. [Raw pairs, exact patch, drivers and CPU samples](rpc-client-isolation.json)
