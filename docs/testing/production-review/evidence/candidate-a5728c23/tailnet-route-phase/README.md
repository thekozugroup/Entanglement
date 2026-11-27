# Recovery after the coordinator sampled a Tailscale worker offline

On release a5728c23 the same paired worker returned verified signed output **3.410 s and 2.598 s** after its Tailscale service recovered sufficiently to echo a nonce over UDP. The two matched 296b427a trials took 28.244 s and 28.004 s. The release archive, Headscale/Tailscale image IDs, exact source, and raw monotonic observations are bound in the [manifest](manifest.json).

| Fixed-phase trial | First independent Online indication after UDP echo | Coordinator receives Online | Worker UDP socket first observed rebound | First ordinary request | First verified signed output |
|---|---:|---:|---:|---|---:|
| C1, stock | +0.207 s | +27.893 s | +2.322 s | Pre-dial rejection; 84 distinct failed requests | +28.244 s |
| C1, successor | −0.119 s | +0.354 s | +2.294 s | Succeeded on first submission | +3.410 s |
| C2, stock | +0.533 s | +27.803 s | +2.358 s | Pre-dial rejection; 83 distinct failed requests | +28.004 s |
| C2, successor | +0.602 s | +1.534 s | +2.384 s | Pre-dial rejection; three distinct failed requests | +2.598 s |

In each matched trial, the actual coordinator process consumed an Offline status. C2's first expedited read still returned Offline at +0.267 s. The next returned Online at +1.534 s. The same coordinator UDP socket stayed bound. The harness verified the selected peer and exact nonce and counted exactly one new guest invocation per recovery. Its CLI attempts are separate user submissions with different nonces. The original end-of-test revocation check then observed authenticated E0403, repaired trust, verified signed work, and both applications exited cleanly. [Primary receipt](two-phase/receipt.json) · [Per-arm timings](two-phase/phase-analysis.json)

In a separate fresh topology the coordinator initially missed on a newly hot-loaded, worker-only signed marker plugin. A subsequent ordinary request returned its expected nonce from the intended peer, proving that the coordinator had just received the worker’s new compatible inventory. During the following link outage the worker revoked the coordinator. After reconnection, the coordinator returned structured remote code `not-authorized` and E0403 for the original plugin, 17.924 s after marker load. The worker invocation count stayed at two during that request. Restoring trust enabled one new verified invocation. Both processes exited cleanly. [Marker protocol](PROTOCOL.md) · [Marker receipt](fresh-marker/receipt.json) · [Raw marker observations](fresh-marker/events.jsonl.gz)

The normalized comparison links all six stock phase trials, preserves their whole-fixture verdicts, and includes both successor repeats and the independent marker. The stock follow-up's later revocation control returned 44 placement errors and failed its explicit worker-denial assertion. Both successor fixtures exited zero. Each immutable raw stream was compressed with gzip. The manifest records raw and stored SHA-256 for independent verification. The measurements used private disposable Linux network namespaces on one physical x86_64 host. They show the effect of a refresh on a still-trusted, explicitly mapped worker. Other operating systems, physical links, and recovery-time distributions require additional measurements. [Normalized comparison](comparison.json) · [Six-arm stock results](../../candidate-296b427a/tailnet-route-phase/README.md)

The complete six-arm stock raw recordings and original receipts are also packaged locally for offline review. [Stock raw recordings](stock-six-raw.tar.gz)
