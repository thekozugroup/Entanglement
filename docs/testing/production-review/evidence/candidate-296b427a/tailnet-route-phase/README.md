# Tailscale worker-service recovery on 296b427a

An authenticated worker became usable about 28 seconds after the two devices could again exchange UDP. Two fixed-phase restarts reproduced this on the canonical release. In each case, the coordinator had sampled the worker offline during its 14-second outage. Tailscale subsequently reported the worker online within 0.6 seconds of the first adjacent UDP response, and the worker’s scheduler socket was bound within 2.4 seconds. The coordinator kept rejecting work locally until its next scheduled status read.

| Restart | Stop offset after healthy coordinator read | Coordinator consumed Offline during outage | Worker port 7443 first observed rebound | Verified signed work after 7444 recovered | Pre-dial missing-route errors |
|---|---:|:---:|---:|---:|---:|
| A1 | 1 s | No | 7.508 s | 10.168 s | 0 |
| B1 | 21 s | No | 0.520 s | 1.112 s | 0 |
| B2 | 21 s | No | 2.343 s | 3.132 s | 0 |
| A2 | 1 s | No | 2.350 s | 3.165 s | 0 |
| C1 | 17 s | Yes | 2.322 s | 28.244 s | 84 |
| C2 | 17 s | Yes | 2.358 s | 28.004 s | 83 |

C1 and C2 were preregistered after the first four trials showed that Tailscale took approximately 11 seconds to mark the remote worker offline. The coordinator’s 21-second-offset trials sampled about 9 seconds into the outage, while it still saw the worker online. All six outcomes are retained. The four controls ran in one fixture and the two follow-ups in a fresh paired fixture on the same x86_64 Linux host. These are mechanism tests with two real devices in Linux network namespaces.

In C1 and C2, the coordinator’s own local Tailscale API independently showed the correct worker online at +0.207 s and +0.533 s. The status CLI actually invoked by the coordinator daemon next supplied that fact at +27.893 s and +27.803 s. The last pre-dial denials were +27.848 s and +27.670 s. The ordinary dispatch that followed each fresh snapshot verified the expected peer and nonce. The public RPC exposes active transports; the private route map is inferred from the consumed status, the source path, and the specific pre-dial failure. Kernel socket presence alone does not demonstrate authenticated service. Both worker and coordinator application processes and identities remained the same through each successful restart assertion.

The 30-second poll updates a Tailscale-only coordinator whose own listener remains healthy. It replaces the route set using only explicitly mapped, currently online peers. Address resolution can also refuse a peer when local trust fails. The test never modified trust during the six timing phases. The repeated missing-address errors occurred on the coordinator before QUIC transmission. A1 illustrates a separate contributor when the coordinator retains its route. Its first request eventually succeeded and the worker socket reappeared several seconds into that request. [Coordinator route filtering](../../../../../../crates/entangle-bin/src/remote/routes.rs) · [Supervisor status monitoring](../../../../../../crates/entangle-bin/src/remote/routes/supervisor.rs) · [Scheduler resolution](../../../../../../crates/entangle-scheduler/src/remote.rs)

## Controls and limits

The four-arm fixture exited zero including the authenticated revoke/repair and graceful-shutdown controls. The two-arm follow-up exited one **after both timed restart assertions completed**. In that fixture’s separate final revocation phase, all 44 attempts returned a placement error indicating there were no live workers. Worker invocation counters stayed unchanged, but the expected authenticated refusal was never observed within 45 seconds. This is a failed follow-up control. Its raw result file is empty because the upstream harness serializes the summary only after all assertions pass. The preserved per-attempt stream, consumed status samples, worker socket observations, traceback, and enter/exit source digests retain the completed measurements. The post-phase failure’s cause remains unresolved.

The architecture’s under-ten-second mesh reconvergence target accompanies application daemon restart and upgrade. The frozen transport-partition gate asks for bounded recovery on physically distinct machines. Service-restart latency here is an operational comparison. Physical two-host and other-platform results remain open. [Architecture](../../../../../architecture.md) · [Frozen rubric](../../../rubric-v1.json)

## Reproduction and provenance

The manifest records each original file’s SHA-256 and its stored SHA-256. Logs and event streams use deterministic gzip. Each harness directory includes its instrumentation, generator, and frozen-source derivative. To recreate a scratch harness, copy a harness directory to a writable temporary directory, run its stage.py, provide verified canonical ELFs and the matching WASI fixture at the paths documented in run.py, then run run.py. The fixture requires the preloaded Headscale, Tailscale, and Python images, rootless Docker with delegated TUN inside its own network namespace, and the frozen checkout. It creates a disposable internal bridge without host port publication. Collection retained only projected local status, synthetic public test-peer data, ordinary test nonces and service events. Neither fixture left containers behind.

[Manifest](manifest.json) · [Four-arm receipt](retained-route/receipt.json) · [Two-arm receipt](sampled-offline/receipt.json) · [Two-arm preregistration](sampled-offline/harness/preregister.json)
