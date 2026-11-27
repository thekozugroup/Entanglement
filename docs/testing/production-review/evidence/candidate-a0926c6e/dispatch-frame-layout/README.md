# One-shot dispatch and Tokio task layout

The production submitter's one-shot future increased by 32 bytes between bb70a619 and a0926c6e. The size and alignment of the Tokio allocation for an accepted Unix socket connection stayed at 4,224 and 128 bytes. Both connection tasks fit below Tokio 1.54.1's 16,384-byte release boxing threshold.

| Compiled type | bb70 bytes | a092 bytes | Alignment |
|---|---:|---:|---:|
| One-shot entry used by the daemon | 2,688 | 2,720 | 16 |
| Public RPC dispatch | 3,712 | 3,744 | 16 |
| Private serve_client | 3,968 | 4,000 | 16 |
| Async block passed to Tokio spawn | 4,048 | 4,080 | 16 |
| Tokio Cell containing the connection task | 4,224 | 4,224 | 128 |

The successor's convenience dispatch_one_shot wrapper measures 2,992 bytes. The daemon calls dispatch_one_shot_with_refresh directly. The release Tokio runtime boxes oversized futures before inserting them into a task cell. Box::new(Cell { ... }) in tokio/src/runtime/task/core.rs receives identical sized and aligned types in both revisions. Both compiled Tokio scheduler flavors emitted the same connection-cell layout.

The stable Rust probe takes public method items, infers each exact returned future type, and emits LLVM constants for its size and alignment. The compiler layout dump for the unmodified private block at crates/entangle-bin/src/server.rs:258 identifies the spawned future and the enclosing Tokio cell directly. The source paths identify the two pinned checkouts. The full compiler dumps remain in the ephemeral scratch area with their digests in versions.json. The four compact outputs preserve all relevant type rows. No daemon execution or linked artifacts were required.

To reproduce on this review host, copy probe.py, connection.py and probe.rs to /tmp/entangle-demand-qa/frame-probe. With pristine relevant crates in the scratch bb70 checkout and main a092 checkout, execute python3 probe.py > probe.log and then python3 connection.py. The scripts use the reviewed release dependency fingerprints and shared unchanged compiled dependencies. They compile both revisions' two changed crates into scratch. The second pass enables the compiler's type-layout diagnostic, producing baseline/compiler-layout.log and candidate/compiler-layout.log. The primary and supplemental measurements stand independently. The type audit identifies a small frame change and rules out a change to this allocator request. It does not measure cycles spent moving or polling those frames.

On the seven primary routes, a successful first placement still takes one worker-pool selection and one reservation. With the positive CPU request used in these workloads the new refresh future is awaited only after a pre-execution miss. The active dispatcher borrows the optional refresh hook from daemon state. The periodic authenticated capability poll now maintains a per-peer query map. No per-request trace counted refreshes in those timing trials. Their observations include shared-machine variability, and the controls produced different directions across independent local-image cohorts. The source and layout analysis does not establish a causal hot-path regression suitable for a product patch.
