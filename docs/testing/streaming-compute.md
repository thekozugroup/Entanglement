# Signed streaming compute

Start two paired daemons with a working scheduler route. Load a signed plugin on the worker and wait for its capability advertisement. The CLI chooses an eligible worker and writes each verified application chunk to stdout. It prints the executor peer ID on stderr.

```sh
entangle compute stream "$PLUGIN_ID" --allow "$WORKER_PEER_ID" --input "$(cat prompt.txt)" --chunk-bytes 65536 --credit-window 4 --total-bytes 1048576
```

A component exposing `entangle:plugin/stream-plugin@0.1.0` yields progressive output via `yield-chunk`. Its call resumes when the scheduler has credit and writes the chunk to the authenticated QUIC stream. The stream-lines sample yields each input line individually. For components exporting only `plugin.run`, the worker first executes the invocation and divides the completed output into chunks.

The scheduler checks both chunk and cumulative limits at each endpoint. It signs each chunk using the worker's Ed25519 identity. The detached signature covers a domain separator, task UUID, sequence, executor timestamp and SHA-256 payload digest. The submitter verifies the expected peer, sequence and signature before releasing a chunk. `TrustedExecutor` limits worker selection to its allowlist. Replicated integrity policies are rejected before route lookup.

Applications using the local daemon RPC can open a session with `compute/stream/open`, pull one verified event at a time with `compute/stream/read`, and cancel with `compute/stream/close`. Chunk events include sequence, timestamp, signature and payload. A read replenishes one credit for the next chunk. The CLI uses the keep-signed partial-output policy and may have written verified partial output when a later chunk or connection fails. Consumers that require atomic output can spool chunks and commit them after `Finished`.

A streaming session sends heartbeats every five seconds, including during credit exhaustion. Three unanswered intervals close the stream with `PeerLost`. The worker records `StalledEvent` and increments `entangle_scheduler_streams_stalled_total` after the configured credit timeout. A new credit resumes a stalled stream. On cancellation the worker drops its producer. The local RPC bounds concurrent sessions at 32 and removes sessions abandoned for a minute. Each initial request accepts at most 1 MiB of input. Negotiated ceilings are 1 MiB per chunk and 256 MiB cumulative.

The scheduler's real loopback QUIC tests execute a signed Wasm guest, withhold credits, drop heartbeats and verify attribution. The daemon integration also checks detached signatures returned through the ordinary local RPC.

```sh
cargo test --locked -p entangle-scheduler --test remote_dispatch stream_acceptance
cargo test --locked -p entangle-bin --test daemon_compute schedules_on_another_daemon_and_enforces_live_revocation
```
