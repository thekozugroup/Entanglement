# Offline operator timing for mesh tailnet link

The optimized 90beded5 release completed all 12 independent first links and 12 identical repeats. Every invocation issued one offline status query. All first links persisted a new mapping; every repeat preserved config bytes, inode and mtime. Every trust-store digest stayed unchanged. The first-link wall time median was 7.596 ms and p95 was 11.705 ms. Repeat median was 6.234 ms and p95 was 11.715 ms. The separately launched fixture took a median 2.941 ms and p95 3.848 ms. Each p95 is the maximum of 12 measurements. This was an operator-side CLI fixture using the canonical ELF, with no live Tailscale daemon. [Frozen source and logs](release-receipt.json) · [Optimized samples and metadata](release/receipt.json) · [Individual calls](release/commands.jsonl)

## Preliminary development sample

The controlled development CLI run used one fixed, already trusted disposable peer, a three-section config in a temporary HOME and one visible IPv4 node in an offline Tailscale status fixture. Each of twelve independent profiles received its first mapping and then an identical repeat. All 24 returned JSON with the exact signed peer fingerprint, key, stable node ID and port. Each command launched precisely one status helper. `changed` was true on every first invocation, and false on every repeat. Trust bytes stayed identical. First links replaced the config; repeats preserved its contents, inode and modification time. [Protocol](preregistration.md) · [Call-path review](source-findings.md) · [Raw operator commands](development/commands.jsonl)

| Development CLI measurement (ms) | Samples | Median | Nearest-rank p95 |
|---|---:|---:|---:|
| First link, end-to-end | 12 | 12.86 | 14.69 |
| Idempotent repeat, end-to-end | 12 | 10.42 | 27.58 |
| Offline status helper only, separate control | 12 | 3.27 | 3.56 |

The p95 is the maximum of twelve values. These are operator process wall times, including subprocess startup and local filesystem work. The helper merely prints 377 bytes of controlled JSON; its separately measured latency is not subtracted and does not predict the latency of a running Tailscale daemon. The deterministic configuration assertions and query counts are independent of timings. [Binary, runner, source, process metadata, raw samples and fixture hashes](development/receipt.json)
