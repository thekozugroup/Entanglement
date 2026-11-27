# Offline operator timing for mesh tailnet link

The optimized f499e3ed release completed all 12 first links and 12 identical repeats. Each invocation issued exactly one local controlled status query. All first links persisted their mapping, and repeats retained the same config bytes, inode and modification time. Every trust-store digest was unchanged. Whole-command median and nearest-rank p95 were **8.015 ms / 10.852 ms** for first links, **6.507 ms / 7.465 ms** for identical repeats, and **3.299 ms / 3.928 ms** for the isolated status fixture itself. The p95 in each group is its maximum of 12 observations. Wall timings include process startup and filesystem work. Actual Tailscale service latency was outside this fixture. [Canonical CLI and source-bound execution](release-receipt.json) · [Metadata and hashes](release/receipt.json) · [Individual calls](release/commands.jsonl)

## Preliminary development sample

The controlled development CLI run used one fixed, already trusted disposable peer, a three-section config in a temporary HOME and one visible IPv4 node in an offline Tailscale status fixture. Each of twelve independent profiles received its first mapping and then an identical repeat. All 24 returned JSON with the exact signed peer fingerprint, key, stable node ID and port. Each command launched precisely one status helper. `changed` was true on every first invocation, and false on every repeat. Trust bytes stayed identical. First links replaced the config; repeats preserved its contents, inode and modification time. [Protocol](preregistration.md) · [Call-path review](source-findings.md) · [Raw operator commands](development/commands.jsonl)

| Development CLI measurement (ms) | Samples | Median | Nearest-rank p95 |
|---|---:|---:|---:|
| First link, end-to-end | 12 | 12.86 | 14.69 |
| Idempotent repeat, end-to-end | 12 | 10.42 | 27.58 |
| Offline status helper only, separate control | 12 | 3.27 | 3.56 |

The p95 is the maximum of twelve values. These are operator process wall times, including subprocess startup and local filesystem work. The helper merely prints 377 bytes of controlled JSON; its separately measured latency is not subtracted and does not predict the latency of a running Tailscale daemon. The deterministic configuration assertions and query counts are independent of timings. [Binary, runner, source, process metadata, raw samples and fixture hashes](development/receipt.json)
