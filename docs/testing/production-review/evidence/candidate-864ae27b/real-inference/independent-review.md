# Independent validation of real CPU inference

Reviewed 27 November 2026 for source commit `864ae27bf3fd08e9d9c62abd4f43ff7bfd4c68c2`, source ID `sha256:2a5db79622c3130c68614ca443ad93b86efec77c11bb5b4e84f6ad7c02277c68`. The immutable input receipt is `result.json`, SHA-256 `04a99672587e613be6da0d71b8dacd16ae28b6eb92c8bc5520db41c31b18b70f`.

The independent verifier recomputed each worker ID as the first 16 bytes of BLAKE3 over its public key, checked the chosen worker against that ID, and verified all 139 Ed25519 signatures over the protocol domain, task ID, sequence number, timestamp and payload digest. It reconstructed each output from its ordered chunks, checked its SHA-256, and compared the exact text and token count against the separately recorded direct backend JSON. All six samples passed: three on `/v1/completions` and three on `/v1/chat/completions`. [Independent results](independent-verification.json) · [Verifier](independent-verify.py) · [Peer fingerprint helper](independent-peer-fingerprint.rs)

I separately hashed the live candidate CLI and daemon, the driver, the model, the llama-server executable and all five recorded shared libraries; each matched the receipt. The model is the listed TinyLlama 1.1B quantized artifact, with the recorded distributor provenance and tensor inspection. The direct responses are separate non-streaming calls to the same local backend with temperature zero; exact equality verifies this test's comparison, not model correctness or identity of output on all future runs.

The six end-to-end first signed chunk times were 281–1,043 ms and end-to-end rates were 9.86–15.81 generated tokens/s. These are six short (20–24 token) samples, with one worker and coordinator as separate processes on the same x86_64 Linux host. They include startup and do not establish a sustained throughput distribution. The backend was CPU-only with two threads and zero GPU layers.

**PERF-LLM remains not evidenced.** The frozen architecture requires a real 70B model on an Apple M4 Max or RTX 4090, a separate battery laptop, streaming TrustedExecutor, first-token latency under 300 ms and sustained throughput of at least 30 tokens/s. This controlled 1.1B CPU loopback functional test does not meet those workload and hardware preconditions.

To repeat the independent cryptographic checks with the workspace's already built `blake3` rlib and Python `cryptography`:

```sh
set -- target/debug/deps/libblake3-*.rlib
rustc --edition=2021 docs/testing/production-review/evidence/candidate-864ae27b/real-inference/independent-peer-fingerprint.rs -L dependency=target/debug/deps --extern "blake3=$1" -o /tmp/entangle-peer-fingerprint
python3 docs/testing/production-review/evidence/candidate-864ae27b/real-inference/independent-verify.py docs/testing/production-review/evidence/candidate-864ae27b/real-inference/result.json --peer-fingerprint /tmp/entangle-peer-fingerprint
```

The first matching workspace rlib must have been built with the current Rust toolchain; pass any compatible helper path via `--peer-fingerprint`. The retained independent-relocatable-verification.json is byte-identical to the original result. The verifier uses the evidence in `result.json`; the identity, model and server files must be obtained and checked separately if their recorded digests are to be reproduced.
