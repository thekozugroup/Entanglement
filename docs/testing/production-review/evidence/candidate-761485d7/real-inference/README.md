# CPU inference on the Tailscale recovery candidate

Two Linux Entanglement daemons used authenticated QUIC to serve three prompts each on the OpenAI-compatible completions and chat endpoints. The worker used llama.cpp b6910, the 1.1-billion-parameter TinyLlama Chat IQ2_XXS model and two CPU threads. Every response matched direct, greedy inference byte for byte. The candidate returned 140 tokens in 139 signed chunks across the six requests. [Raw prompts, backend responses, signatures and timing](result.json)

| API | First verified chunk, ms | End-to-end tokens/s |
| --- | --- | --- |
| Completions | 626, 359, 317 | 13.07, 15.45, 14.16 |
| Chat completions | 959, 518, 486 | 10.25, 13.77, 14.36 |

Timing starts at the accepted stream open and ends at the first verified chunk or at stream completion. The receipt also records time spent waiting for the first worker inventory. All six successful opens found an eligible worker on their first attempt. These measurements used one shared x86-64 host during functional validation. The production inference gate still requires a 70B model on the specified GPU, submitted from a separate laptop on battery. [Server log](result.server.log) · [Earlier incomplete attempts](initial-attempt.md)

From the repository root, use Python 3.11 or later with `cryptography`, OpenSSL, the locked release binaries and the recorded model. Use a fresh output path so the server log is also retained.

```sh
python3 docs/testing/production-review/evidence/candidate-761485d7/real-inference/verify.py \
  --server /path/to/llama-server --model /path/to/TinyLlama-1.1B-Chat-v1.0-IQ2_XXS.gguf \
  --bin-dir target/release --output /tmp/entangle-cpu-inference.json
```

The model SHA-256 is `9ee11adf737960ff06123d5c4fba24d12c5b05ba460a7afa88950fbf2b61add0`. The two data-only distribution archives, model license and tensor inspection have separate receipts. [Server build and model retrieval](../../candidate-864ae27b/real-inference/README.md) · [Distribution hashes](model-provenance.json) · [Model notice](model-notice.md)
