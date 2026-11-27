# CPU inference through two paired Entanglement daemons

Six requests to the published Linux x86-64 candidate returned exactly the same UTF-8 bytes as direct greedy inference against the same llama.cpp server. The server loaded the 1.1-billion-parameter TinyLlama chat model, IQ2_XXS, with two CPU threads. The worker advertised the operator-configured inference capability. Two separately initialized Entanglement processes communicated over authenticated QUIC on one Linux host. The model used 322,591,712 bytes on disk. [Machine results](result.json) · [Tensor inventory](model-tensor-inspection.json)

| OpenAI-compatible route | Requests | Generated tokens | Signed chunks | First verified chunk, min–max | End-to-end tokens/s, min–max |
|---|---:|---:|---:|---:|---:|
| `/v1/completions` | 3 | 72 | 72 | 281–618 ms | 13.26–15.81 |
| `/v1/chat/completions` | 3 | 68 | 67 | 483–1,043 ms | 9.86–14.24 |

The coordinator opened a fresh task per prompt, restricted placement to the paired worker and set a four-chunk credit window. The driver verified the executor, sequence, task UUID, payload digest, and detached Ed25519 signature on every chunk. It then submitted the same input directly at temperature zero and compared the full output. The token count comes from the direct API's usage record. End-to-end throughput includes placement, inference, chunk delivery and final stream completion. Three samples per route support a functional check and descriptive timing. Hardware, prompts, context reuse and model size affect timing. The 70B GPU and battery-laptop gate remains open. [Driver](verify.py) · [Independent verification](independent-verification.json)

## Reproduce

The server source was llama.cpp tag `b6910`, commit `5d8bb900bc7daa84bfa7bb1d25ab7e32394919f3`. The build used CMake 3.31.6, Ninja 1.11.1 and GCC 14.2.0 on Debian x86-64. The measurements used these build settings.

```sh
git clone --depth 1 --branch b6910 https://github.com/ggml-org/llama.cpp.git /tmp/entangle-llama-src
git -C /tmp/entangle-llama-src rev-parse HEAD
cmake -S /tmp/entangle-llama-src -B /tmp/entangle-llama-build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DLLAMA_CURL=OFF -DGGML_NATIVE=OFF -DGGML_CCACHE=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=ON -DGGML_OPENMP=ON
cmake --build /tmp/entangle-llama-build --target llama-server --parallel 3
```

To reproduce the model input, download the two pinned npm tarballs. Compare each tarball's SHA-512 against its integrity field, read only the regular-file member `package/model.part` from each, and concatenate their bytes in part-number order. Compare the result's SHA-256 with `9ee11adf737960ff06123d5c4fba24d12c5b05ba460a7afa88950fbf2b61add0`. The published evidence contains public provenance, license and tensor descriptions. The model weights were kept in the temporary test workspace. Direct upstream Hugging Face access was unavailable here. [Distribution digests](model-provenance.json) · [Model attribution](MODEL.json) · [License](APACHE-2.0.txt)

Run the driver from a checkout containing the published candidate binaries, using Python 3.11 or later with `cryptography` and OpenSSL. The `--output` argument selects a fresh local receipt.

```sh
python3 docs/testing/production-review/evidence/candidate-864ae27b/real-inference/verify.py \
  --server /tmp/entangle-llama-build/bin/llama-server \
  --model /path/to/TinyLlama-1.1B-Chat-v1.0-IQ2_XXS.gguf \
  --bin-dir target/release --output /tmp/entangle-cpu-inference.json
```
