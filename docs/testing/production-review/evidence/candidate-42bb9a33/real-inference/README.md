# Real inference on the follow-up Linux release

The release worker served three prompts each through llama.cpp’s OpenAI-compatible completion and chat endpoints. Two separately initialized daemons used authenticated QUIC on one x86-64 Linux host. The backend ran TinyLlama Chat 1.1B IQ2_XXS on two CPU threads. Each answer matched the direct greedy backend response byte for byte. The six successful streams carried 140 tokens in 139 signed chunks. [Raw requests, outputs, signatures and timing](result.json) · [Model provenance](model-provenance.json)

| Endpoint | First verified chunk, ms | End-to-end tokens/s |
| --- | --- | --- |
| /v1/completions | 4052, 1085, 1674 | 0.78, 4.11, 1.9 |
| /v1/chat/completions | 2578, 1448, 957 | 2.76, 5.1, 7.49 |

The test waits for the model server health check and for the worker to become eligible for the first request. Each recorded first-chunk latency begins at the accepted stream open. The source and release hashes were checked before and after the requests. This functional run shared its host with other validation jobs. The 70B GPU and separate battery laptop production target remains open. [Current driver](verify.py) · [Server log](result.server.log) · [Model setup and build](../../candidate-864ae27b/real-inference/README.md)

### Repeat after the other workload and build processes finished

The quiet run verified another 139 Ed25519 chunk signatures and matched all six direct responses. The same two CPU threads, model SHA-256 and release executables were used.

| Endpoint | First verified chunk, ms | End-to-end tokens/s |
| --- | --- | --- |
| /v1/completions | 1032, 337, 240 | 9.77, 17.0, 17.91 |
| /v1/chat/completions | 953, 591, 482 | 10.0, 13.42, 14.19 |

The earlier concurrent and later quiet runs use fresh coordinators and model-server processes. Each table contains three short prompts per endpoint. [Quiet measurements](quiet.json) · [Independent verifier output](quiet-verification.json)
