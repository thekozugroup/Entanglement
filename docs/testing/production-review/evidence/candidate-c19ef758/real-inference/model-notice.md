# Bundled explainer model

Slaunt Audit includes the quantized `TinyLlama/TinyLlama-1.1B-Chat-v1.0`
model in `tinyllama-1.1b-chat-v1.0.IQ2_XXS.gguf`. The registry rejects a single
package tarball of this size, so the GGUF bytes are shipped as two immutable
npm data dependencies and reassembled locally. The model is distributed under
the Apache License 2.0. The original model card identifies the model as 1.1B
parameters and Apache-2.0 licensed:

- `slaunt-model-tinyllama-1b-part1@0.1.0`
- `slaunt-model-tinyllama-1b-part2@0.1.0`

The complete license text is included in `APACHE-2.0.txt` in this directory.

<https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0>

The GGUF quantization source and revision are recorded in `MODEL.json`:

<https://huggingface.co/imi2/TinyLlama-1.1B-Chat-v1.0-2bit-wikitext-gguf>

The model is loaded locally through `node-llama-cpp`; Slaunt verifies each part
size and the assembled SHA-256 before loading it, and does not send server
configuration, tool declarations, or audit output to a remote model.
