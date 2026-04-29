# Centrifuge Plugin Architecture Research

**Date:** 2026-04-28
**Mission:** Choose an extension mechanism for Centrifuge — a tiny Rust kernel where plugins declare resource needs (CPU/GPU/NPU/storage/network) and a permission tier.

---

## 1. Dynamic Libraries — `cdylib` + `libloading` / `abi_stable`

Rust has no stable ABI. Every compiler bump (and even codegen-units changes) can shift struct layouts, vtables, and `repr(Rust)` enum tags. Loading a `cdylib` with raw `libloading` works, but you must hand-define every type as `#[repr(C)]`, never pass `String`/`Vec`/`Box<dyn Trait>` across the boundary, and pray the host and plugin were compiled with byte-identical toolchains.

`abi_stable` (rodrimati1992, currently 0.11.x as of 2025) closes that gap. It provides FFI-safe equivalents (`RString`, `RVec`, `RBox`, `RHashMap`, `RResult`), the `#[sabi_trait]` macro for FFI-safe trait objects, and "prefix types" that let you add fields to vtables in a semver-compatible way. At load time it checks every type's layout against the host's expected layout and refuses incompatible libraries.

- **Perf:** zero overhead — direct function calls, no serialization. Fastest of all options.
- **Sandboxing:** none. A plugin can `unsafe` its way into your address space, leak memory, or `abort()`. Panics across FFI are UB unless you wrap every entry point in `catch_unwind` (abi_stable does this).
- **GPU/NPU:** trivial — just hand a `wgpu::Device` or `Arc<dyn Backend>` across.
- **Hot reload:** `abi_stable` explicitly does NOT support unloading (`dlclose` is unsafe in Rust because of TLS destructors and global state).
- **Multi-language:** in practice no — you'd be forcing every plugin author into Rust.
- **Real users:** `openrr` (robotics framework) is the canonical large-scale user. swc explored it for plugins but moved to wasm. `sccache` does NOT use abi_stable; it ships compiled in-tree. Bevy's `bevy_dynamic_plugin` exists but is widely considered fragile.

Verdict: best raw performance, worst safety story. Acceptable only when host and plugins ship together.

---

## 2. WebAssembly via Wasmtime / Wasmer

The WebAssembly Component Model + WASI 0.2 (Preview 2) is the story that changed dramatically in 2024–2025. WASI 0.2.0 shipped January 2024, WASI 0.2.1 mid-2024, and Wasmtime 25+ ships full Preview 2 support. Interfaces are described in WIT (WebAssembly Interface Types); `wit-bindgen` generates host and guest bindings; `cargo-component` produces components from Rust crates targeting `wasm32-wasip2`.

The component model gives you what core wasm couldn't: strings, lists, records, variants, resources (handles), and async — passed across the boundary with automatic lifting/lowering. Components from different languages interoperate through the same WIT contract.

- **Perf:** AOT-compiled via Cranelift, typically 1.5×–3× native for compute. Component-model boundary crossings cost a few hundred ns each because of lifting/lowering — chatty hot loops hurt; bulk byte transfers don't.
- **Sandboxing:** capability-based and free. The host hands the guest exactly the file descriptors, sockets, and resources it asks for. Memory is a linear `Vec<u8>` the runtime owns — the guest cannot escape.
- **ABI stability:** WIT is the contract; the engine handles everything else. Decoupled from rustc.
- **GPU/NPU:** the gap. WASI-NN exists for inference (OpenVINO, ONNX, llama.cpp backends in Wasmtime) and supports "named models" preloaded by the host. WASI-GFX (phase-2 proposal, demoed at Wasm I/O Barcelona March 2025) exposes WebGPU — the host runs `wgpu`, the guest gets typed handles. Neither is universally shipped yet; you'd ride the bleeding edge.
- **Hot reload:** instantiate a new component, drop the old one. Trivially safe.
- **Multi-language:** Rust, C/C++, Go (TinyGo + WASIp2 is rough), JS (componentize-js), Python (componentize-py). Reality: 95% of components are written in Rust.

Verdict: the obvious choice for a sandboxed, multi-language plugin system **if** you can tolerate the perf penalty and the GPU story being a year or two from boring.

---

## 3. Extism

Extism (Dylibso, v1.x stable since 2024) is wasm-but-batteries-included. It picks a runtime for you (Wasmtime under the hood), defines a bytes-in/bytes-out plugin convention with a tiny PDK, and ships host SDKs for ~12 languages (Rust, Go, Python, Node, .NET, PHP, OCaml, Ruby, Elixir, Zig, C, Java).

Plugins export named functions; the host calls them with a `&[u8]`. Persistent var slots, host-mediated HTTP (capability-gated), timers, fuel limits, and host functions are first-class.

- **Perf:** Wasmtime perf, plus a copy at the boundary (it's bytes, not typed values). Fine for coarse-grained ops; bad for chatty ones.
- **Sandboxing:** Wasmtime's, plus extra runtime limits.
- **GPU/NPU:** none built in. You'd register host functions for it.
- **Multi-language:** strongest in this list — the PDK list is huge.
- **Trade-off vs raw component model:** simpler API, smaller plugins, fewer typed records, no resource handles.

Verdict: ideal if multi-language plugin authoring is the #1 priority and you don't need rich typed interfaces.

---

## 4. Embedded Scripting — Rhai, mlua, pyo3

For when "plugin" means "user-supplied logic," not "compiled extension."

- **Rhai** (≈v1.20, 2025): pure-Rust AST interpreter, zero-deps, sandboxed by construction (no I/O unless you give it). ~1M iterations of trivial work in 0.14s. Trivial Rust integration via `#[export_module]`. Slow vs compiled wasm by 10–50×.
- **mlua**: bindings to Lua 5.4 / LuaJIT / Luau. LuaJIT is shockingly fast (often within 2× of native). Sandbox depends on which `package` library you expose. Mature, but you ship a C dependency.
- **pyo3**: full CPython embed. Massive ecosystem (numpy, torch). Heavyweight: GIL, ~40MB runtime, no real sandbox — a Python plugin can `import os; os.system(...)`. Used by Polars (the entire pyo3-polars expression-plugin system: Rust functions compiled to `.so`, dynamically linked into the Polars expression engine, registered from Python).

Verdict: scripting beats compiled plugins when (a) hot-reload matters, (b) plugins are short, (c) authors aren't systems programmers. Wrong tool for GPU/NPU compute kernels.

---

## 5. Subprocess + IPC (the boring, battle-tested option)

A plugin is a separate executable. Host launches it; they talk over stdio, a Unix socket, or gRPC. Examples are everywhere:

- **HashiCorp `go-plugin`** (Terraform, Vault, Nomad, Packer): subprocess + gRPC over a Unix domain socket, `yamux` multiplexing, mTLS handshake, bidirectional. Plugin crashes don't crash host. Cross-language because gRPC.
- **LSP (Helix, Zed, every editor)**: stdio + JSON-RPC. Helix uses LSPs as its de-facto plugin system — there is no in-process plugin API yet (a Steel/Scheme prototype exists but hasn't merged as of April 2026).
- **Nushell plugins**: stdio with a length-prefixed protocol; each plugin announces JSON or MessagePack encoding. Bidirectional streams added in PR #11911 (2024). Plugins can be in any language.
- **rust-analyzer's proc-macro server**: `proc-macro-srv` runs as a separate process, communicating via newline-delimited JSON over stdio. Originally a perf workaround; post-xz it's also a (weak) sandboxing story — IDEs can kill the process if a macro misbehaves.

- **Perf:** worst of any option for fine-grained calls (process launch + serialization). Fine for coarse-grained "compile this file" type RPCs.
- **Sandboxing:** OS-level — `seccomp` / `pledge` / job objects available; you control the binary's permissions.
- **GPU/NPU:** trivial — the subprocess is a real native process, can use `wgpu`/CUDA/whatever.
- **Hot reload:** kill, restart.
- **Dev ergonomics:** painful protocol design and versioning, but rock-solid in production.

Verdict: best when plugins are heavyweight (a whole language toolchain), need full OS access, or already exist as separate binaries.

---

## 6. In-Tree Cargo Features

Bevy is the canonical example: every "plugin" is a Rust crate compiled into the binary. The `Plugin` trait registers systems/resources into the `App`. ECS gives you isolation by data scope, not by trust. Tauri ditto: most plugins are Cargo crates with optional NPM glue; only the JS sidecar story uses subprocess IPC.

- **Perf:** native, no boundary.
- **Sandboxing:** zero.
- **Distribution:** users must compile their own binary or you ship feature-flagged builds.

Verdict: legit "plugin system" for some projects but doesn't satisfy Centrifuge's "permission tier" goal — there's nothing to enforce.

---

## 7. Concrete Case Studies — Quick Map

| Project | Mechanism | Why |
|---|---|---|
| **Zellij** | wasm via `wasmi` interpreter (migrated from Wasmtime in v0.44) | Want plugin sandbox; small terminal multiplexer prefers interpreter startup speed over peak throughput |
| **Lapce** | WASI components, written in any language compiling to wasm | "Native + sandboxed plugins, polyglot" was a founding goal |
| **Zed** | Wasm Component Model + WIT + `zed_extension_api` (compile to `wasm32-wasip1`) | Sandbox, no Electron/Node, async host calls, typed records |
| **Helix** | None shipped; Steel (Scheme) prototype experimental | Maintainers historically resisted scope creep; plugin API design ongoing |
| **Bevy** | In-process Rust crates implementing `Plugin` trait | ECS already provides the "module" abstraction; trust assumed |
| **Tauri** | Rust crates + JS bindings + optional binary sidecars | Desktop app — user trusts what they install |
| **Tantivy / Meilisearch** | No plugin system; configurable analyzers/tokenizers as features | Search engines avoid arbitrary plugin code paths for query correctness |
| **Polars** | `pyo3-polars` expression plugins — Rust → `cdylib`, dynamically loaded, registered from Python | Wants compiled-Rust speed without rebuilding Polars; trusts the author |
| **Deno** | Rust core + JS extensions via `deno_core` ops (`#[op2]`) | Embedders extend; end users get JS, not Rust loading |
| **rust-analyzer** | Proc-macro subprocess over JSON stdio | Process isolation as crash safety + (weak) sandbox |
| **Nushell** | Subprocess + length-prefixed JSON or MessagePack stdio | Polyglot plugins, OS isolation, no embedded VM cost |

---

## 8. GPU / NPU from Sandboxed Plugins — what's actually possible (April 2026)

This is the load-bearing question for Centrifuge. Three real paths:

1. **WASI-NN (named models)**. The host loads the model, the guest passes tensors and gets results. Wasmtime supports OpenVINO, ONNX Runtime, llama.cpp backends. NPU access happens because ONNX Runtime exposes execution providers (CoreML, NNAPI, DirectML). The plugin never sees the GPU directly — it sees a tensor API. This is the safest, most capability-aligned model.
2. **WASI-GFX (WebGPU in components)**. Phase-2 proposal, demoed Wasm I/O Barcelona March 2025. Host runs `wgpu`; guest gets typed device/queue/buffer handles. Real general-purpose compute via compute shaders. Status: works in demos, not yet in stable Wasmtime as a default feature.
3. **Host-function escape hatch**. Define your own WIT interface (`compute.submit-job`, etc.), implement it on the host with `wgpu` or CUDA, expose it. Zero standardization but ships today and gives you full control over permission tier enforcement.

Subprocess plugins, by contrast, just use the GPU directly — but you trade the wasm capability model for OS-level sandboxing (seccomp, app sandbox), which is harder to make portable.

---

## Synthesis — Recommendation for Centrifuge

Centrifuge requirements: Rust core, multi-language plugins desirable, GPU/NPU compute support, enforceable permission tiers.

### Top 3 ranked

**1. WebAssembly Component Model (Wasmtime + WIT) — RECOMMENDED.**
The only mechanism that natively encodes "permission tiers" — capability-based security is exactly the WIT/WASI design. Multi-language works (Rust, C, Go, JS, Python all compile to components, with Rust being the smooth path). For GPU/NPU: start with WASI-NN for inference workloads (it covers ~80% of NPU use cases today) and define your own WIT host functions for `wgpu` compute (the WASI-GFX standard track will catch up). Pay the boundary cost — for a kernel-and-plugins design, plugin calls should be coarse-grained anyway. Wasmtime 25+ has been production-grade since 2024.

Brutal honesty: you'll write a lot of WIT, `wit-bindgen` ergonomics still rough in Rust async, debugging across the boundary is annoying, and the GPU story requires you to design custom host APIs because the standards aren't quite there.

**2. Extism, only if multi-language is THE priority.**
Get Wasmtime sandboxing with a much simpler plugin author experience and 12-language PDK support. Cost: bytes-in/bytes-out instead of typed records, less expressive permission tiers (you build tier enforcement in host functions yourself). Drop down to it if you want plugin authors to feel like they're writing AWS Lambdas, not consuming a Rust crate.

**3. Subprocess + protocol (Cap'n Proto recommended over gRPC for perf).**
Worth it only if plugins are large, long-running, need full GPU/CUDA/driver access, or are pre-existing binaries. OS sandboxing (`sandbox-exec` on macOS, seccomp on Linux, AppContainer on Windows) gives you a permission-tier story but it's per-OS work. Use this as a "tier 0 / native" escape hatch for plugins that the wasm path can't satisfy — not as the default.

### Recommendation

**Default to wasm Component Model with Wasmtime.** Map permission tiers directly onto WIT capability imports — a "high-trust" tier gets the `wgpu-compute` interface, a "low-trust" tier doesn't. Use WASI-NN for inference plugins. Reserve a subprocess escape hatch (tier-native) for the rare plugin that genuinely needs raw driver access; gate it behind an explicit user opt-in. Avoid `abi_stable` unless you're shipping plugins as part of the same release as the kernel — the sandboxing gap defeats the entire point of permission tiers.

---

## Sources

- [abi_stable on GitHub](https://github.com/rodrimati1992/abi_stable_crates)
- [NullDeref — Plugins in Rust: abi_stable](https://nullderef.com/blog/plugin-abi-stable/)
- [Bytecode Alliance — Wasmtime / WASI 0.2](https://bytecodealliance.org/articles/using-wasi-nn-in-wasmtime)
- [WASI and the Component Model: 2025 status](https://eunomia.dev/blog/2025/02/16/wasi-and-the-webassembly-component-model-current-status/)
- [Extism docs](https://extism.org/docs/concepts/plug-in-system/)
- [Zed Decoded: Extensions](https://zed.dev/blog/zed-decoded-extensions)
- [Lapce WASI plugins](https://github.com/lapce/lapce/blob/master/lapce-proxy/src/plugin/wasi.rs)
- [Zellij plugin system (DeepWiki)](https://deepwiki.com/zellij-org/zellij)
- [Helix — does it support plugins?](https://helixeditor.com/2025/04/11/does-helix-support-plugins/)
- [Bevy plugin architecture](https://deepwiki.com/bevyengine/bevy/3.1-app-lifecycle-and-plugin-architecture)
- [Tauri plugin development](https://v2.tauri.app/develop/plugins/)
- [Polars expression plugins (pyo3-polars)](https://github.com/pola-rs/pyo3-polars)
- [Deno ops + extensions architecture](https://github.com/denoland/deno_core/blob/main/ARCHITECTURE.md)
- [Nushell plugin protocol](https://www.nushell.sh/contributor-book/plugin_protocol_reference.html)
- [HashiCorp go-plugin](https://github.com/hashicorp/go-plugin)
- [rust-analyzer proc-macro-srv](https://rust-analyzer.github.io/manual.html)
- [WASI-NN proposal](https://github.com/WebAssembly/wasi-nn)
- [WASI-GFX (Wasm I/O 2025 talk)](https://2025.wasm.io/sessions/gpus-unleashed-make-your-games-more-powerful-with-wasi-gfx/)
- [Rhai benchmarks](https://rhai.rs/book/about/benchmarks.html)
- [script-bench-rs](https://github.com/khvzak/script-bench-rs)
