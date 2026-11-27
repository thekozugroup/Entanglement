# Direct daemon package-read finding disposition

**Closed on Linux for `864ae27bf3fd08e9d9c62abd4f43ff7bfd4c68c2`.** Both the RPC and configured startup paths refused symlinks and oversized regular files for each of the three signed package members. Both paths subsequently loaded and invoked the repaired signed package. The prior Medium availability finding remains part of the historical record for `2602ce17`. [Prior scoped review](../candidate-2602ce17/independent-security-review.md) · [Original finding clarification](../candidate-2602ce17/independent-security-review-clarification.md)

**Review identity and independence.** Codex engineering reviewer `tailroute` reported the original issue, implemented the fix and ran this verification. The separately assigned Codex reviewer `qa` independently inspected the candidate's reads and limits and concluded that they address the reported finding on supported Unix targets. This is an internal code review and a Linux execution result. External audit and macOS hardware testing remain separate.

**Source and artifact identity.** The receipt names source ID `sha256:2a5db79622c3130c68614ca443ad93b86efec77c11bb5b4e84f6ad7c02277c68`, checks the repository before and after the run, and records both optimized binary hashes. The approved release build and the temporary-home test completed with exit code zero. [Release build](release-build.json) · [Loader receipt](loader-boundary-linux.json) · [Runnable check](verify-loader.py)

## Controls verified

| Input | Limit | Evidence |
|---|---:|---|
| `entangle.toml` | 1 MiB | Both entry points rejected a symlink to the original correctly signed manifest and a sparse regular file one byte over the limit. |
| `plugin.wasm` | 64 MiB | Both entry points rejected the corresponding symlink and oversized file. |
| `plugin.wasm.sig` | 64 KiB | Both entry points rejected the corresponding symlink and oversized file before signature verification could admit the package. |

On Unix the shared reader opens the final component with `O_NOFOLLOW | O_NONBLOCK`, checks the opened descriptor's file type and length, and bounds the actual bytes read. The runtime uses these checks for its manifest, component and detached signature, and still verifies the artifact and publisher binding. The test confirmed that the six failed RPC requests left the plugin out of the live registry and all six malformed startup configurations caused an unsuccessful daemon exit. The output challenge after each recovery used a disposable publisher and node. [Shared reader](../../../../../crates/entangle-signing/src/package_io.rs) · [Loader](../../../../../crates/entangle-runtime/src/loader.rs) · [Kernel admission](../../../../../crates/entangle-runtime/src/kernel.rs) · [Regression tests](../../../../../crates/entangle-runtime/src/tests.rs)

The original review's registry transfer, artifact signature, streaming protocol and inference adapter implementation files named in this assessment did not change between the two candidates. The successor also changed the local RPC serializer and shell-wrapper diagnostics. This finding disposition covers the three local input reads and Linux behavior documented above. It does not establish a fresh security assessment of those separate changes, of all ancestor path components, or of non-Unix filesystem semantics.
