# Direct daemon package-loading review

The prior **Medium availability finding remains closed on Linux** for candidate `761485d7490a56c7215ad958db81949204c74245`. The optimized daemon rejected six invalid packages through RPC and six through configured startup. Both entry points subsequently loaded the repaired signed package and returned the expected result from a fresh invocation. [Release archive](linux-archive.json) · [Behavioral receipt](loader-boundary-linux.json) · [Reproduction script](verify-loader.py)

| Signed package member | Maximum file size | Conditions exercised at both entry points |
|---|---:|---|
| `entangle.toml` | 1 MiB | Symlink to the genuine signed member and regular file one byte over its limit |
| `plugin.wasm` | 64 MiB | Same two conditions |
| `plugin.wasm.sig` | 64 KiB | Same two conditions |

The frozen Linux archive had SHA-256 `da07d6662bda25c9da80974e81d12a62683173f1f67194d841d83c8536145f8a`. I extracted its CLI and daemon into a disposable test directory, verified each against the release manifest and rechecked the binaries after execution. During each RPC refusal, the test checked that the plugin had not entered the live registry. The six configured startup attempts exited unsuccessfully within the test deadline. The output receipt contains the tested conditions and outcomes. [Archive manifest](linux-archive.json) · [Observed results](loader-boundary-linux.json)

The kernel reads the manifest, component and detached signature through a shared reader. On Unix it opens the final path component with `O_NOFOLLOW | O_NONBLOCK`, checks regular-file type and length on that open descriptor, and limits the subsequent read to one byte above the configured cap. The kernel then verifies the package signature. The exact-source workspace suite passed both named loader regressions. [Reader](../../../../../crates/entangle-signing/src/package_io.rs) · [Package loader](../../../../../crates/entangle-runtime/src/loader.rs) · [Runtime](../../../../../crates/entangle-runtime/src/kernel.rs) · [Workspace receipt](workspace-test.json)

**Attribution and scope.** Codex engineering reviewer `tailroute` reported the original finding, authored its fix and ran the current release test. Codex reviewer `qa` independently checked this candidate's loader, kernel, shared reader and regression tests against `864ae27b` and confirmed they were byte-identical. This finding disposition covers local package loading on Linux. It leaves parent-directory path resolution, other operating systems, external auditing and hosted release controls outside its scope. The tailnet supervisor has a separate reviewer because its author also ran this loader check. [Historical finding](../candidate-2602ce17/independent-security-review-clarification.md) · [Predecessor disposition](../candidate-864ae27b/loader-security-disposition.md)
