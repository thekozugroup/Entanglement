# Cargo and toolchain comparison

On 27 November 2026, the read-only capture observed clean build B's two final Cargo fingerprint records at 07:31:32 UTC, before Cargo's private target was removed. The source was `c19ef7587a2215ef9434b642413bebd0473caf20` with digest `sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644`. The build manifest records `Cargo.lock` SHA-256 `2ea7955d2dd3a3b91c6a31832d1ea0d0bef4613d8bbce8083cce56675dded0d9` and the exact build arguments, executable hashes and retained binary paths. [Build receipt](../results.json)

The comparison started at the cached CLI and daemon's actual linked units, `entangle-cli-1438826a0f3d5a99` and `entangle-bin-86c910d20e950a7b`. It resolved 611 Cargo units from their saved dependency fingerprints. All 611 had matching unit paths in B and identical compiler, feature, profile, target, configuration and extra Rust flag fields. Two dependency tokens pointed to multiple cached build-script records and remain unresolved. Six units showed dependency-token differences along the `zstd-sys`, `zstd-safe`, `zstd`, `entangle-oci`, and CLI chain. All direct daemon dependency tokens matched. The sampled B binary compiler invocations used `opt-level=3`, thin LTO, one codegen unit and symbol stripping, with no path-remapping argument. [Final B units](clean-b-final-units.json) · [Graph comparison](clean-b-graph-comparison.json) · [Comparison driver](compare.py)

Cached and B copies of the selected native `libzstd.a` were byte-identical, with SHA-256 `cf9e36d95baa66e978ea82e43f68ab97e65a313ad4c60e20d70e8dc21f4ff9e6`. Recorded C/AR environment values agreed. The normalized `zstd-safe` build output matched. After target-root normalization, the `zstd-sys` output difference consisted of eight extra observations of unset AR and ARFLAGS environment variables. All 16 generated Cranelift Rust files in the selected matching unit also compared byte for byte. The ELF path inventory located distinct absolute build roots for those files. [Binary section and path observations](../elf-layout-verified.json)

`readelf -p .comment` identified Rust 1.91.1 `ed61e7d7e`, LLD 21.1.2, and Debian GCC 14.2.0 in the cached and both clean ELF pairs. The system GNU `ld` in the general tool inventory is a separate executable. The `1.91` and `1.91.1` toolchain directories had byte-identical compiler driver, standard library archive and linker binaries. Only `1.91` contained the `rust-src` component and its standard-library tree. That difference is consistent with the captured absolute standard-library paths in the cached ELFs and virtual `/rustc/<commit>` paths in A. A's Cargo target had already been removed when this comparison began, so its effective Cargo fields are unavailable. The measurements identify real path differences and leave the cause of the remaining ELF differences unresolved.

| Captured input or receipt | SHA-256 |
| --- | --- |
| B root fingerprints | `626592fda0a09ed97bf124a321ff8834707301388e18fce7be48caed7fab6187` |
| B graph comparison | `4a84506b9587fb23293b67c3888a92ab9474e6e0098dd1edba7b88c4c7604517` |
| Comparison driver | `79a09d2f06917db70d16ff32714c47fe0128850f6d007e2fe6fd8a747a08fadf` |
| Rust compiler driver shared object | `52a4f37887b3aa299436ca2e08c0a5781a5c1d0ab9ff0d0f1a18275fd7dd3a25` |
| Rust standard library archive | `75699e73a2ad28230cec7272212340a506cd689084e32f6a66af19a2886553fb` |
| `rust-lld` | `a2aef2573bc0409403747456072c373523ebfea0d03a832520331a17e8ec65a5` |
| `gcc-ld/ld.lld` wrapper | `21a45393b9a99e325e5cd6632e19b9020fb6daf631a93e035f0c159428bc96dc` |
