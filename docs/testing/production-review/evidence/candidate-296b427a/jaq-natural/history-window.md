# Historical scope of the jaq clock case

The stock workspace never combined this clock assertion with a CLI test suite portable to the paired WASI workers. A read-only scan of all 2,588 commits reachable from the unshallow upstream checkout, including the 36 historical blobs at the case’s path, found the assertion in exactly two trees. Both contained the same eight golden tests, which rely on native filesystem fixtures and subprocess spawning, and both enabled the native mimalloc allocator by default. Searching the complete Rust tree history for additions or removals of the filter literal also returned only the introduction and removal commits. Both affected trees’ manifests, README, workflow and build scripts had no documented WASI configuration. [Raw Git ancestry, exact case lists and build configuration](history-window.json) · [Read-only reproducer](history-window.py)

| Upstream change | Commit date | Commit |
|---|---|---|
| CLI adopts mimalloc | 2022-03-14 | [c12729ad](https://github.com/01mf02/jaq/commit/c12729ad666f347281d8b37e9bddb3601fa12f68) |
| Golden tests added | 2022-05-19 | [dadd1473](https://github.com/01mf02/jaq/commit/dadd1473c2ea8311cc68c6c1578309d31cdcff96) |
| Allocator made optional, still enabled by default | 2022-08-11 | [274c90e0](https://github.com/01mf02/jaq/commit/274c90e025f1357bf1691a877bcc52e80b4f7290) |
| All eight golden tests present | 2022-10-07 | [4b514394](https://github.com/01mf02/jaq/commit/4b514394c3359b8e5561055632c0a7a2bcff9f28) |
| Clock assertion introduced | 2023-06-29 | [90cabdc4](https://github.com/01mf02/jaq/commit/90cabdc4b0a0f136814fd71777318ef3d6e7369e) |
| Last affected tree, exercised by the archived cohort | 2023-07-04 | [606164eb](https://github.com/01mf02/jaq/commit/606164eb26420c892c9bac27f7daf77b7a406b6d) |
| Upstream removes the flaky test | 2023-07-04 | [191e5e67](https://github.com/01mf02/jaq/commit/191e5e6780aad7fcc6295e3aced68bfd657eef14) |

The Git comparisons establish ancestry independently of commit dates. The golden-test file had the same blob ID in both affected snapshots. Disabling the optional allocator would still leave the eight native golden cases in the workspace. This investigation inspected source only. [Observed native and WASI results](README.md)
