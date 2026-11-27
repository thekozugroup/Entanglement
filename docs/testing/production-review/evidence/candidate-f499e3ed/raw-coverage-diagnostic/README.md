# Two-camera observation with complete placement diagnostics

On the unchanged f499e3ed release, one single-worker control and one three-worker mesh batch fully decoded and dehazed both genuine camera inputs. Each output matched its pinned reference. The corrected observer ran in an isolated checkout. The single-worker batch took 11.892 seconds and the mesh batch took 10.512 seconds. The single pair is a diagnostic and has no median or production speedup grade. [Source-bound receipt](execution-receipt.json) · [Registered protocol](plan.md) · [Normalized observations](observations.json)

| Worker ID | Single Canon / Nikon tiles | Mesh Canon / Nikon tiles | Mesh total |
|---|---:|---:|---:|
| 1b89962463add86d5cdf3c8d41f13143 | Outside single-worker allowlist | 2 / 0 | 2 |
| a2dc6b306d1669343ed41db21b2bb134 | Outside single-worker allowlist | 3 / 2 | 5 |
| afa9b082e31bb810760bdf491095430f | 12 / 6 | 7 / 4 | 11 |

Both arms validated all 18 tiles, the expected output dimensions, the linear RGB16 PNG structure and pixels, full independent SHA-256 and per-tile assignments. The first mesh worker served no Nikon tiles and served two Canon tiles. Across the full batch, all three allowed peers appeared. The earlier failed primary also required all three peers across the whole batch. Its missing peer was unrecorded and cannot be recovered from these new identities. [Single-worker progress](single.stdout.jsonl) · [Mesh progress](mesh.stdout.jsonl) · [Original failed qualification](../raw-batch/README.md)

The diagnostics correction preserves the original failure conditions. It distinguishes a missing input or absent reference from a missing/differing digest, retains filenames and expected/actual digest pairs, and reports zero tiles for specified workers. Each verified PNG and per-photo timing/placement remains available in a failed arm. Eight regression and existing image benchmark tests passed, including persisted failure without a speedup, a missing source whose available bytes match, simultaneous coverage/digest failures, and absent reference names. [Source patch](observer.patch) · [Unit test transcript](observer-tests.log)

The supplementary runner records the exact product and observer fingerprints. The binary-diff-free source patch can be applied directly to the public base. For exact Git identity, the small incremental bundle contains the isolated commits and requires a clone with f499e3ed as parent. In a disposable clone of that base, fetch the bundle’s refs/heads/work and check out b90aac1bf936c71f1ee4cf12893312f530a92b53. The retained runner uses /tmp/entangle-f499-raw-coverage-fix for that observer checkout. [Exact observer bundle](observer.bundle) · [Diagnostic command](run.py)
