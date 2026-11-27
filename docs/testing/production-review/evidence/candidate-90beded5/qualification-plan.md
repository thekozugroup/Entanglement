# Operator enrollment and native release promotion qualification

Registered 2026-11-27T10:40:22.733564+00:00 before candidate tests, from branch tip `84aa663b26e4a59a408f14c5417b5af0999cb4a7`. The release-wide standard is the existing 57-criterion rubric. The checks below qualify changes to that source. Unverified release conditions continue to require independent evidence.

| Area | Required evidence for these changes |
|---|---|
| Correctness | The existing status command and JSON remain usable. The enrollment command writes the correct peer key, node ID and UDP port, and an identical request preserves the file. The promotion gate accepts canonical archives for their signed target and rejects a signed archive with an inconsistent target or incomplete layout. |
| Authorization and isolation | Enrollment requires an existing trusted Entanglement key and a matching unique online Tailscale node. Exercise nontrusted, revoked, self and ambiguous identities. Refusals leave configuration untouched. Exercise signed work after enrollment and after revocation. |
| Reliability | Preserve unrelated TOML, configuration permissions and existing mappings, refuse conflicting associations, and handle an already-held configuration lock and concurrent writers. Confirm the verified configuration works when the daemon starts. |
| Interoperability | Use real Tailscale clients and an isolated Headscale network on one Linux kernel. Submit a signed workload returning an independently expected result and the selected peer. Keep the existing two-host instructions usable. Exercise canonical native package layouts and both supported OS filename formats. |
| Performance | Count local status subprocesses on successful enrollment and an idempotent repeat. Measure standalone CLI latency under a controlled status fixture. Confirm the change adds no periodic process to ordinary dispatch. Separate these figures from the existing workload benchmark. |
| Release and operations | Run locked workspace tests, format/lint, relevant Python tests, package checks and an independent code/evidence review. Publish only to the previously approved review branch after verification. Production signing and physical-host evidence retain their own gates. |

Report failures and fixture limits. Preserve current-source commands, UTC bounds, return codes and hashes for final qualification. Run all checks locally.
