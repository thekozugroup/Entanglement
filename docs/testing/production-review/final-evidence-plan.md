# Candidate evidence plan

Freeze the complete candidate and refresh the lockfile before collecting final
receipts. Record `python3 scripts/production_score.py --source-id` before and
after **each** run. A changed ID invalidates that run for candidate scoring;
retain it as historical evidence and rerun after the final freeze. Keep command,
exit status, UTC time, complete output, binary and corpus hashes, host and tool
versions with each receipt. Do not change source to make a run pass without a
new source ID and rerun. The grader does not establish evidence truth; a second
reviewer must compare the receipt and source to every part of each contract.

The fixed rubric has 57 checks. This is their evidence plan, not a pass claim:

| IDs | Candidate evidence |
|---|---|
| MAN-1–4; BRG-1–6; INT-1–5; STR-1–3 | One `cargo test --locked --workspace` run includes manifest, host, signed bridge vectors and ledger, semantic QUIC, and streaming integration tests. Independently inspect exact scenario, error variants, telemetry and hash assertions; run individually named filters only if an ambiguity needs investigation. An ignored test or passing name is not evidence. |
| PKG-1, PKG-3, PKG-4 | The same workspace run can exercise local serial packaging, missing-lockfile, and signed independent-rebuild tests. Inspect complete artifact hash and command assertions; a locally rebuilt fixture does not prove the published-artifact case. |
| PKG-2 | Require the completed configured hosted macOS 14, Ubuntu 22.04 and 24.04 builds and identical artifact hashes. A local build or declared workflow is insufficient. |
| WRP-1–3 | The workspace run covers the standard shell suite. Run `ENTANGLE_FISH=/path/to/verified/fish cargo test --locked -p entangle-cli --test wrapper -- --include-ignored` for explicit Zsh and Fish cases. Verify actual install opt-in, same-shell disable, and shadowing scenario independently; sourcing Fish manually does not prove normal Fish startup, and a child cannot see all parent aliases/functions. |
| MAX-1–3 | Run `python3 scripts/tests/max-tier.py <candidate-binary-dir>` in an isolated profile with the script's real pseudo-terminal, tier-5 fixture, config and audit assertions. Check exact 5→3 scenario and event codes in the frozen contract; 5→2 evidence is useful but not identical. |
| MIR-1–2 | Workspace OCI tests exercise signed publisher separation and signed mirror listing on loopback. Inspect scenario-specific assertions and test real HTTPS registry/mirror in an authorized environment; do not treat a mocked registry as production interoperability. |
| REL-1–2 | Run release verifier negative and valid-signature harness with pinned verified Cosign; separately require an actual production-signed 1.0 RC and real two-of-three release-key ceremony/reconstruction record. Ephemeral test keys and historical proof fixtures cannot stand in for custody. |
| BUS-1–2 | Run `scripts/check-release-governance.py` against the real roster, GitHub history, CODEOWNERS, and authentic current rotation record. Do not fabricate holders, events or timestamps. Preserve exit status and CI/issue evidence. |
| COR-CLI, COR-REMOTE | Run `plugins/smoke_test.py <candidate-entangle> <candidate-entangled> --two-node` using the saved Python environment. Capture all seven workloads, selected peer per remote call, zero-plugin coordinator, raw/file outputs, binary hashes and output; same-host loopback is not physical-network evidence. |
| COR-PLATFORMS; INTEROP-LINUX, INTEROP-MAC | Require final-source full hosted CI plus real execution on each supported physical architecture/OS. Compilation, cross-linking, emulation or workflow declarations alone do not satisfy independent hardware execution. |
| AUTH-LIVE | Run live daemon trust tests covering unknown, observer, revoked, removed, corrupt trust and both dispatch directions; include proof the change occurred while daemons were running. |
| AUTH-WASI | Run filesystem escape/permissions negative tests on actual supported OS targets, including trailing symlinks and rename. Runtime-only Linux loopback cannot substitute for macOS or other requested targets. |
| AUTH-CHAIN | Run configured `cargo deny --locked --all-features check advisories bans licenses sources` on the candidate with a freshly verified official RustSec snapshot and all shipped standalone lockfiles. Retain date, DB commit, unfiltered findings and exits; do not add unreviewed suppressions. |
| REL-RESTART, REL-PARTITION, REL-LIMITS | On supported actual hosts, test restart/recovery and time-bounded network partition/reconnect, trust revocation and overloaded resource bounds. Record exact observations and actual timing; simulated loopback alone is insufficient for the two-host gates. |
| INTEROP-WAN, INTEROP-TAILNET, INTEROP-LAN | Use separate real hosts/network domains. Confirm public NAT/direct and relay paths separately; use the documented private-tailnet harness with two real tailnet hosts and actual ACLs; verify real LAN multicast without manual routes. Container/namespace proxies are useful but must not be substituted for physical hosts. |
| PERF-LLM, PERF-IMAGE, PERF-TEST | Run the full architecture §7.0 workloads on the specified real hardware and dataset. Preserve real 70B first-token and sustained-token samples, 8,000 RAW/three-desktop speedup, and workspace-wide distributed Rust tests including actual flaky semantics. A one-shot guest, 24 derived JPEGs, one test target, injected flaky fixture or same-VM scaling is not a substitute. |
| PERF-BASELINE | Run final candidate and an approved comparable baseline with raw measurements, source/binary hashes, hardware, sample counts and methodology; show at most 5% regression. Report image fixed/unrestricted and wire microbenchmarks separately, and preserve misses and uncertainty. No approved comparable baseline is `not_evidenced`. |
| OPS-RELEASE | Build and independently verify/install actual final release artifacts and provenance on all four supported physical OS/architecture pairs; compare source rebuild checksums. A local package or dry run does not suffice. |
| OPS-GOVERNANCE | Require real verified roster, CODEOWNERS activity, 35-day rotation note, key ceremony and automated gate execution. Missing people, evidence or permission are external blockers. |
| OPS-RECOVERY | On supported hosts verify encrypted backup/restore of identity, trust and state on a fresh node, continuity, and failure cases. A unit test or self-roundtrip without distinct node evidence is incomplete. |
| OPS-SECURITY | Require independently attributable security review and disclosure/incident rehearsal with no unresolved critical/high issues, not a successful test suite. |
| OPS-CI | Verify actual final candidate CI results and branch protection requiring those jobs. A local workflow parse or unchecked action file is insufficient. |

The serialized AgentSession tests mutate their own process's current directory:
`cargo test --locked -p entangle-agent-host --test session -- --ignored --test-threads=1`.
They prove adapter snapshot/restore only, not agent sandbox or MCP gateway.
Keep their receipt separate from the 57 required checks unless it directly proves
one. Likewise, the informational ATC name inventory cannot award any check.
