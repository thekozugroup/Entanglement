# Candidate 8e07cc25 iteration verdict: disqualified

Candidate commit `8e07cc254e0489b882918f2aa2fa71b4c4d9c6ca`, source `sha256:b303a993baa13a6ec89c614795c6e0dc82ab317d8d3579bfb44fe9f3fb2492f4`, did not pass qualification. The exact-source locked default-parallel `cargo test --locked --workspace --no-fail-fast` completed with **781 passed, 1 failed, 29 ignored** across 104 result sections; exit 101. `trusted_executor_empty_allowlist_refused_e0303` expected the runtime integrity error but observed `Placement(NoWorkers)` ([receipt](workspace-test.json), [full output](workspace-test.log)). The command finished all remaining sections; repeated qualification suites were not started.

The fresh [governance check](governance-real.json) exited 1: all five roles had one named holder and the rotation record was missing. The [16-graph dependency audit](dependencies.json) passed advisories, bans and sources on every graph, and licenses on 15; the separately archived allocator diagnostic graph lacked its own license metadata and failed the strict license check. This is recorded independently of its production-shipping status. Fmt, diff, actionlint, Clippy and strict rustdoc passed according to [static qualification](static-qualification.json).

This iteration was disqualified, so no 57-gate score is asserted. The earlier sealed `bb70a619` assessment remains unchanged.
