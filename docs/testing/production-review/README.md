# Fixed production review rubric

`rubric-v1.json` is the frozen rubric, fixed before this review's new fixes.
It embeds all 34 actual §15 contract definitions verbatim, plus 23 production
checks. Its SHA-256 is pinned in `scripts/production_score.py`; changing the
rubric requires a separately versioned rubric, not a retroactive rerating.
The specification's summary says 35, but it defines 34 numbered propositions.

Every check is binary and mandatory. A check passes only when **every part** of
its written requirement has attributable evidence for the same source snapshot.
Missing evidence is not a pass; a demonstrated failure and missing evidence are
reported separately. The scorer calculates six separate percentages as
`100 × passes / checks`. Readiness requires each score to be **strictly above
95**, plus every architecture and production hard gate to pass. There is no
cross-metric average and no partial credit. Since every current check is a hard
gate, a ready candidate must in fact have 100% on all six metrics. The §7.0
performance numbers are the architecture's own requirements; the 5% regression
limit is an explicit prospective review threshold and requires an approved,
comparable historical baseline. Absence of one cannot pass.

The runner verifies evidence presence, SHA-256, exit status, reviewer attribution,
and exact candidate snapshot identifier. It **does not prove evidence is true,
that the commands exercised the stated behavior, or that a reviewer was
independent**. An independent reviewer must inspect the actual logs, hardware,
source, complete invocation, and assertions before recording a pass. Test names,
synthetic fixtures, compile-only checks, and a prior commit's logs do not prove a
real cross-host or governance gate. Keep sensitive evidence in a protected
workspace path and record its digest; do not copy secrets into this repository.

## Baseline and rerating

- `baseline-2026-11-26.md` preserves the previous semantic review. It is a
  historical record, not proof that its findings apply to the current source.
- `runs/baseline-unverified.json` is the conservative initial machine rating:
  no check is credited until evidence is bound to an exact source snapshot and
  independently reviewed against this frozen rubric. Its zero percentages mean
  **unverified**, not that every check was demonstrated to fail.
- Use a new, dated JSON run for each rerating; never edit a prior run or replace
  its evidence. Store evidence under `docs/testing/production-review/evidence/`
  or another workspace path. The source hash excludes only that evidence folder
  `runs/` to avoid a self-referential rating, and Python `__pycache__` directories; it includes tracked and
  non-ignored untracked files, their content, names, executable bits and symlink
  targets. Capture the hash only when the candidate tree is stable.

```bash
python3 -m unittest scripts.tests.test_production_score -v
python3 scripts/production_score.py --source-id
python3 scripts/production_score.py --run docs/testing/production-review/runs/baseline-unverified.json --historical
# New candidate runs require the current snapshot to match by default.
python3 scripts/production_score.py --run docs/testing/production-review/runs/NEW.json
```

A run contains `source_id` (`sha256:<digest>`), the exact `rubric_sha256`, and
one observation per rubric ID. Every observation has `status` (`pass`, `fail`,
or `not_evidenced`) and a concrete `reason`. A pass also requires `reviewer`,
`reviewed_at_utc`, and a nonempty `evidence` list. Each evidence entry has
`path` (workspace-relative), `sha256` (of the nonempty file), `source_id`,
`command`, `exit_code` (zero), `claim`, and `observed_at_utc`. An entry can also
cite a workspace-relative JSON `receipt_path` with the command or review method.
The scorer verifies that its
`source_before` and `source_after` match the candidate, its `log`, `sha256` and
`exit_code` match the evidence entry, and its UTC start and finish are ordered.
Earlier reviews can still cite a log directly. Attach enough
independent artifacts to establish **all** parts of the requirement. Negative
or unavailable evidence belongs in `reason`, with a source path where possible.
Historical mode preserves historical scores but never asserts current readiness.
The scorer exits 0 only for a fully ready current rating, 1 for a valid blocked rating,
and 2 for malformed inputs. It prints every blocker and all six scores as JSON.
