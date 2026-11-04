# Maintainer and key rotation notes

Spec 12.1 requires a dated rotation note at least every 35 days, and a
release fails (`rotation_note_fresh` in `.github/workflows/release.yml`, i.e.
`cargo xtask rotation-note-check`) when the newest note is older than that.
A note is the standing statement "we looked at roles, keys and custody this
month and this is the state"; a no-change note is a valid note.

## Format

One level-2 heading per note, newest anywhere in the file (the check takes the
maximum date), heading starts with an ISO date:

```markdown
## YYYY-MM-DD - short title

- **Roles:** holders added / removed / unchanged (cross-check `docs/maintainers/roles.toml`).
- **Keys:** release-key custody, share holders, any ceremony run (link the record in `key-ceremony.md`).
- **Access:** repository, registry and signing-infrastructure access changes.
- **Next review:** YYYY-MM-DD (at most 35 days out).
- **Author:** handle
```

Only headings of the form `## YYYY-MM-DD` count as notes. The check counts days
in UTC; a note dated one day after the UTC date (your local date east of UTC)
is accepted, anything further in the future is rejected.

## Notes

## 2026-11-04 - Governance baseline

- **Roles:** every role in `docs/maintainers/roles.toml` still has a single
  declared holder; `cargo xtask bus-factor` is expected to report violations
  until second holders are seated (INV-BUS-1 is not yet met).
- **Keys:** no release key has been generated yet. The 2-of-3 ceremony and the
  rehearsal record template are in `key-ceremony.md`; the ceremony has not been
  run.
- **Access:** no changes.
- **Next review:** 2026-12-02.
- **Author:** thekozugroup
