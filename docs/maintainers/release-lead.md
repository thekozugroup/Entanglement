# Release Lead

## Responsibilities

You own the release pipeline: `.github/workflows/release.yml`, the `docker/Dockerfile`, the planned Homebrew tap (`entanglement-dev/tap`), sigstore signing on release artifacts, the changelog discipline, and the version cadence.

You sign releases with the project's release key (2-of-3 Shamir per spec §12.1). You're the final go/no-go on shipping.

## Onboarding

1. Spec §3.6 (OCI/tarball distribution), §12 (build phases + slip policy), §12.1 (bus factor + Shamir signing).
2. The full content of `.github/workflows/release.yml` and `docker/Dockerfile` — and the gaps marked "Phase 1.x".
3. Walk a dry-run release: build, package, sign locally, verify the signature with a clean keyring.
4. Read the slip-policy section in §12.2. Internalize that public ship-date moves transparently are a feature.

## Decisions you can make solo

- Cutting a patch release (x.y.Z) when the change is a clean bugfix with no public API impact and CI is green.
- Updating the Homebrew tap formulas to match a new release.
- Posting changelogs.

## Decisions that need quorum (≥2 release-leads + 1 security-lead for any release; +1 core-runtime-lead for minor or major)

- Cutting a minor release (x.Y.0).
- Cutting a major release (X.0.0).
- Releasing without a signed artifact.
- Adding a new distribution channel (crates.io, snap, MSI installer).
- Yanking a release.

## Escalation

If a release would slip its declared date by more than 30 days, post a slip notice (per §12.2) and move the public date. Don't ship under pressure that compromises the §11 invariants — if the choice is "ship late or ship insecure," ship late.
