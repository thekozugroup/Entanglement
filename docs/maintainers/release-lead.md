# Release Lead

## Responsibilities

You own the release pipeline: `.github/workflows/release.yml`, the `docker/Dockerfile`, the planned Homebrew tap (`entanglement-dev/tap`), sigstore signing on release artifacts, the changelog discipline, and the version cadence.

You sign releases with the project's release key (2-of-3 Shamir per spec §12.1). You're the final go/no-go on shipping.

## Onboarding

1. Spec §3.6 (OCI/tarball distribution), §12 (build phases + slip policy), §12.1 (bus factor + Shamir signing).
2. The full content of `.github/workflows/release.yml` and `docker/Dockerfile` — and the gaps marked "Phase 1.x".
3. Walk a dry-run release: build, package, sign locally, verify the signature with a clean keyring.
4. Read the slip-policy section in §12.2. Internalize that public ship-date moves transparently are a feature.

Record each monthly rotation review in `docs/governance/rotations.md` under a
`## YYYY-MM-DD` heading, with a bullet for each role such as
`- release-lead: @first-holder, @second-holder`. The release check matches
those handles against the committed roster, CODEOWNERS, and recent merged
pull requests to crates owned by each role.

## Stage and promote a release

A tag push builds the platform archives, checks release governance and tag CI,
and attaches Sigstore bundles to the exact staged archives. Use the artifacts
from that successful run for the publisher ceremony. The workflow expects the
externally approved Ed25519 public key in the repository variable
`ENTANGLE_RELEASE_PUBLISHER_KEY` as SubjectPublicKeyInfo PEM. Distribute that key
to users through a trusted channel independent of the archives.

Record the ceremony rehearsal in `docs/governance/key-ceremony.md` before
cutting the tag. After the required maintainer approvals and two-of-three
ceremony, the offline signing station can produce a raw signature for each
staged archive with OpenSSL 3. The key path refers to the locally reconstructed
release key.

```sh
openssl pkeyutl -sign -rawin -inkey "$RECONSTRUCTED_RELEASE_KEY" \
  -in "$TARBALL" -out "$TARBALL.sig"
```

Run the Release workflow manually on the same tag. Supply the successful
tag-push run ID as `staged_run`. Supply `publisher_signatures` as a JSON object
with keys `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`aarch64-apple-darwin`, and `x86_64-apple-darwin`. Each value contains the 128
hex characters from that target's 64-byte `.sig` file. The workflow downloads
the staged bytes, checks both signatures against its trusted key and the
tagged workflow identity, and publishes the verified assets. Private shares
and private keys stay with their custodians. Record ceremony and custody
evidence separately in the maintainers' authenticated release record.

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
