# Release-key ceremony (2-of-3 Shamir)

Covers ATC-REL-2 and the Ed25519 half of ATC-REL-1 (spec 12, 16.9). A release is
only trusted when it carries both a cosign (Rekor) bundle and an Ed25519
signature by the **release key** (`entangle release verify`). The release key is
never held whole by one person: it is split 2-of-3 and the original is destroyed.

Status: the ceremony has **not** been run for a real key. The rehearsal record
below is a template; fill one in for every rehearsal and for the real event.

## Roles

| Role | Who | Duty |
|---|---|---|
| Ceremony lead | release-lead | Runs the commands, keeps the record |
| Custodian A, B, C | three distinct maintainers | Each holds exactly one share |
| Witness | a maintainer who is not a custodian | Watches, countersigns the record |

No person is both custodian and witness. No custodian receives two shares.

## Preconditions

- An offline machine (no network, no swap on disk if avoidable) with the
  `entangle` binary built from a verified release and an encrypted or RAM-backed
  working directory (`mktemp -d` on tmpfs).
- Three removable media (one per custodian). Shares are text files; print a copy
  if the custodian also wants paper.

## Procedure

1. **Generate the key** (mode 0600, refuses to overwrite):

   ```sh
   entangle release key generate --out release.pem
   ```

   Record the printed `fingerprint` and `public key`.

2. **Split 2-of-3:**

   ```sh
   entangle release key split --threshold 2 --shares 3 release.pem --out-dir shares/
   ```

   This writes `shares/release.pem.share-1`, `-2`, `-3`, each one line
   `entangle-share-v1:<hex>`. Every share carries the split's set id, the
   threshold, its index and a checksum; mixing shares of different splits or a
   mistyped share is rejected, and a wrong share fails an integrity check
   instead of yielding a garbage key.

3. **Prove reconstruction before destroying anything.** On the same machine:

   ```sh
   entangle release key combine shares/release.pem.share-1 shares/release.pem.share-3 --out check.pem
   cmp release.pem check.pem && echo reconstruction OK
   ```

   Repeat for pairs (1,2) and (2,3) (different `--out` each time). Confirm that
   `entangle release key combine shares/release.pem.share-2 --out x.pem` fails
   with `need 2 shares`.

4. **Distribute** one share file per custodian onto their medium. Verify each
   custodian can read it, then remove `shares/` from the machine.

5. **Destroy the original** `release.pem`, `check.pem` and any `x.pem`
   (`shred -u`; on SSD/tmpfs, power-cycle the machine).

6. **Publish the public key** (never a share): add the public key to the
   release keyring on verifier machines with
   `entangle release key add <public-key-hex> --name release-2026`, and record
   the fingerprint in the signed release notes.

7. **Record** the ceremony (template below) and add a rotation note to
   `rotations.md`.

## Signing a release with two custodians

Two custodians bring their shares to the signing machine:

```sh
entangle release key combine A.share B.share --out release.pem
entangle release sign entanglement-v1.0.0-x86_64-unknown-linux-gnu.tar.gz --key release.pem
shred -u release.pem
```

The `.ed25519` file is uploaded next to the artifact and its cosign `.sigstore`
bundle. Verifiers run `entangle release verify <artifact>`.

## Properties (what the tests pin)

- Any 2 of the 3 shares reconstruct; 1 share does not (`not enough shares`), and
  one share is information-theoretically independent of the key (the unit test
  `single_share_is_consistent_with_every_secret` checks this exhaustively for a
  one-byte secret).
- Field arithmetic over GF(256) is branch-free and table-free
  (`crates/entangle-signing/src/shamir.rs`).
- Share integrity: per-share checksum, per-split set id, and a check trailer
  inside the shared payload.

## Rehearsal record (template)

Copy this block to `rotations.md` or an internal ticket for each rehearsal and for
the real ceremony. A rehearsal must use a throwaway key that is never added to
any keyring.

```text
Ceremony record
Date (UTC):                  YYYY-MM-DD
Kind:                        rehearsal | production
entangle version:            (output of `entangle version`)
Machine / medium:            (offline host id, tmpfs yes/no)
Ceremony lead:
Witness:
Custodians (A / B / C):
Key fingerprint:
Public key (hex):
Set id (printed by split):
Reconstruction checks:       (1,2) pass/fail   (1,3) pass/fail   (2,3) pass/fail
Single share rejected:       pass/fail
Original and temporary key files destroyed (method):
Shares delivered (custodian -> medium, initials):
Deviations / notes:
Signatures: lead ______  witness ______  custodians ______ ______ ______
```

### Rehearsal log

| Date | Kind | Result | Record |
|---|---|---|---|
| (none yet) | | | |
