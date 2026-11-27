# Pairing with the release CLI

The archived Linux CLI completed both channels. Each case used two disposable homes with distinct keys on one Linux host. Both processes exited 0 and each `peers.toml` contained exactly one trusted peer with the other device's independently checked Ed25519 public key and peer ID. Both stores used mode `0600`. The transcript retains the shipped prompts and replaces codes, blobs, fingerprints, keys and temporary paths. [Recorded prompts and receipt](pairing-receipt.json)

## Default network channel

On device B run `entangle pair --responder`. On A run `entangle pair`, select B if prompted, and enter the six-digit code shown on B. Compare both fingerprints across the devices and answer `y` on both. When discovery is unavailable, use a reachable `entangle pair --peer <long-address>` command printed by B.

The check used the printed address to connect over loopback QUIC and disabled mDNS for reproducibility. It verified that both stores were absent before confirmation. The recorded network transcript includes Iroh relay channel shutdown diagnostics. Both commands then finished successfully. [Default path integration test](../../../../../../crates/entangle-cli/tests/pair.rs)

## Manual channel

1. On A run `entangle pair --manual`. Read A's six-digit code over a trusted channel and give B the complete `ENT-REQ-` blob.
2. On B run `entangle pair --responder --manual` and paste the request. Compare the displayed fingerprints with the operators of both devices. Enter the code A displayed and return the complete `ENT-ACC-` blob to A.
3. On A paste the accept blob. Confirm the reported responder fingerprint against B's screen, then send the `ENT-FIN-` blob to B. A records B after producing that blob. If the fingerprint differs, stop and remove A's entry with `entangle mesh untrust <peer-id>`.
4. On B paste the finalize blob. Confirm each side saw `added to …/peers.toml`, then check both entries with `entangle mesh peers`.

Any blob file option selects the same manual channel. On the manual path B receives the code from A. On the default network path A receives it from B. [Pair command implementation](../../../../../../crates/entangle-cli/src/cmd/pair.rs)

## Reproduce this receipt

Use Python 3.11 with PTY support, OpenSSL and `b3sum` on Linux. Supply the frozen checkout and the corresponding canonical release archive and manifest. The driver checks SHA-256 and BLAKE3 across the archive and confirms the extracted CLI hash before running it. It creates and removes its own private key files in disposable directories.

```sh
python3 -B replay.py \
  --repo "$FROZEN_REPO" \
  --manifest "$RELEASE_MANIFEST" \
  --archive "$RELEASE_ARCHIVE" \
  --b3sum "$(command -v b3sum)" \
  --out "$NEW_RECEIPT_DIRECTORY"
```

[Replay driver](replay.py)
