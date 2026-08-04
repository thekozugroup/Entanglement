# Entanglement Phase 1 Tutorial

This tutorial walks through the complete Phase 1 happy path: installing the
daemon, initializing your identity, building a plugin, loading it, invoking it,
and pairing a second device. Every command is shown with expected output.

Cross-references to deeper theory live in [docs/architecture.md](architecture.md).

---

## 1. Setup

### Option A — Homebrew (placeholder; not yet published)

```bash
brew tap entanglement-dev/tap
brew install entangled
```

### Option B — Docker (placeholder; not yet published)

```bash
docker pull ghcr.io/entanglement-dev/entangled:latest
docker run --rm -v ~/.entangle:/root/.entangle ghcr.io/entanglement-dev/entangled:latest version
```

### Option C — Build from source (works today)

```bash
git clone https://github.com/thekozugroup/Entanglement
cd Entanglement
cargo install --path crates/entangle-cli      # `entangle` CLI binary
cargo install --path crates/entangle-bin      # `entangled` daemon binary
```

Verify:

```
$ entangle --version
entangle 0.1.0

$ entangled --version
entangled 0.1.0
```

---

## 2. Initialize — Generate Your Identity

```bash
entangle init --non-interactive
```

Expected output:

```
Entanglement init
  Generating Ed25519 identity key...
  Writing ~/.entangle/identity.key
  Writing ~/.entangle/config.toml
  Writing ~/.entangle/keyring.toml

Identity fingerprint: a3f9…c7d1   ← your public key, hex-encoded SHA-256

Done. Run `entangle version` to verify.
```

`--non-interactive` skips the guided wizard (useful for CI). Omit it for a
step-by-step prompts version that lets you set a display name and preferred
broker URL.

> **Note:** The `~/.entangle/` directory contains your private key. Back it up.
> If you lose it you cannot sign future plugin releases under the same publisher
> fingerprint.

---

## 3. Inspect Your Identity

```bash
entangle version
```

Expected output:

```
entangle 0.1.0
identity: a3f9…c7d1          ← fingerprint (first 8 hex chars shown)
config:   ~/.entangle/config.toml
keyring:  1 key(s)
```

The **fingerprint** is the hex-encoded SHA-256 of your Ed25519 public key. It
acts as your publisher ID — every plugin you build is prefixed with it (e.g.
`a3f9c7d1/hash-it@0.1.0`). See [architecture.md §4](architecture.md#4-identity)
for the full identity model.

---

## 4. Build a Plugin

We will use the `hash-it` example: a pure-compute BLAKE3 hasher that declares
**zero capabilities** at tier 2. This contrasts with `hello-world` (tier 1,
also zero capabilities) to show the tier axis is independent of capability
count.

### 4.1 Add the Wasm target

```bash
rustup target add wasm32-wasip2
```

Output (first time):

```
info: downloading component 'rust-std' for 'wasm32-wasip2'
info: installing component 'rust-std' for 'wasm32-wasip2'
```

### 4.2 Build

From the workspace root:

```bash
cargo xtask hash-it build
```

Expected output:

```
[xtask] checking wasm32-wasip2 target...
[xtask] building hash-it plugin...
   Compiling blake3 v1.5.1
   Compiling entangle-sdk v0.1.0
   Compiling entangle-hash-it v0.1.0
    Finished release [optimized] target(s) in 8.42s
[xtask] reading identity key from /Users/alice/.entangle/identity.key
[xtask] publisher fingerprint: a3f9…c7d1
[xtask] wrote examples/hash-it/dist/plugin.wasm
[xtask] wrote examples/hash-it/dist/plugin.wasm.sig
[xtask] wrote examples/hash-it/dist/entangle.toml

[xtask] done. dist/:
  plugin.wasm
  plugin.wasm.sig
  entangle.toml  (plugin id: a3f9c7d1/hash-it)

Next steps:
  entangle keyring add a3f9…c7d1 --name self
  entangle plugins load examples/hash-it/dist/
```

If you see `wasm32-wasip2 target not installed`, re-run step 4.1.

---

## 5. Trust Your Publisher Key

Before the broker will accept your locally-built plugin, your own fingerprint
must be in the keyring:

```bash
entangle keyring add a3f9…c7d1 --name self
```

Expected output:

```
added a3f9c7d1... "self"
```

Run `entangle keyring list` at any time to see trusted publishers. See
[architecture.md §5](architecture.md#5-keyring) for the trust model.

---

## 6. Load the Plugin

```bash
entangle plugins load examples/hash-it/dist/ --allow-local
```

Expected output:

```
plugins: verifying signature...  ok
plugins: checking tier constraints...
  tier=2, capabilities=[]  →  ok (zero-capability tier-2 plugin)
plugins: registered a3f9c7d1/hash-it@0.1.0
```

`--allow-local` permits plugins whose manifest `id` was built from a local
keyring entry. In a production flow you would publish to the registry instead.

If you see `ENTANGLE-E0011: unknown publisher`, make sure you ran step 5 first.

---

## 7. Invoke the Plugin

```bash
entangle plugins invoke a3f9c7d1/hash-it@0.1.0 --input "hello"
```

Expected output:

```
9d54da…  (BLAKE3 hex of "hello\n")
```

Pass arbitrary bytes via `--input-file`:

```bash
echo -n "hello" | entangle plugins invoke a3f9c7d1/hash-it@0.1.0 --input-file -
# → ea8f763f29b62a3887c3c3f3f3a9f9d9...  (BLAKE3 of bare "hello", no newline)
```

The plugin writes one log line via the host-provided logging convenience:

```
[hash-it] hash-it: hashing 5 bytes
```

This log appears in `~/.entangle/logs/plugins.log` (or stdout if no daemon is
running).

---

## 8. Inspect Tier Enforcement

Tier 2 enforces that no capabilities in `[capabilities]` exceed what tier 2
permits. `hash-it` declares none, which is always fine. Let's deliberately
break it to see the error.

Edit `examples/hash-it/entangle.toml`, add a line under `[capabilities]`:

```toml
[capabilities]
host.docker-socket = true      # ← this is a tier-4 capability
```

Rebuild and try to load:

```bash
cargo xtask hash-it build
entangle plugins load examples/hash-it/dist/ --allow-local
```

Expected error:

```
Error ENTANGLE-E0042: capability 'host.docker-socket' requires tier >= 4,
  but plugin declares tier = 2.
  Fix: raise [plugin] tier to 4 in entangle.toml, or remove the capability.
```

The broker rejects the bundle before any Wasm executes. Tier enforcement is
purely manifest-driven at load time. See [architecture.md §7](architecture.md#7-tier-model)
for the full tier table.

Revert the change before continuing:

```bash
git checkout examples/hash-it/entangle.toml
cargo xtask hash-it build
entangle plugins load examples/hash-it/dist/ --allow-local
```

---

## 9. Daemon Mode

So far every command ran in-process. For persistent operation — and to support
multi-app plugin sharing — start the daemon:

```bash
# Terminal 1
entangled run
```

Expected output (illustrative — the daemon's exact banner lives in `entangle-bin`):

```
entangled 0.1.0
listening on ~/.entangle/sock
broker: ready
```

In a second terminal, all `entangle` CLI commands transparently talk to the
daemon via the Unix socket:

```bash
# Terminal 2
entangle plugins list
# → a3f9c7d1/hash-it@0.1.0  (tier=2, caps=[])

entangle plugins invoke a3f9c7d1/hash-it@0.1.0 --input "world"
# → <BLAKE3 hex of "world">
```

The daemon keeps the plugin registry in memory for the life of its process.
Persisting the registry across `entangled` restarts (so plugins reload
automatically on the next `entangled run`) is not implemented yet — Phase 2.
Stopping the daemon (`Ctrl-C`) is graceful, but you currently need to
`entangle plugins load` again after a restart.

---

## 10. Doctor

At any time, run:

```bash
entangle doctor
```

`entangle doctor` runs 13 structured checks and prints one `[ok]`/`[warn]`/
`[fail]`/`[skip]` line per check (see `crates/entangle-cli/src/cmd/doctor.rs`).
Expected output (healthy, daemon not running):

```
[ok]    identity                  Ed25519 keypair, fp a3f9…c7d1
[ok]    identity-perms            mode 0600
[ok]    config                    /home/alice/.entangle/config.toml
[ok]    keyring                   1 trusted publisher(s)
[ok]    peers                     0 trusted peer(s)
[ok]    dir-perms                 mode 0700
[ok]    rust-toolchain            rustc 1.91.0 (...)
[ok]    wasm32-wasip2             installed
[warn]  daemon-reachable          not running (start with `entangled run`) — socket /home/alice/.entangle/sock absent
[skip]  daemon-version-match      skipped (daemon not reachable)
[ok]    OS sandbox                Landlock available
[ok]    disk-space                42.0 GiB free
[skip]  clock-skew                skipped (daemon not reachable)

Summary: 10 ok, 1 warn, 0 fail, 2 skip
```

`warn` does not fail the command; `entangle doctor` only exits non-zero if any
check reports `[fail]` (e.g. a corrupt `identity.key` or a `peers.toml` parse
error). Run `entangled run` in another terminal to turn the two daemon-related
checks green.

---

## 11. Pair a Second Device

Pairing establishes mutual trust-on-first-use (TOFU) between two devices: each
side records the other's Ed25519 public key and display name in
`~/.entangle/peers.toml`, gated by a 6-digit code (read aloud / typed
out-of-band) plus a fingerprint comparison. The exchange happens over a
manual copy-paste channel in Phase 1. There is **no** `--respond`, `--accept`,
or `--finalize` flag, and the blobs are not colon-separated — see
`crates/entangle-cli/src/cmd/pair.rs` for the real implementation.

### 11.1 Initiator (device A)

```bash
entangle pair
```

Output:

```
Generating pairing material...
Code:         123-456  (read aloud — expires in 5 minutes)
Fingerprint:  a3f9…c7d1
Display name: alice-laptop

Paste this REQUEST blob to the other device's `entangle pair --responder`:

ENT-REQ-eyJpbml0aWF0b3JfcGVlcl9pZCI6Ii4uLiJ9

Waiting for ACCEPT blob (paste below, then press Enter):
>
```

Read the 6-digit code aloud to whoever is on device B and send them the
`ENT-REQ-...` blob over whatever out-of-band channel you trust (chat,
AirDrop, a shared file).

### 11.2 Responder (device B)

```bash
entangle pair --responder
```

Output:

```
Paste REQUEST blob (then press Enter):
> ENT-REQ-eyJpbml0aWF0b3JfcGVlcl9pZCI6Ii4uLiJ9

Initiator:             'alice-laptop'
Initiator fingerprint: a3f9…c7d1
Your fingerprint:      b71e…04aa

Verify with the other device that BOTH fingerprints match what it shows.
Then enter the 6-digit code displayed on the initiator: 123456
✓ Code matches

Paste this ACCEPT blob to the initiator:

ENT-ACC-eyJyZXNwb25kZXJfcGVlcl9pZCI6Ii4uLiJ9

Waiting for FINALIZE blob:
>
```

You can type the code with or without the dash — `entangle pair --code
123456` also works non-interactively. Send the `ENT-ACC-...` blob back to
the initiator.

### 11.3 Initiator receives the ACCEPT blob

Paste `ENT-ACC-...` at the initiator's "Waiting for ACCEPT blob" prompt. It
verifies the responder's signature and prints:

```
✓ Paired with peer 'bob-desktop' (b71e…04aa)

Paste this FINALIZE blob to the other device:

ENT-FIN-eyJzaWduYXR1cmVfaGV4IjoiLi4uIn0

✓ added to /home/alice/.entangle/peers.toml
```

Send the `ENT-FIN-...` blob back to the responder.

### 11.4 Responder receives the FINALIZE blob

Paste it at the responder's "Waiting for FINALIZE blob" prompt:

```
✓ Paired with peer 'alice-laptop' (a3f9…c7d1)
✓ added to /home/bob/.entangle/peers.toml
```

Both devices now have the other's public key and display name in
`peers.toml`. To trust plugins *published* by the other device's key, also
run `entangle keyring add <their_pubkey_hex> --name <label>` on each side —
pairing and publisher trust are separate keyrings.

### 11.5 Non-interactive / scripted pairing

Every prompt has a file-based flag so pairing can run in CI or across two
terminals on the same machine without hand-copying blobs:

| Flag | Side | Meaning |
|------|------|---------|
| `--responder` | either | act as the responder instead of the initiator |
| `--display-name <NAME>` | either | override the display name (default: hostname) |
| `--emit-request-file <PATH>` | initiator | write the REQUEST blob to a file instead of stdout |
| `--consume-accept-file <PATH>` | initiator | read the ACCEPT blob from a file instead of stdin |
| `--emit-finalize-file <PATH>` | initiator | write the FINALIZE blob to a file instead of stdout |
| `--request-file <PATH>` | responder | read the REQUEST blob from a file instead of stdin |
| `--code <CODE>` | responder | pass the 6-digit code non-interactively |
| `--emit-accept-file <PATH>` | responder | write the ACCEPT blob to a file instead of stdout |
| `--consume-finalize-file <PATH>` | responder | read the FINALIZE blob from a file instead of stdin |

The blob exchange itself stays manual (copy-paste, a shared file, or a QR
code you generate yourself) — automatic pairing over the mesh transports is
Phase 2. See [architecture.md §8](architecture.md#8-pairing) for the
protocol's threat model.

---

## 12. What Is NOT in Phase 1

Phase 1 covers local single-machine operation. The following are explicitly out
of scope and will ship in later phases:

| Feature | Spec section | Target phase |
|---------|-------------|--------------|
| Mesh transport over iroh (NAT-traversing P2P) | architecture.md §10 mesh.iroh | Phase 2 |
| Mesh transport over Tailscale | architecture.md §10 mesh.tailscale | Phase 2 |
| Distributed compute over real remote workers | architecture.md §11 | Phase 2 |
| MCP gateway server for agent-host integration | architecture.md §12 | Phase 2 |
| Plugin registry (publish / discover / update) | architecture.md §13 | Phase 3 |
| Audit log streaming to external SIEM | architecture.md §14 | Phase 3 |
| Multi-tenant broker (serve multiple users) | architecture.md §15 | Phase 3 |
| Hardware attestation (TPM, Secure Enclave) | architecture.md §16 | Phase 4 |

If you encounter an error code not listed in this tutorial, check the full
error reference in [architecture.md §appendix-errors](architecture.md#appendix-errors).

---

## Quick Reference

| Command | What it does |
|---------|-------------|
| `entangle init` | Generate identity key and config |
| `entangle version` | Show version and fingerprint |
| `entangle keyring add <fp> --name <n>` | Trust a publisher |
| `entangle keyring list` | List trusted publishers |
| `cargo xtask hash-it build` | Build + sign hash-it plugin |
| `cargo xtask hello-world build` | Build + sign hello-world plugin |
| `entangle plugins load <dir/> --allow-local` | Register a built plugin |
| `entangle plugins list` | List registered plugins |
| `entangle plugins invoke <id> --input <s>` | Call a plugin |
| `entangled run` | Start the background daemon |
| `entangle doctor` | Health check |
| `entangle pair` | Begin device pairing (initiator) |
| `entangle pair --responder` | Respond to a pairing request |

---

*Entanglement Phase 1 — see [architecture.md](architecture.md) for deeper reference.*
