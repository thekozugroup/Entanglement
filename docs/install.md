# Installing Entanglement

> ## Start here
>
> **There is no published release yet**, so the `curl … | sh` one-liner and the
> Homebrew formula cannot work today — they only ever install prebuilt release
> tarballs, and there are none. Build from source instead:
>
> ```bash
> git clone https://github.com/thekozugroup/Entanglement
> cd Entanglement
> ./scripts/bootstrap.sh
> ```
>
> That needs a Rust toolchain (1.91+). If you would rather not install one, use
> [Docker](#2-docker) instead. Everything else on this page is documented
> honestly as either *works today* or *waiting on a release*.

Entanglement ships two binaries:

| Binary | What it is | Typical use |
|--------|------------|-------------|
| `entangled` | the daemon — runs the kernel and serves JSON-RPC 2.0 over a Unix socket | one long-running process per device |
| `entangle` | the CLI — talks to that daemon | interactive / scripted operator commands |

Everything either binary reads or writes lives under `~/.entangle/`
(`config.toml`, `identity.key`, `keyring.toml`, `peers.toml`, and the `sock`
Unix socket). There is **no config-directory flag** — the daemon resolves that
path from `$HOME`, so whatever runs `entangled` must have the same `$HOME` as
the user running `entangle`.

---

## Which method should I use?

Ordered by what actually works right now.

| # | Method | Works today? | Needs Rust? | Best for |
|---|--------|--------------|-------------|----------|
| 1 | [`scripts/bootstrap.sh`](#1-from-source-recommended-today) (from source) | **Yes** | yes (1.91+) | everyone, right now |
| 2 | [Docker](#2-docker) | **Yes**\* | no (builds in the image) | Linux servers; strongest isolation |
| 3 | [`cargo install --git`](#3-cargo-install---git) | **Yes** | yes (1.91+) | no clone wanted; installs from the default branch |
| 4 | [systemd](#4-systemd-bare-metal-linux) | **Yes**, once you have binaries | either | bare-metal Linux servers |
| 5 | [Install script (`curl \| sh`)](#5-install-script-requires-a-published-release) | **No** — needs a release | no | workstations, once v0.1.0 is cut |
| 6 | [Homebrew](#6-homebrew-requires-a-published-release) | **No** — needs a release | no | macOS / Linuxbrew, once v0.1.0 is cut |

\* Docker needs no release and no host toolchain, and `docker-compose.yml`
validates cleanly (`docker compose config`). The image build itself was **not**
executed while writing this page — no Docker daemon was available — so treat it
as "should work, commands verified against the files" rather than "observed
end-to-end". Method 1 *was* run end to end.

### Supported platforms

Building from source works anywhere the Rust toolchain and Wasmtime do. The
**release** pipeline targets exactly four triples, which is what methods 5 and 6
will consume:

| OS | Architecture | Release target triple |
|----|--------------|-----------------------|
| Linux (glibc) | x86_64 | `x86_64-unknown-linux-gnu` |
| Linux (glibc) | aarch64 | `aarch64-unknown-linux-gnu` |
| macOS | Apple silicon | `aarch64-apple-darwin` |
| macOS | Intel | `x86_64-apple-darwin` |

Windows is WSL2-only in Phase 1 — `entangled run` requires Unix domain sockets
and refuses to start elsewhere. Native AppContainer support is Phase 5. musl
(Alpine) is not a release target; build from source or use the container image.

---

## 1. From source (recommended today)

### The scripted path

[`scripts/bootstrap.sh`](../scripts/bootstrap.sh) is the companion to
`install.sh`: same conventions, same safety bar, but it compiles from your
checkout instead of downloading a release, so it does not need one to exist.

```bash
git clone https://github.com/thekozugroup/Entanglement
cd Entanglement
./scripts/bootstrap.sh --dry-run      # see exactly what it would do
./scripts/bootstrap.sh
```

What it does:

1. Checks that `cargo` and `rustc` exist and that Rust is **1.91 or newer** (the
   workspace MSRV, pinned by `rust-toolchain.toml`). It never installs a
   toolchain for you — it points you at <https://rustup.rs>.
2. Checks for the **`wasm32-wasip2`** target that plugins compile to, and offers
   to add it with `rustup target add wasm32-wasip2`. The two binaries build fine
   without it; you only need it to compile plugins. It will not touch your
   toolchain unprompted — when stdin is not a terminal it prints the command and
   moves on.
3. Runs `cargo install --path crates/entangle-cli --locked` and the same for
   `crates/entangle-bin`, installing `entangle` and `entangled`.
4. Smoke-tests the result with `entangle --version`.
5. Warns if the install directory is not on your `PATH`, or if a different
   `entangle` earlier on your `PATH` would win.
6. Runs `entangle init` **only if `~/.entangle/identity.key` does not exist.**
   If you already have an identity it says so and leaves it completely alone —
   overwriting it breaks every pairing you have and the old private key is
   unrecoverable.

Like `install.sh`, it **never calls `sudo`**, never edits your shell rc files,
and refuses to run as root unless you pass `--allow-root`.

### Options

```
--prefix DIR        Install prefix; binaries land in DIR/bin. If DIR ends in
                    /bin its parent is used (cargo appends "bin" itself).
                    Default: $PREFIX, else $CARGO_HOME, else $HOME/.cargo
                    (=> $HOME/.cargo/bin)
--clone-to DIR      git clone the repo into DIR first, then build there.
                    Refuses to write into a non-empty directory.
--cli-only          Install only the `entangle` CLI.
--daemon-only       Install only the `entangled` daemon.
--add-wasm-target   Add wasm32-wasip2 without asking.
--skip-wasm-target  Do not check for or add wasm32-wasip2.
--skip-init         Do not run `entangle init` at the end.
--dry-run           Print every command that would run; change nothing.
--allow-root        Permit running as root (refused by default).
--force             Pass --force to cargo install (rebuild/reinstall).
-h, --help          Show help.
```

Because it needs the `crates/` tree, `bootstrap.sh` **cannot be piped from
curl** the way `install.sh` can. If you have no checkout yet it can make one:

```bash
curl -fsSLO https://raw.githubusercontent.com/thekozugroup/Entanglement/main/scripts/bootstrap.sh
sh bootstrap.sh --clone-to ~/src/Entanglement
```

### The manual path

Exactly what the script automates, if you would rather drive it yourself:

```bash
git clone https://github.com/thekozugroup/Entanglement
cd Entanglement

# Both binaries into ./target/release/
cargo build --release --workspace --bins --locked

# Or install them onto your PATH (~/.cargo/bin by default)
cargo install --path crates/entangle-cli --locked   # installs `entangle`
cargo install --path crates/entangle-bin --locked   # installs `entangled`
```

Note the crate-name / binary-name split, which matters for `cargo uninstall`:

| Package (crate) | Binary it installs |
|-----------------|--------------------|
| `entangle-cli` | `entangle` |
| `entangle-bin` | `entangled` |

To build plugins you also need the WASM target:

```bash
rustup target add wasm32-wasip2
cargo xtask hello-world build       # builds + signs the bundled example
```

A release build of this workspace compiles Wasmtime and Iroh; budget several GB
of disk and a few minutes of CPU on a first build.

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the full dev loop and
[`docs/tutorial.md`](./tutorial.md) for a hands-on walkthrough.

---

## 2. Docker

The container image is the recommended Linux server path, and the only path that
needs **no Rust toolchain on your machine** today — the toolchain lives in the
builder stage. It builds both binaries and runs `entangled` as a non-root
`entangle` user with `HOME=/var/lib/entangle`, so all state lands in
`/var/lib/entangle/.entangle/`.

Note there is **no published image to pull yet** either (the GHCR push happens
on a release tag), so build it locally.

### docker compose

```bash
git clone https://github.com/thekozugroup/Entanglement
cd Entanglement
docker compose -f docker/docker-compose.yml up --build
docker compose -f docker/docker-compose.yml down          # stop
docker compose -f docker/docker-compose.yml down -v       # stop + delete state
```

The compose service is hardened: `read_only: true`, `cap_drop: [ALL]`,
`no-new-privileges`, a 16 MB tmpfs `/tmp`, and a named `entangle-data` volume
for the only writable path the daemon needs.

`docker-compose.yml` sets `network_mode: host` so `mesh.local` mDNS discovery
reaches the LAN. That works on **Linux hosts only**; on Docker Desktop for Mac
"host" is the VM's network, not your Mac's. See
[`docker/README.md`](../docker/README.md) for details and workarounds.

### Plain docker build / run

From the **repository root** (the build context needs `crates/` and `Cargo.lock`):

```bash
docker build -f docker/Dockerfile -t entangledev/entangle .

docker run -d \
  --name entangled \
  -v ent:/var/lib/entangle \
  entangledev/entangle
```

The image's `ENTRYPOINT` is `entangled` with a default command of `run`, so the
container starts the daemon with no extra arguments. In Phase 1 the daemon
listens only on a Unix socket — no ports are published.

Run CLI commands inside the container (they share the volume, hence the same
`~/.entangle`):

```bash
docker exec -it entangled entangle init --non-interactive
docker exec -it entangled entangle doctor
docker exec -it entangled entangle mesh status
```

Both the image `HEALTHCHECK` and the compose `healthcheck` run
`entangled status`, which round-trips a `version` RPC over the socket — unlike
`entangle doctor`, it exits non-zero when the daemon is dead or wedged.

### Published image (after a release)

Tagged releases also push a multi-arch (`linux/amd64`, `linux/arm64`) image
with SBOM and provenance. Once v0.1.0 exists:

```bash
docker pull ghcr.io/thekozugroup/entanglement:<version>
```

---

## 3. `cargo install --git`

No clone required — cargo fetches the default branch and builds it:

```bash
cargo install --git https://github.com/thekozugroup/Entanglement entangle-cli   # the `entangle` CLI
cargo install --git https://github.com/thekozugroup/Entanglement entangle-bin   # the `entangled` daemon
```

Package names are `entangle-cli` / `entangle-bin`; the binaries they install are
`entangle` and `entangled`. Add `--locked` to build against the committed
`Cargo.lock`.

This installs whatever is on the default branch, not a released version, so it
moves as the branch moves. For a pinned build use `--tag` or `--rev` once tags
exist, or [method 1](#1-from-source-recommended-today).

> **Previously broken, now fixed.** Until recently this failed with
> `failed to update submodule 'tools/graphify' — no URL configured`: the repo
> carried a gitlink with no `.gitmodules` entry, and `cargo install --git`
> always runs a submodule update. Plain `git clone` tolerated it, which is why
> building from a clone kept working. The stale gitlink has been removed. If you
> hit this error, you are on an older commit — update and retry.

---

## 4. systemd (bare-metal Linux)

[`packaging/entangled.service`](../packaging/entangled.service) is a hardened
unit: dedicated `entangle` user, `StateDirectory=entangle` at mode 0700,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, empty capability bounding
set, `SystemCallFilter=@system-service`, and `RestrictAddressFamilies` limited
to `AF_UNIX`/`AF_INET`/`AF_INET6`/`AF_NETLINK` (the last three are for mDNS).

Get the binaries first (method 1 or 2 above — `bootstrap.sh` installs into your
user prefix, so copy them out of `~/.cargo/bin` or `./target/release/`), then:

```bash
sudo useradd --system --user-group --home /var/lib/entangle entangle
sudo install -m0755 target/release/entangled /usr/local/bin/entangled
sudo install -m0755 target/release/entangle  /usr/local/bin/entangle
sudo install -m0644 packaging/entangled.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now entangled
```

Check on it:

```bash
systemctl status entangled
journalctl -u entangled -f
```

`Environment=HOME=/var/lib/entangle` in the unit is **required** — the daemon
has no config-dir flag and a system service otherwise has no usable home. State
therefore lives in `/var/lib/entangle/.entangle/`. To run CLI commands against
that daemon, run them as the `entangle` user:

```bash
sudo -u entangle env HOME=/var/lib/entangle entangle init --non-interactive
sudo -u entangle env HOME=/var/lib/entangle entangle doctor
```

> `MemoryDenyWriteExecute` is deliberately **not** set: the daemon embeds the
> wasmtime JIT, which needs to map executable pages.

---

## 5. Install script (requires a published release)

> **Not usable yet.** This project has **zero published releases**, so there is
> no tarball to download. Run today, the script exits non-zero and points you
> back at methods 1 and 2. Everything below becomes correct the moment a
> `v0.1.0` tag is pushed — nothing here needs to change.

```bash
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Entanglement/main/scripts/install.sh | sh
```

Prefer to read before you run (always a good habit for `curl | sh`):

```bash
curl -fsSLO https://raw.githubusercontent.com/thekozugroup/Entanglement/main/scripts/install.sh
less install.sh
sh install.sh
```

What it will do:

1. Detects your OS and CPU and maps them to one of the four release targets
   above (Rosetta-translated shells on Apple silicon are detected and get the
   native `aarch64` build).
2. Resolves the latest release tag, or the one you passed with `--version`.
3. Downloads `entanglement-<tag>-<target>.tar.gz` **and** its `.sha256`.
4. Verifies the SHA-256 digest. On a mismatch it deletes the archive and exits
   non-zero — nothing is ever extracted before the checksum passes.
5. Installs `entangle` and `entangled` into `$HOME/.local/bin` (or your
   `--prefix`), then runs `entangle --version` to prove the binary works.

### Options

```
--version X.Y.Z     Install a specific release (default: latest).
                    The leading "v" is optional.
--prefix DIR        Install prefix. If DIR ends in /bin it is used verbatim,
                    otherwise "/bin" is appended.
                    Default: $PREFIX, else $HOME/.local  (=> $HOME/.local/bin)
--dry-run           Print the resolved platform, URLs and destination; download
                    and install nothing.
--allow-root        Permit running as root (refused by default).
--force             Reinstall even when that version is already present.
-h, --help          Show help.
```

`--dry-run` works today and is a useful way to check platform detection — with
no release to resolve it substitutes a `vX.Y.Z` placeholder and tells you so.

Two behaviours worth knowing about:

- **It never calls `sudo`.** If the target directory is not writable it tells
  you so and exits. Installing into `/usr/local/bin` means either making that
  directory writable by you, or running the script yourself under `sudo` with
  `--allow-root`.
- **It refuses to run as root** unless you pass `--allow-root`, so a piped
  one-liner cannot quietly scatter root-owned binaries across a shared prefix.

If `$HOME/.local/bin` is not on your `PATH`, the script prints the line to add:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile
```

### Verify the release yourself (stronger than the checksum)

Every release asset is also signed with cosign (keyless / sigstore, with SLSA
build provenance) and carries a BLAKE3 sidecar. The installer checks SHA-256;
[`scripts/verify-release.sh`](../scripts/verify-release.sh) checks all three.

```bash
TAG=v0.1.0
TARGET=x86_64-unknown-linux-gnu
BASE="https://github.com/thekozugroup/Entanglement/releases/download/${TAG}"
TARBALL="entanglement-${TAG}-${TARGET}.tar.gz"

curl -fsSLO "${BASE}/${TARBALL}"
curl -fsSLO "${BASE}/${TARBALL}.sha256"
curl -fsSLO "${BASE}/${TARBALL}.b3"
curl -fsSLO "${BASE}/${TARBALL}.sigstore"

./scripts/verify-release.sh "${TARBALL}"   # from a repo checkout
tar -xzf "${TARBALL}"
install -m0755 "entanglement-${TAG}-${TARGET}/entangle"  ~/.local/bin/
install -m0755 "entanglement-${TAG}-${TARGET}/entangled" ~/.local/bin/
```

`verify-release.sh` needs `sha256sum` (coreutils), plus `b3sum` and `cosign` for
the BLAKE3 and signature checks — it warns and skips those two if the tools are
missing, so install them if you want the full check to actually run.

---

## 6. Homebrew (requires a published release)

> **Not usable yet**, for two reasons: there is no release tarball to pour
> from, and the formula in this repo is still a template whose `version` and
> four `sha256` values are literal `PLACEHOLDER_*` strings. It deliberately
> fails loudly rather than installing something unverified. The tap
> (`homebrew-entanglement`) is populated when a release is cut.

```bash
brew install thekozugroup/entanglement/entangle
brew services start entangle      # runs `entangled run` in the background
```

The formula source lives at
[`packaging/homebrew/entangle.rb`](../packaging/homebrew/entangle.rb) and is
copied into the tap when a release is cut. It installs both binaries from the
prebuilt release tarball (no Rust toolchain needed), generates shell completions
from the binary itself, and defines a `service` block so `brew services` can
supervise the daemon.

The service intentionally runs as your user with your normal `$HOME`, because
`entangled` and `entangle` must agree on `~/.entangle`. Run `entangle init`
once before starting the service.

```bash
brew services stop entangle
brew services restart entangle
```

---

## First run

`bootstrap.sh` does this step for you when you have no identity yet. To do it by
hand:

```bash
entangle init                      # interactive wizard
entangle init --non-interactive    # accept defaults: transports=local, max_tier=5, new identity
```

`init` creates `~/.entangle/` at mode 0700 containing:

| File | Mode | Contents |
|------|------|----------|
| `identity.key` | 0600 | your Ed25519 device identity (never share it) |
| `config.toml` | 0644 | `[mesh] transports`, `multi_node`; `[security] max_tier_allowed` |
| `keyring.toml` | 0600 | trusted publisher keys |
| `peers.toml` | 0600 | the trusted-peer allowlist |

`init` is idempotent: with all four files present it prints
`Already initialized` and changes nothing. Importing a *different* key over an
existing `identity.key` prompts for confirmation and backs the old one up first.

Then start the daemon and check your work:

```bash
entangled run                 # foreground (Phase 1 has no daemonize mode)

# in another terminal
entangle doctor               # identity, config, keyring, peers, daemon reachability
entangle version              # CLI + crate + daemon versions
entangle mesh status
entangle plugins list
```

`entangle doctor` exits 0 even when the daemon is down — it reports that as a
warning. Use `entangled status` when you need a hard up/down check (that is what
the container healthcheck uses).

Optional shell completions:

```bash
entangle completions bash > ~/.local/share/bash-completion/completions/entangle
entangle completions zsh  > "${fpath[1]}/_entangle"
entangle completions fish > ~/.config/fish/completions/entangle.fish
```

`entangle completions` also accepts `powershell` and `elvish`.

### Your first plugin

The plugin subcommands available in this revision are `new`, `build`, `list`,
`load`, `unload`, and `invoke`:

```bash
rustup target add wasm32-wasip2                 # once
cargo xtask hello-world build                   # prints your publisher fingerprint
entangle keyring add <fingerprint> --name self
entangle plugins load examples/hello-world/dist/ --allow-local
entangle plugins invoke <fingerprint>/hello-world@0.1.0 --input world
```

`entangle plugins new <name>` scaffolds a fresh plugin project that builds and
loads as-is, and `entangle plugins build <dir>` builds and signs any plugin
directory — not just the bundled examples.

> **Landing separately, not verified here.** A `entangle quickstart` command, an
> `entangle plugins install <NAME>` / `entangle plugins available` pair, and a
> plugin catalog resolved from `--catalog`, `$ENTANGLE_CATALOG`, `./plugins`, or
> `~/.entangle/catalog` — plus a top-level `plugins/` directory of ready-made
> plugins (json-query, csv-stats, markdown-html, image-resize, qr-encode,
> compress) — are being added in parallel with this document. They did **not**
> exist in the revision this page was written and tested against, so none of
> those commands were run. Treat the intended flow as
> `entangle quickstart` → `entangle plugins available` →
> `entangle plugins install <NAME>`, and check `entangle plugins --help` for
> what your build actually has.

---

## Upgrading

| Installed with | Upgrade |
|----------------|---------|
| `bootstrap.sh` | `git pull && ./scripts/bootstrap.sh --force` |
| source (manual) | `git pull && cargo install --path crates/entangle-cli --locked --force` (and `entangle-bin`) |
| Docker | `docker compose -f docker/docker-compose.yml up --build -d` |
| systemd | install the new binaries, then `sudo systemctl restart entangled` |
| install script | re-run it (add `--force` to reinstall the same version) — *after a release exists* |
| Homebrew | `brew update && brew upgrade entangle` — *after a release exists* |

Stop the daemon before replacing its binary on disk; the install script's atomic
rename keeps a running process safe, but the new code only takes effect after a
restart.

---

## Uninstall

Removing the binaries never removes your identity or config — that is a
separate, deliberate step.

**Built from source (`bootstrap.sh` or `cargo install --path`)** — uninstall by
*package* name, not binary name:

```bash
cargo uninstall entangle-cli      # removes the `entangle` binary
cargo uninstall entangle-bin      # removes the `entangled` binary
```

If you used `--prefix`/`--root`, point cargo at the same place, or just delete
the two files:

```bash
cargo uninstall --root "$HOME/.local" entangle-cli entangle-bin
# or
rm -f ~/.cargo/bin/entangle ~/.cargo/bin/entangled
```

A `cargo build` (rather than `cargo install`) leaves nothing on your `PATH`;
`rm -rf target/` reclaims the disk.

**Install script / manual tarball:**

```bash
rm -f ~/.local/bin/entangle ~/.local/bin/entangled
# or wherever you pointed --prefix
```

**Docker:**

```bash
docker compose -f docker/docker-compose.yml down -v   # -v also deletes the state volume
# or, for a plain `docker run`:
docker rm -f entangled
docker volume rm ent
docker rmi entangledev/entangle
```

**Homebrew:**

```bash
brew services stop entangle
brew uninstall entangle
```

**systemd:**

```bash
sudo systemctl disable --now entangled
sudo rm /etc/systemd/system/entangled.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/entangled /usr/local/bin/entangle
sudo rm -rf /var/lib/entangle      # deletes the daemon's identity and config
sudo userdel entangle
```

**Finally, the state directory** (this destroys your device identity; every
device you have paired with will no longer recognise you):

```bash
rm -rf ~/.entangle
```

Also worth reclaiming after a source build:

```bash
rustup target remove wasm32-wasip2   # if you added it only for this project
```

---

## Troubleshooting

### Install-time

**`error: could not resolve a release to download`** (from `install.sh`) — the
expected result today: there are no published releases. Use
[method 1](#1-from-source-recommended-today) or [method 2](#2-docker). The
script's own error text lists both.

**`error: failed to update submodule 'tools/graphify'`** (from
`cargo install --git`) — a repository defect, not your setup. See
[method 3](#3-cargo-install---git-currently-broken) for the cause and the
workaround (clone, then `cargo install --path`).

**`fatal: no submodule mapping found in .gitmodules for path 'tools/graphify'`**
— the same defect, surfacing if you run `git submodule update --init` in a
clone. You do not need to: nothing in the workspace builds from
`tools/graphify`, and it is not a workspace member. Ignore it and build
normally.

**`Rust X.Y.Z is too old`** (from `bootstrap.sh`) — the workspace MSRV is
**1.91** because iroh 1.0 requires it. With rustup, `rust-toolchain.toml`
fetches the right toolchain automatically; otherwise
`rustup toolchain install 1.91` or install rustup from <https://rustup.rs>.

**`no Rust toolchain found`** (from `bootstrap.sh`) — install rustup, or use
[Docker](#2-docker), which needs no toolchain on the host.

**`this script must be run from inside an Entanglement checkout`** — you piped
`bootstrap.sh` from curl, or ran a copy from outside the repo. It compiles from
source, so it needs the `crates/` tree. Either clone first, or pass
`--clone-to DIR`.

**`refusing to run as root`** — intended, in both scripts. Re-run as your normal
user, or pass `--allow-root` if you are scripting a container image build.

**The build dies partway through** — a release build of this workspace compiles
Wasmtime and Iroh and wants several GB of disk plus real RAM. On a small VM,
`cargo build --release -j2` (or `CARGO_BUILD_JOBS=2`) trades wall time for peak
memory. Expect roughly 10 minutes for a cold release build of the CLI on a
modest machine; the daemon reuses most of that work.

**`warning: package 'spin v0.9.8' in Cargo.lock is yanked in registry
'crates-io', consider running without --locked`** — a warning, not an error, and
the build succeeds. Keep `--locked`: it is what makes the build reproducible and
matches what CI and `docker/Dockerfile` do. Do not drop it to silence this.

**`brew install` fails on a `PLACEHOLDER_SHA256_*` string** — intended. The
formula is a template until a release fills in its `version` and four digests;
see [method 6](#6-homebrew-requires-a-published-release).

**`SHA-256 MISMATCH`** — the installer deletes the archive and installs nothing.
Retry once (a truncated download looks the same); if it persists, treat it as a
supply-chain issue and report it at
<https://github.com/thekozugroup/Entanglement/security/advisories/new>.

### Run-time

**`entangle: command not found`** — the install directory is not on your `PATH`.
For a source install that is `~/.cargo/bin`; for the install script,
`~/.local/bin`. Add it:

```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.profile
```

**Another `entangle` wins** — an older copy is earlier on your `PATH`. Both
scripts warn about this. Find it with `command -v entangle` and remove it, or
reorder `PATH`.

**`error: daemon not running at ~/.entangle/sock`** — start it with
`entangled run`, or pass `--allow-local` to run a throwaway in-process kernel
(no persistent state; testing only).

**Daemon fails to start under systemd or Docker** — almost always `$HOME`. The
daemon resolves `~/.entangle` from `$HOME`; the unit sets
`Environment=HOME=/var/lib/entangle` and the image sets
`ENV HOME=/var/lib/entangle` for exactly this reason. Don't remove them.

**GLIBC version errors on Linux** — the release binaries are glibc builds from
Ubuntu 24.04 runners. On older distros or on musl (Alpine), use the container
image or build from source.

**Peers are not discovered** — Phase 1 discovery is mDNS on the LAN
(`mesh.local`). Under Docker it needs `network_mode: host` on a Linux host;
Docker Desktop for Mac cannot bridge mDNS to your LAN.

For the full operator runbook — config schema, error codes, backup/restore —
see [`docs/operations.md`](./operations.md).

---

## What a `v0.1.0` release unblocks

Cutting and pushing a `v0.1.0` tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml) and turns on,
with no further doc changes:

- `curl … | sh` via [`scripts/install.sh`](../scripts/install.sh) — the script is
  already correct and only fails today because tag resolution finds nothing.
- Homebrew, once the release job substitutes `version` and the four `sha256`
  values into [`packaging/homebrew/entangle.rb`](../packaging/homebrew/entangle.rb)
  and copies it into the tap.
- `docker pull ghcr.io/thekozugroup/entanglement:<version>`.
- `scripts/verify-release.sh` against real `.sha256` / `.b3` / `.sigstore`
  sidecars.

A release does **not** fix `cargo install --git` — that needs the
`tools/graphify` gitlink removed (or a `.gitmodules` entry added) in a separate
commit.
