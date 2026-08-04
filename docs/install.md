# Installing Entanglement

Entanglement ships two binaries:

| Binary | What it is | Typical use |
|--------|------------|-------------|
| `entangled` | the daemon — runs the kernel and serves JSON-RPC 2.0 over a Unix socket | one long-running process per device |
| `entangle` | the CLI — talks to that daemon | interactive / scripted operator commands |

Both live in the same release tarball and the same container image. Everything
either binary reads or writes lives under `~/.entangle/` (`config.toml`,
`identity.key`, `keyring.toml`, `peers.toml`, and the `sock` Unix socket). There
is **no config-directory flag** — the daemon resolves that path from `$HOME`, so
whatever runs `entangled` must have the same `$HOME` as the user running
`entangle`.

> **Release status.** The install script, Homebrew formula, and GHCR image all
> pull from GitHub Releases, which are produced by
> [`.github/workflows/release.yml`](../.github/workflows/release.yml) when a
> `v*.*.*` tag is pushed. Until the first tag lands there is nothing to
> download — use [Docker](#docker) or [build from source](#build-from-source)
> in the meantime.

---

## Choose an install method

| Method | Best for | Section |
|--------|----------|---------|
| `curl … \| sh` | Linux/macOS workstations; no toolchain required | [Install script](#install-script-recommended) |
| Homebrew | macOS (and Linuxbrew), with `brew services` for the daemon | [Homebrew](#homebrew) |
| Docker | Linux servers; strongest default isolation | [Docker](#docker) |
| systemd | bare-metal Linux servers, no container runtime | [systemd](#systemd-bare-metal-linux) |
| From source | contributors, unsupported platforms | [Build from source](#build-from-source) |

### Supported platforms

Releases are built for exactly four targets:

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

## Install script (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Entanglement/main/scripts/install.sh | sh
```

Prefer to read before you run (always a good habit for `curl | sh`):

```bash
curl -fsSLO https://raw.githubusercontent.com/thekozugroup/Entanglement/main/scripts/install.sh
less install.sh
sh install.sh
```

What it does:

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

Examples:

```bash
sh install.sh --dry-run                       # see exactly what would happen
sh install.sh --version 0.1.0                 # pin a version
sh install.sh --prefix "$HOME/.local"         # => ~/.local/bin (the default)
sh install.sh --prefix /usr/local             # => /usr/local/bin, if writable
```

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

## Homebrew

```bash
brew install thekozugroup/entanglement/entangle
brew services start entangle      # runs `entangled run` in the background
```

The formula source lives in this repo at
[`packaging/homebrew/entangle.rb`](../packaging/homebrew/entangle.rb) and is
copied into the tap when a release is cut. It installs both binaries from the
prebuilt release tarball (no Rust toolchain needed), generates shell
completions from the binary itself, and defines a `service` block so
`brew services` can supervise the daemon.

The service intentionally runs as your user with your normal `$HOME`, because
`entangled` and `entangle` must agree on `~/.entangle`. Run `entangle init`
once before starting the service.

```bash
brew services stop entangle
brew services restart entangle
```

> The formula in this repo is a template with clearly marked placeholders for
> `version` and the four per-target `sha256` values. It will refuse to install
> until a release fills them in — see the comment block at the top of the file.

---

## Docker

The container image is the recommended Linux server path. It builds both
binaries and runs `entangled` as a non-root `entangle` user with
`HOME=/var/lib/entangle`, so all state lands in `/var/lib/entangle/.entangle/`.

### Build and run locally

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
docker exec -it entangled entangle doctor
docker exec -it entangled entangle mesh status
```

### docker compose

```bash
docker compose -f docker/docker-compose.yml up --build
docker compose -f docker/docker-compose.yml down          # stop
docker compose -f docker/docker-compose.yml down -v       # stop + delete state
```

The compose service is hardened: `read_only: true`, `cap_drop: [ALL]`,
`no-new-privileges`, a 16 MB tmpfs `/tmp`, and a named `entangle-data` volume
for the only writable path the daemon needs.

Both the image and the compose service healthcheck run `entangled status`,
which round-trips a `version` RPC over the socket — unlike `entangle doctor`,
it exits non-zero when the daemon is dead or wedged.

`docker-compose.yml` sets `network_mode: host` so `mesh.local` mDNS discovery
reaches the LAN. That works on Linux hosts only; on Docker Desktop for Mac
"host" is the VM's network, not your Mac's. See
[`docker/README.md`](../docker/README.md) for details and workarounds.

### Published image

Tagged releases also push a multi-arch (`linux/amd64`, `linux/arm64`) image
with SBOM and provenance:

```bash
docker pull ghcr.io/thekozugroup/entanglement:<version>
```

---

## systemd (bare-metal Linux)

[`packaging/entangled.service`](../packaging/entangled.service) is a hardened
unit: dedicated `entangle` user, `StateDirectory=entangle` at mode 0700,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, empty capability bounding
set, `SystemCallFilter=@system-service`, and `RestrictAddressFamilies` limited
to `AF_UNIX`/`AF_INET`/`AF_INET6`/`AF_NETLINK` (the last three are for mDNS).

Install the binaries system-wide first (the install script writes to your user
prefix, so copy them or use `--prefix`), then:

```bash
sudo useradd --system --user-group --home /var/lib/entangle entangle
sudo install -m0755 entangled /usr/local/bin/entangled
sudo install -m0755 entangle  /usr/local/bin/entangle
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
sudo -u entangle env HOME=/var/lib/entangle entangle doctor
```

> `MemoryDenyWriteExecute` is deliberately **not** set: the daemon embeds the
> wasmtime JIT, which needs to map executable pages.

---

## Build from source

Requires Rust 1.91+ (pinned by `rust-toolchain.toml`).

```bash
git clone https://github.com/thekozugroup/Entanglement
cd Entanglement

# Both binaries into ./target/release/
cargo build --release --workspace --bins --locked

# Or install them onto your PATH (~/.cargo/bin by default)
cargo install --path crates/entangle-cli --locked   # entangle
cargo install --path crates/entangle-bin --locked   # entangled
```

To build the example plugins you also need the WASM target:

```bash
rustup target add wasm32-wasip2
cargo xtask hello-world build
```

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the full dev loop and
[`docs/tutorial.md`](./tutorial.md) for a hands-on walkthrough.

---

## First run

```bash
entangle init                 # interactive wizard
entangle init --non-interactive   # accept defaults: transports=local, max_tier=5, new identity
```

`init` creates `~/.entangle/` at mode 0700 containing:

| File | Mode | Contents |
|------|------|----------|
| `identity.key` | 0600 | your Ed25519 device identity (never share it) |
| `config.toml` | 0644 | `[mesh] transports`, `multi_node`; `[security] max_tier_allowed` |
| `keyring.toml` | 0600 | trusted publisher keys |
| `peers.toml` | 0600 | the trusted-peer allowlist |

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

---

## Upgrading

| Installed with | Upgrade |
|----------------|---------|
| install script | re-run it (add `--force` to reinstall the same version) |
| Homebrew | `brew update && brew upgrade entangle` |
| Docker | `docker compose -f docker/docker-compose.yml up --build -d` (the compose service builds from source), or `docker pull ghcr.io/thekozugroup/entanglement:<version>` |
| systemd | install the new binaries, then `sudo systemctl restart entangled` |
| source | `git pull && cargo install --path crates/entangle-cli --locked --force` |

Stop the daemon before replacing its binary on disk; the install script's
atomic rename keeps a running process safe, but the new code only takes effect
after a restart.

---

## Uninstall

Removing the binaries never removes your identity or config — that is a
separate, deliberate step.

**Install script / manual:**

```bash
rm -f ~/.local/bin/entangle ~/.local/bin/entangled
# or wherever you pointed --prefix
```

**Homebrew:**

```bash
brew services stop entangle
brew uninstall entangle
```

**Docker:**

```bash
docker compose -f docker/docker-compose.yml down -v   # -v also deletes the state volume
# or, for a plain `docker run`:
docker rm -f entangled
docker volume rm ent
docker rmi entangledev/entangle
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

**From source:**

```bash
cargo uninstall entangle-cli
cargo uninstall entangle-bin
```

**Finally, the state directory** (this destroys your device identity; every
device you have paired with will no longer recognise you):

```bash
rm -rf ~/.entangle
```

---

## Troubleshooting

**`entangle: command not found`** — the install directory is not on your
`PATH`. Add `$HOME/.local/bin` (see above), or re-run the installer with
`--prefix` pointed somewhere already on `PATH`.

**The installer says another `entangle` will win** — an older copy is earlier
on your `PATH`. Find it with `command -v entangle` and remove it, or reorder
`PATH`.

**`SHA-256 MISMATCH`** — the installer deletes the archive and installs
nothing. Retry once (a truncated download looks the same); if it persists,
treat it as a supply-chain issue and report it at
<https://github.com/thekozugroup/Entanglement/security/advisories/new>.

**`refusing to run as root`** — intended. Re-run as your normal user, or pass
`--allow-root` if you are scripting a container image build.

**`error: daemon not running at ~/.entangle/sock`** — start it with
`entangled run`, or pass `--allow-local` to run a throwaway in-process kernel
(no persistent state; testing only).

**Daemon fails to start under systemd or Docker** — almost always `$HOME`. The
daemon resolves `~/.entangle` from `$HOME`; the unit sets
`Environment=HOME=/var/lib/entangle` and the image sets `ENV HOME=/var/lib/entangle`
for exactly this reason. Don't remove them.

**GLIBC version errors on Linux** — the release binaries are glibc builds from
Ubuntu 24.04 runners. On older distros or on musl (Alpine), use the container
image or build from source.

**Peers are not discovered** — Phase 1 discovery is mDNS on the LAN
(`mesh.local`). Under Docker it needs `network_mode: host` on a Linux host;
Docker Desktop for Mac cannot bridge mDNS to your LAN.

For the full operator runbook — config schema, error codes, backup/restore —
see [`docs/operations.md`](./operations.md).
