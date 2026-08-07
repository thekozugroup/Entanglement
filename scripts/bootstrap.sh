#!/bin/sh
# Entanglement bootstrap — build and install from source, from zero.
#
#   git clone https://github.com/thekozugroup/Entanglement
#   cd Entanglement
#   ./scripts/bootstrap.sh
#
# This is the companion to scripts/install.sh. The difference:
#
#   install.sh    downloads a prebuilt, signed release tarball from GitHub
#                 Releases. No Rust toolchain needed — but it needs a PUBLISHED
#                 RELEASE, and as of today this project has none.
#   bootstrap.sh  compiles the two binaries from the checkout you are standing
#                 in. Needs a Rust toolchain, needs no release. Works today.
#
# What it does, in order:
#   1. Checks prerequisites: cargo/rustc >= 1.91 (the workspace MSRV).
#   2. Checks for the wasm32-wasip2 target that plugins compile to, and offers
#      to add it via rustup.
#   3. `cargo install --locked` the CLI (`entangle`) and the daemon (`entangled`).
#   4. Runs `entangle init` only if there is no identity yet. It NEVER touches
#      an existing ~/.entangle/identity.key.
#   5. Prints the next steps.
#
# Like install.sh, this script deliberately does NOT: call sudo, modify your
# shell rc files, send telemetry, or overwrite an existing device identity.

set -eu
# pipefail is not in POSIX; enable it only on shells that support it (bash, zsh,
# ksh, busybox ash). dash silently lacks it and must not abort here.
# shellcheck disable=SC3040
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi

REPO="thekozugroup/Entanglement"
REPO_URL="https://github.com/${REPO}"
MSRV_MAJOR=1
MSRV_MINOR=91
WASM_TARGET="wasm32-wasip2"

# ── Defaults (overridable by flags / env) ────────────────────────────────────
PREFIX="${PREFIX:-}"     # empty = cargo's own default root ($CARGO_HOME|~/.cargo)
DRY_RUN=0
ALLOW_ROOT=0
FORCE=0
SKIP_INIT=0
CLONE_TO=""              # non-empty = clone the repo there first
WASM_MODE="ask"          # ask | add | skip
WHICH="both"             # both | cli | daemon

# ── Output helpers (identical to install.sh) ─────────────────────────────────
# Everything informational goes to stderr so the script stays pipe-friendly.
info() { printf '%s\n' "$*" >&2; }
step() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

# Is stdin a terminal? Used to decide whether we may prompt at all.
interactive() { [ -t 0 ]; }

usage() {
    cat <<EOF
Entanglement bootstrap — build and install from source

Usage:
  ./scripts/bootstrap.sh [options]

Run it from a checkout of ${REPO} (or pass --clone-to to make one).

Options:
  --prefix DIR        Install prefix. Binaries land in DIR/bin. If DIR ends in
                      /bin, its parent is used (cargo appends "bin" itself).
                      Default: \$PREFIX, else cargo's default
                      (\$CARGO_HOME, else \$HOME/.cargo => \$HOME/.cargo/bin)
  --clone-to DIR      git clone ${REPO_URL} into DIR first, then build there.
                      Refuses to write into a non-empty directory.
  --cli-only          Install only the \`entangle\` CLI.
  --daemon-only       Install only the \`entangled\` daemon.
  --add-wasm-target   Add the ${WASM_TARGET} target without asking.
  --skip-wasm-target  Do not check for or add ${WASM_TARGET}.
  --skip-init         Do not run \`entangle init\` at the end.
  --dry-run           Print every command that would run; change nothing.
  --allow-root        Permit running as root (refused by default).
  --force             Pass --force to cargo install (rebuild/reinstall even if
                      the same version is already installed).
  -h, --help          Show this help.

Environment:
  PREFIX              Same as --prefix.
  CARGO_HOME          Respected as cargo's default install root.
  CARGO_BUILD_JOBS    Cap build parallelism (e.g. 2). A release build of this
                      workspace compiles Wasmtime and Iroh; on a small or
                      disk-constrained machine, lowering this trades wall time
                      for peak disk and memory.

Examples:
  ./scripts/bootstrap.sh --dry-run
  ./scripts/bootstrap.sh
  ./scripts/bootstrap.sh --prefix "\$HOME/.local"
  ./scripts/bootstrap.sh --clone-to ~/src/Entanglement --add-wasm-target

Why this script exists:
  The advertised \`curl … | sh\` path (scripts/install.sh) downloads a release
  tarball, and ${REPO} has no published release yet. Until a v0.1.0 tag is
  cut, building from source is the install path that actually works. See
  docs/install.md.
EOF
}

# ── Argument parsing ─────────────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
        --prefix)
            [ $# -ge 2 ] || die "--prefix requires an argument (e.g. --prefix \$HOME/.local)"
            PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            PREFIX="${1#--prefix=}"
            shift
            ;;
        --clone-to)
            [ $# -ge 2 ] || die "--clone-to requires an argument (e.g. --clone-to ~/src/Entanglement)"
            CLONE_TO="$2"
            shift 2
            ;;
        --clone-to=*)
            CLONE_TO="${1#--clone-to=}"
            shift
            ;;
        --cli-only)
            WHICH="cli"
            shift
            ;;
        --daemon-only)
            WHICH="daemon"
            shift
            ;;
        --add-wasm-target)
            WASM_MODE="add"
            shift
            ;;
        --skip-wasm-target)
            WASM_MODE="skip"
            shift
            ;;
        --skip-init)
            SKIP_INIT=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --allow-root)
            ALLOW_ROOT=1
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown option: $1"
            ;;
        esac
    done
}

# ── Dry-run plumbing ─────────────────────────────────────────────────────────
# run <cmd...> — echo in dry-run mode, execute otherwise.
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] ' >&2
        printf '%s ' "$@" >&2
        printf '\n' >&2
        return 0
    fi
    "$@"
}

# ── Prerequisite checks ──────────────────────────────────────────────────────
# Print the numeric version rustc reports, e.g. "1.91.1" from
# "rustc 1.91.1 (ed61e7d7e 2025-11-07)".
rustc_version() {
    rustc --version 2>/dev/null | awk '{ print $2 }' | tr -d '\r'
}

# Compare the detected rustc against the workspace MSRV. Nightly/beta strings
# like "1.93.0-nightly" still parse, because we only read the first two fields.
check_rust_version() {
    _v="$(rustc_version)"
    [ -n "$_v" ] || die "could not parse 'rustc --version' output — is rustc working?"

    _maj="${_v%%.*}"
    _rest="${_v#*.}"
    _min="${_rest%%.*}"
    # Strip any pre-release suffix off the minor field (e.g. 91-nightly).
    _min="${_min%%-*}"

    case "${_maj}${_min}" in
    *[!0-9]*)
        warn "could not parse a numeric version out of 'rustc ${_v}' — skipping the MSRV check"
        return 0
        ;;
    esac

    if [ "$_maj" -lt "$MSRV_MAJOR" ] ||
        { [ "$_maj" -eq "$MSRV_MAJOR" ] && [ "$_min" -lt "$MSRV_MINOR" ]; }; then
        die "Rust ${_v} is too old — this workspace needs ${MSRV_MAJOR}.${MSRV_MINOR} or newer.
  rust-toolchain.toml pins ${MSRV_MAJOR}.${MSRV_MINOR}, so if you have rustup it will
  fetch the right toolchain automatically once it is installed:
      rustup toolchain install ${MSRV_MAJOR}.${MSRV_MINOR}
  Without rustup, upgrade your distro's Rust or install rustup:
      https://rustup.rs"
    fi
    info "    rustc ${_v} (>= ${MSRV_MAJOR}.${MSRV_MINOR}, ok)"
}

check_prereqs() {
    step "Checking prerequisites"

    if ! have cargo || ! have rustc; then
        die "no Rust toolchain found (need both 'cargo' and 'rustc').
  Install rustup, then re-run this script:
      curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh
      . \"\$HOME/.cargo/env\"
  See https://rustup.rs — this script will not install a toolchain for you."
    fi
    info "    cargo   $(cargo --version 2>/dev/null || echo '?')"
    check_rust_version

    if have rustup; then
        info "    rustup  $(rustup --version 2>/dev/null | head -n 1)"
    else
        warn "rustup not found. The build will use whatever 'cargo' is on your PATH,"
        info "         and rust-toolchain.toml's pinned ${MSRV_MAJOR}.${MSRV_MINOR} cannot be honoured."
    fi
}

# ── wasm32-wasip2 (the target plugins compile to) ────────────────────────────
wasm_target_installed() {
    rustup target list --installed 2>/dev/null | grep -qx "$WASM_TARGET"
}

ensure_wasm_target() {
    if [ "$WASM_MODE" = "skip" ]; then
        info "    ${WASM_TARGET}: check skipped (--skip-wasm-target)"
        return 0
    fi

    if ! have rustup; then
        warn "cannot check for the ${WASM_TARGET} target without rustup."
        info "         The two binaries build fine without it; you only need it to COMPILE"
        info "         plugins from source. Install rustup if you plan to write plugins."
        return 0
    fi

    if wasm_target_installed; then
        info "    ${WASM_TARGET}: already installed"
        return 0
    fi

    info ""
    info "  The ${WASM_TARGET} target is not installed."
    info "  It is not needed to build 'entangle' or 'entangled', but it IS needed to"
    info "  compile plugins from source (cargo xtask hello-world build, and the plugins"
    info "  under plugins/ and examples/)."
    info ""

    _add=0
    case "$WASM_MODE" in
    add) _add=1 ;;
    ask)
        if [ "$DRY_RUN" -eq 1 ]; then
            info "    [dry-run] would ask whether to run: rustup target add ${WASM_TARGET}"
            return 0
        fi
        if interactive; then
            printf '  Add it now with "rustup target add %s"? [Y/n] ' "$WASM_TARGET" >&2
            read -r _ans || _ans=""
            case "$_ans" in
            "" | y | Y | yes | YES | Yes) _add=1 ;;
            *) _add=0 ;;
            esac
        else
            # Non-interactive (piped/CI): never make toolchain changes unasked.
            warn "not a terminal, so not adding it. Re-run with --add-wasm-target, or:"
            info "             rustup target add ${WASM_TARGET}"
            return 0
        fi
        ;;
    esac

    if [ "$_add" -eq 1 ]; then
        step "Adding the ${WASM_TARGET} target"
        run rustup target add "$WASM_TARGET" ||
            die "'rustup target add ${WASM_TARGET}' failed.
  Re-run this script with --skip-wasm-target to continue without it; you will
  not be able to compile plugins from source until it is installed."
    else
        info "    skipped — add it later with: rustup target add ${WASM_TARGET}"
    fi
}

# ── Repo location ────────────────────────────────────────────────────────────
# Resolve the repository root. Normally this script lives at <root>/scripts/,
# so the root is the parent of the script's directory.
script_dir() {
    _s="$0"
    # Follow one level of symlink if readlink is available.
    if [ -L "$_s" ] && have readlink; then
        _l="$(readlink "$_s" 2>/dev/null || true)"
        case "$_l" in
        /*) _s="$_l" ;;
        ?*) _s="$(dirname "$_s")/$_l" ;;
        esac
    fi
    (cd "$(dirname "$_s")" && pwd)
}

looks_like_repo() {
    [ -f "$1/Cargo.toml" ] && [ -d "$1/crates/entangle-cli" ] && [ -d "$1/crates/entangle-bin" ]
}

clone_repo() {
    _dest="$1"
    have git || die "git is required for --clone-to but was not found."
    if [ -e "$_dest" ]; then
        # Refuse to clone into anything that already has content.
        [ -d "$_dest" ] || die "--clone-to ${_dest} exists and is not a directory."
        if [ -n "$(ls -A "$_dest" 2>/dev/null || true)" ]; then
            if looks_like_repo "$_dest"; then
                step "Reusing the existing checkout at ${_dest}"
                return 0
            fi
            die "--clone-to ${_dest} is not empty and does not look like an Entanglement checkout.
  Pick an empty directory, or cd into your existing checkout and run
  ./scripts/bootstrap.sh from there."
        fi
    fi
    step "Cloning ${REPO_URL} into ${_dest}"
    run git clone "$REPO_URL" "$_dest" ||
        die "git clone failed. Check your network, or clone it yourself and run
  ./scripts/bootstrap.sh from inside the checkout."
}

resolve_repo_root() {
    if [ -n "$CLONE_TO" ]; then
        clone_repo "$CLONE_TO"
        if [ "$DRY_RUN" -eq 1 ] && ! looks_like_repo "$CLONE_TO"; then
            # Nothing was actually cloned in dry-run mode; keep going anyway.
            printf '%s\n' "$CLONE_TO"
            return 0
        fi
        looks_like_repo "$CLONE_TO" || die "${CLONE_TO} does not look like an Entanglement checkout after cloning."
        (cd "$CLONE_TO" && pwd)
        return 0
    fi

    _sd="$(script_dir)"
    for _cand in "$(dirname "$_sd")" "$PWD"; do
        if looks_like_repo "$_cand"; then
            printf '%s\n' "$_cand"
            return 0
        fi
    done

    die "this script must be run from inside an Entanglement checkout.
  It compiles the binaries from source, so it needs the crates/ tree — it
  cannot be piped straight from curl the way scripts/install.sh can.

  Either clone it yourself:
      git clone ${REPO_URL}
      cd Entanglement
      ./scripts/bootstrap.sh

  or let this script do it:
      ./scripts/bootstrap.sh --clone-to ~/src/Entanglement"
}

# ── Install root ─────────────────────────────────────────────────────────────
# `cargo install --root R` writes binaries to R/bin. Accept a --prefix that
# ends in /bin (as install.sh does) by handing cargo its parent.
resolve_cargo_root() {
    _p="$1"
    if [ -z "$_p" ]; then
        printf '%s\n' "${CARGO_HOME:-${HOME:-}/.cargo}"
        return 0
    fi
    case "$_p" in
    */bin) printf '%s\n' "$(dirname "$_p")" ;;
    *) printf '%s\n' "${_p%/}" ;;
    esac
}

# ── Build + install one crate ────────────────────────────────────────────────
# --locked pins to the committed Cargo.lock, so a drifting registry cannot
# silently change the dependency graph out from under a verified build.
# The two branches exist so --force stays a properly quoted argument rather
# than an unquoted variable that happens to word-split.
cargo_install_crate() {
    if [ "$FORCE" -eq 1 ]; then
        run cargo install --path "${ROOT_DIR}/crates/${1}" --locked --root "$CARGO_ROOT" --force
    else
        run cargo install --path "${ROOT_DIR}/crates/${1}" --locked --root "$CARGO_ROOT"
    fi
}

# ── Identity ─────────────────────────────────────────────────────────────────
maybe_init() {
    _bindir="$1"

    if [ "$SKIP_INIT" -eq 1 ]; then
        info ""
        step "Skipping 'entangle init' (--skip-init)"
        return 0
    fi

    _dir="${HOME:-}/.entangle"
    _id="${_dir}/identity.key"

    if [ -e "$_id" ]; then
        info ""
        step "Existing identity found at ${_id} — leaving it alone"
        info "    This script will NOT regenerate or overwrite a device identity."
        info "    Overwriting it would break every pairing you already have and the"
        info "    old private key is unrecoverable. Run 'entangle doctor' to check it."
        return 0
    fi

    info ""
    step "No identity at ${_id} — running 'entangle init'"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "    [dry-run] ${_bindir}/entangle init --non-interactive"
        return 0
    fi

    if interactive; then
        # Interactive wizard: lets the operator choose transports and max tier.
        "${_bindir}/entangle" init || die "'entangle init' failed. Re-run it by hand: ${_bindir}/entangle init"
    else
        "${_bindir}/entangle" init --non-interactive ||
            die "'entangle init --non-interactive' failed. Re-run it by hand: ${_bindir}/entangle init"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    if [ "$(id -u 2>/dev/null || echo 1000)" = "0" ] && [ "$ALLOW_ROOT" -ne 1 ]; then
        die "refusing to run as root.
  Building and installing as root writes root-owned binaries into a shared
  prefix and creates ~/.entangle for the WRONG user — the daemon and the CLI
  must agree on \$HOME. Re-run as your normal user, or pass --allow-root if you
  really mean it (e.g. in a container image build)."
    fi

    [ -n "${HOME:-}" ] || die "\$HOME is not set — this script needs it for ~/.entangle and the default prefix."

    ROOT_DIR="$(resolve_repo_root)"
    CARGO_ROOT="$(resolve_cargo_root "$PREFIX")"
    BINDIR="${CARGO_ROOT}/bin"

    case "$WHICH" in
    both) CRATES="entangle-cli entangle-bin" ;;
    cli) CRATES="entangle-cli" ;;
    daemon) CRATES="entangle-bin" ;;
    *) die "internal error: bad --cli-only/--daemon-only state" ;;
    esac

    info ""
    info "  checkout    ${ROOT_DIR}"
    info "  install to  ${BINDIR}"
    case "$WHICH" in
    both) info "  binaries    entangle (CLI), entangled (daemon)" ;;
    cli) info "  binaries    entangle (CLI)" ;;
    daemon) info "  binaries    entangled (daemon)" ;;
    esac
    info ""

    if [ "$DRY_RUN" -eq 1 ]; then
        step "Dry run — nothing will be built, written, or initialized."
        info ""
    fi

    check_prereqs
    ensure_wasm_target

    # ── Build + install ──────────────────────────────────────────────────────
    for _crate in $CRATES; do
        step "Building and installing ${_crate} (release; this takes a few minutes)"
        if ! cargo_install_crate "$_crate"; then
            die "'cargo install --path crates/${_crate}' failed.
  Scroll up for the compiler error. Common causes:
    - 'No space left on device'  -> a release build of this workspace compiles
      Wasmtime and Iroh and needs several GB free. Free some, then re-run;
      cargo reuses what it already built. CARGO_BUILD_JOBS=2 lowers peak usage.
    - Rust older than ${MSRV_MAJOR}.${MSRV_MINOR}     -> rustup toolchain install ${MSRV_MAJOR}.${MSRV_MINOR}
    - out of RAM (killed)        -> also CARGO_BUILD_JOBS=2
    - no network on first run    -> cargo must fetch the crates in Cargo.lock once
  If it is already installed and you just want to redo it, add --force."
        fi
    done

    # ── Smoke test ───────────────────────────────────────────────────────────
    if [ "$DRY_RUN" -eq 0 ] && [ "$WHICH" != "daemon" ]; then
        step "Verifying the installed binary"
        if ! ver_out="$("${BINDIR}/entangle" --version 2>&1)"; then
            die "installed ${BINDIR}/entangle but it failed to run:
${ver_out}"
        fi
        info "    ${ver_out}"
    fi

    # ── PATH advice (same logic as install.sh) ───────────────────────────────
    case ":${PATH}:" in
    *":${BINDIR}:"*)
        resolved="$(command -v entangle 2>/dev/null || true)"
        if [ -n "$resolved" ] && [ "$resolved" != "${BINDIR}/entangle" ]; then
            warn "another 'entangle' earlier on your PATH will win: ${resolved}"
        fi
        ;;
    *)
        info ""
        warn "${BINDIR} is not on your PATH. Add it, e.g.:"
        info "    echo 'export PATH=\"${BINDIR}:\$PATH\"' >> ~/.profile"
        info "    export PATH=\"${BINDIR}:\$PATH\"   # for this shell"
        ;;
    esac

    # ── First-run identity ───────────────────────────────────────────────────
    if [ "$WHICH" != "daemon" ]; then
        maybe_init "$BINDIR"
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        info ""
        step "Dry run complete — nothing was changed."
        exit 0
    fi

    cat >&2 <<EOF

Entanglement built and installed from source.

Next steps:
  entangled run          # start the daemon in the foreground (Phase 1 has no
                         # daemonize mode — use a second terminal, or the
                         # systemd unit at packaging/entangled.service)

Then, in another terminal:
  entangle doctor        # health check: identity, config, keyring, daemon
  entangle version       # CLI + crate + daemon versions
  entangle mesh status
  entangle plugins list

Build the example plugin (needs the ${WASM_TARGET} target):
  cargo xtask hello-world build      # prints your publisher fingerprint
  entangle keyring add <fingerprint> --name self
  entangle plugins load examples/hello-world/dist/ --allow-local
  entangle plugins invoke <fingerprint>/hello-world@0.1.0 --input world

Shell completions:
  entangle completions bash   # also zsh, fish, powershell, elvish

Upgrading later:
  git -C "${ROOT_DIR}" pull
  ./scripts/bootstrap.sh --force

Docs: docs/install.md (install paths), docs/tutorial.md (hands-on walkthrough),
      docs/operations.md (config schema, error codes, backup/restore).
EOF
}

main "$@"
