#!/bin/sh
# Entanglement installer — POSIX sh, safe to pipe from curl:
#
#   curl -fsSL https://raw.githubusercontent.com/thekozugroup/Entanglement/main/scripts/install.sh | sh
#
# Downloads a signed release tarball from GitHub Releases, VERIFIES its SHA-256
# checksum before extracting anything, and installs the `entangle` (CLI) and
# `entangled` (daemon) binaries into a user-writable prefix.
#
# Artifact naming is dictated by .github/workflows/release.yml:
#
#   entanglement-<tag>-<rust-target>.tar.gz          (+ .sha256, .b3, .sigstore)
#
# where <tag> is the git tag *including* its leading "v" (e.g. v0.1.0) and the
# tarball unpacks to a single top-level directory of the same stem, containing
# `entangle`, `entangled`, LICENSE, README.md, architecture.md, tutorial.md.
#
# This script deliberately does NOT: use sudo, modify your shell rc files, send
# telemetry, or extract an archive whose checksum has not been verified.

set -eu
# pipefail is not in POSIX; enable it only on shells that support it (bash, zsh,
# ksh, busybox ash). dash silently lacks it and must not abort here.
# shellcheck disable=SC3040
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi

REPO="thekozugroup/Entanglement"
RELEASES_URL="https://github.com/${REPO}/releases"
PROJECT="entanglement"

# ── Defaults (overridable by flags / env) ────────────────────────────────────
VERSION=""                       # empty = resolve the latest published release
PREFIX="${PREFIX:-}"             # empty = ${HOME}/.local  (bin dir gets appended)
DRY_RUN=0
ALLOW_ROOT=0
FORCE=0

# ── Output helpers ───────────────────────────────────────────────────────────
# Everything informational goes to stderr so the script stays pipe-friendly.
info() { printf '%s\n' "$*" >&2; }
step() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<EOF
Entanglement installer

Usage:
  install.sh [options]

Options:
  --version X.Y.Z     Install a specific release (default: latest).
                      A leading "v" is optional; "0.1.0" and "v0.1.0" are equal.
  --prefix DIR        Install prefix. If DIR ends in /bin it is used verbatim,
                      otherwise "/bin" is appended.
                      Default: \$PREFIX, else \$HOME/.local  (=> \$HOME/.local/bin)
  --dry-run           Print everything that would happen; download and install
                      nothing. Useful for checking OS/arch detection and URLs.
  --allow-root        Permit running as root (refused by default).
  --force             Reinstall even when the requested version is already
                      present.
  -h, --help          Show this help.

Environment:
  PREFIX                    Same as --prefix.
  ENTANGLE_INSTALL_OS       Override detected OS   (testing only: linux|darwin)
  ENTANGLE_INSTALL_ARCH     Override detected arch (testing only: x86_64|aarch64)

Examples:
  install.sh
  install.sh --version 0.1.0 --prefix "\$HOME/.local"
  install.sh --prefix /usr/local          # only if /usr/local/bin is writable
  install.sh --dry-run

Stronger verification:
  This installer always verifies the SHA-256 checksum published alongside the
  tarball. Releases are additionally signed with cosign (keyless/sigstore) and
  carry a BLAKE3 sidecar; to check those, download the tarball plus its
  .sha256 / .b3 / .sigstore files and run scripts/verify-release.sh <tarball>
  from a repository checkout (needs cosign, and b3sum for the BLAKE3 check).
EOF
}

# ── Argument parsing ─────────────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
        --version)
            [ $# -ge 2 ] || die "--version requires an argument (e.g. --version 0.1.0)"
            VERSION="$2"
            shift 2
            ;;
        --version=*)
            VERSION="${1#--version=}"
            shift
            ;;
        --prefix)
            [ $# -ge 2 ] || die "--prefix requires an argument (e.g. --prefix \$HOME/.local)"
            PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            PREFIX="${1#--prefix=}"
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

# ── Platform detection ───────────────────────────────────────────────────────
# Maps to the exact Rust target triples built by .github/workflows/release.yml:
#   x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu,
#   x86_64-apple-darwin,      aarch64-apple-darwin
detect_os() {
    if [ -n "${ENTANGLE_INSTALL_OS:-}" ]; then
        printf '%s\n' "$ENTANGLE_INSTALL_OS"
        return 0
    fi
    os="$(uname -s 2>/dev/null || echo unknown)"
    case "$os" in
    Linux) printf 'linux\n' ;;
    Darwin) printf 'darwin\n' ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
        die "native Windows is not supported (Phase 5). Install inside WSL2 and re-run this script there."
        ;;
    *)
        die "unsupported operating system: ${os}. Build from source: https://github.com/${REPO}"
        ;;
    esac
}

detect_arch() {
    if [ -n "${ENTANGLE_INSTALL_ARCH:-}" ]; then
        printf '%s\n' "$ENTANGLE_INSTALL_ARCH"
        return 0
    fi
    arch="$(uname -m 2>/dev/null || echo unknown)"
    case "$arch" in
    x86_64 | amd64 | x64) arch="x86_64" ;;
    aarch64 | arm64) arch="aarch64" ;;
    *)
        die "unsupported CPU architecture: ${arch}. Released targets are x86_64 and aarch64 only; build from source: https://github.com/${REPO}"
        ;;
    esac
    # An Apple-silicon Mac running this script under Rosetta reports x86_64.
    # Prefer the native arm64 build in that case.
    if [ "$arch" = "x86_64" ] && [ "$(uname -s 2>/dev/null || true)" = "Darwin" ] &&
        [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
        arch="aarch64"
    fi
    printf '%s\n' "$arch"
}

target_triple() {
    case "$1/$2" in
    linux/x86_64) printf 'x86_64-unknown-linux-gnu\n' ;;
    linux/aarch64) printf 'aarch64-unknown-linux-gnu\n' ;;
    darwin/x86_64) printf 'x86_64-apple-darwin\n' ;;
    darwin/aarch64) printf 'aarch64-apple-darwin\n' ;;
    *) die "no released build for ${1}/${2}" ;;
    esac
}

# ── Download helpers ─────────────────────────────────────────────────────────
require_downloader() {
    if have curl; then
        DOWNLOADER=curl
    elif have wget; then
        DOWNLOADER=wget
    else
        die "neither curl nor wget is installed — cannot download the release"
    fi
}

# fetch <url> <dest-file>
fetch() {
    case "$DOWNLOADER" in
    curl) curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1" ;;
    wget) wget -q --https-only -O "$2" "$1" ;;
    esac
}

# Print the tag the /releases/latest redirect lands on, e.g. "v0.1.0".
resolve_latest_tag() {
    _url=""
    case "$DOWNLOADER" in
    curl)
        _url="$(curl -fsSL --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' \
            "${RELEASES_URL}/latest" 2>/dev/null || true)"
        ;;
    wget)
        _url="$(wget -q -S --spider --https-only "${RELEASES_URL}/latest" 2>&1 |
            tr -d '\r' | awk '/^[ \t]*Location:/ { u = $2 } END { print u }' || true)"
        [ -n "$_url" ] || _url="${RELEASES_URL}/latest"
        ;;
    esac
    _tag="${_url##*/}"
    case "$_tag" in
    v[0-9]*) printf '%s\n' "$_tag" ;;
    *) return 1 ;;
    esac
}

# Normalize a user-supplied version into a release tag (adds the leading "v")
# and reject anything that is not a plain semver-ish string — the value is
# interpolated into a URL and a filename.
normalize_tag() {
    _t="v${1#v}"
    if ! printf '%s' "$_t" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9._-]+)?$'; then
        die "invalid --version '$1' (expected X.Y.Z, optionally with a -pre suffix)"
    fi
    printf '%s\n' "$_t"
}

# ── Checksums ────────────────────────────────────────────────────────────────
# Linux ships sha256sum (coreutils); macOS ships shasum. openssl is a last
# resort. Whichever we use, we compare the digest ourselves rather than relying
# on `-c`, so a mismatched *filename* inside the .sha256 file can never make a
# failed comparison look like a pass.
sha256_of() {
    if [ "$OS" = "darwin" ]; then
        if have shasum; then
            shasum -a 256 "$1" | awk '{ print $1 }'
            return 0
        fi
    fi
    if have sha256sum; then
        sha256sum "$1" | awk '{ print $1 }'
    elif have shasum; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    elif have openssl; then
        openssl dgst -sha256 "$1" | awk '{ print $NF }'
    else
        die "no SHA-256 tool found (need sha256sum, shasum, or openssl) — refusing to install unverified binaries"
    fi
}

lower() { printf '%s' "$1" | tr 'ABCDEF' 'abcdef'; }

# ── Prefix resolution ────────────────────────────────────────────────────────
resolve_bindir() {
    _p="$1"
    [ -n "$_p" ] || _p="${HOME:-}/.local"
    [ "$_p" != "/.local" ] || die "\$HOME is not set — pass --prefix DIR explicitly"
    case "$_p" in
    */bin) printf '%s\n' "$_p" ;;
    *) printf '%s\n' "${_p%/}/bin" ;;
    esac
}

# ── Cleanup ──────────────────────────────────────────────────────────────────
TMPDIR_INSTALL=""
cleanup() {
    [ -n "$TMPDIR_INSTALL" ] && [ -d "$TMPDIR_INSTALL" ] && rm -rf "$TMPDIR_INSTALL"
    return 0
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    if [ "$(id -u 2>/dev/null || echo 1000)" = "0" ] && [ "$ALLOW_ROOT" -ne 1 ]; then
        die "refusing to run as root.
  Installing as root writes binaries owned by root into a shared prefix and is
  rarely what you want. Re-run as your normal user, or pass --allow-root if you
  really mean it (e.g. in a container image build)."
    fi

    OS="$(detect_os)"
    ARCH="$(detect_arch)"
    TARGET="$(target_triple "$OS" "$ARCH")"
    BINDIR="$(resolve_bindir "$PREFIX")"

    require_downloader

    if [ -n "$VERSION" ]; then
        TAG="$(normalize_tag "$VERSION")"
    else
        step "Resolving the latest release of ${REPO}"
        if TAG="$(resolve_latest_tag)"; then
            :
        elif [ "$DRY_RUN" -eq 1 ]; then
            TAG="vX.Y.Z"
            warn "could not resolve the latest tag (offline?) — using a placeholder for the dry run"
        else
            die "could not resolve a release to download.

  ${REPO} has no published releases yet, so this script — which only
  ever installs prebuilt release tarballs — has nothing to fetch. That is
  expected right now, not a bug in the script or your network.

  Two install paths DO work today (full details in docs/install.md):

    1. From source — needs a Rust toolchain (1.91+), no release required:
         git clone https://github.com/${REPO}
         cd Entanglement
         ./scripts/bootstrap.sh

    2. Docker — needs no Rust toolchain, builds in the image:
         git clone https://github.com/${REPO}
         cd Entanglement
         docker compose -f docker/docker-compose.yml up --build

  If a release has since been cut and you are merely offline or behind a proxy
  that blocks the redirect, pass the version explicitly:
         install.sh --version X.Y.Z
  Published releases: ${RELEASES_URL}"
        fi
    fi

    NAME="${PROJECT}-${TAG}-${TARGET}"
    TARBALL="${NAME}.tar.gz"
    TARBALL_URL="${RELEASES_URL}/download/${TAG}/${TARBALL}"
    SHA_URL="${TARBALL_URL}.sha256"

    info ""
    info "  platform    ${OS}/${ARCH}  (target ${TARGET})"
    info "  version     ${TAG}"
    info "  tarball     ${TARBALL_URL}"
    info "  checksum    ${SHA_URL}"
    info "  install to  ${BINDIR}/entangle, ${BINDIR}/entangled"
    info ""

    if [ "$DRY_RUN" -eq 1 ]; then
        step "Dry run — nothing downloaded, nothing written."
        info "Would download the tarball and its .sha256, verify the digest,"
        info "extract ${NAME}/{entangle,entangled} and install them into ${BINDIR}."
        exit 0
    fi

    # ── Already installed? ───────────────────────────────────────────────────
    if [ -x "${BINDIR}/entangle" ]; then
        installed="$("${BINDIR}/entangle" --version 2>/dev/null | awk 'NR==1 { print $NF }' || true)"
        if [ -n "$installed" ] && [ "$installed" = "${TAG#v}" ] && [ "$FORCE" -ne 1 ]; then
            step "entangle ${installed} is already installed in ${BINDIR} — nothing to do."
            info "Re-run with --force to reinstall, or --version X.Y.Z to change versions."
            exit 0
        fi
        if [ -n "$installed" ]; then
            step "Replacing entangle ${installed} in ${BINDIR} with ${TAG#v}"
        else
            step "Replacing an existing (unrecognized) entangle in ${BINDIR}"
        fi
    fi

    # ── Writability: never escalate silently ────────────────────────────────
    if [ -d "$BINDIR" ]; then
        [ -w "$BINDIR" ] || die "${BINDIR} exists but is not writable by $(id -un 2>/dev/null || echo "this user").
  Either re-run with a writable prefix:
      install.sh --prefix \"\$HOME/.local\"
  or install there yourself with elevated privileges (this script will not call sudo):
      sudo install.sh --prefix $(dirname "$BINDIR") --allow-root"
    else
        parent="$(dirname "$BINDIR")"
        while [ ! -d "$parent" ] && [ "$parent" != "/" ]; do parent="$(dirname "$parent")"; done
        [ -w "$parent" ] || die "cannot create ${BINDIR}: ${parent} is not writable.
  Pick a writable prefix (e.g. --prefix \"\$HOME/.local\") — this script will not call sudo."
        mkdir -p "$BINDIR"
    fi

    TMPDIR_INSTALL="$(mktemp -d 2>/dev/null || mktemp -d -t entangle-install)"
    trap cleanup EXIT HUP INT TERM

    # ── Download ────────────────────────────────────────────────────────────
    step "Downloading ${TARBALL}"
    fetch "$TARBALL_URL" "${TMPDIR_INSTALL}/${TARBALL}" ||
        die "download failed: ${TARBALL_URL}
  Is ${TAG} published for ${TARGET}? See ${RELEASES_URL}
  If that page is empty, no release exists yet — build from source with
  ./scripts/bootstrap.sh, or use Docker. See docs/install.md."

    step "Downloading ${TARBALL}.sha256"
    fetch "$SHA_URL" "${TMPDIR_INSTALL}/${TARBALL}.sha256" ||
        die "checksum file missing: ${SHA_URL}
  Refusing to install an unverified archive."

    # ── Verify BEFORE extracting ────────────────────────────────────────────
    step "Verifying SHA-256"
    expected="$(awk 'NR==1 { print $1 }' "${TMPDIR_INSTALL}/${TARBALL}.sha256")"
    if ! printf '%s' "$expected" | LC_ALL=C grep -Eq '^[0-9a-fA-F]{64}$'; then
        die "malformed checksum file (${SHA_URL}) — refusing to install."
    fi
    actual="$(sha256_of "${TMPDIR_INSTALL}/${TARBALL}")"
    if [ "$(lower "$actual")" != "$(lower "$expected")" ]; then
        rm -f "${TMPDIR_INSTALL}/${TARBALL}"
        die "SHA-256 MISMATCH for ${TARBALL} — the download was corrupted or tampered with.
    expected: ${expected}
    actual:   ${actual}
  The archive has been deleted and NOTHING was extracted or installed.
  Please report this at https://github.com/${REPO}/security/advisories/new"
    fi
    info "    ok: ${actual}"

    # ── Extract ─────────────────────────────────────────────────────────────
    step "Extracting"
    mkdir -p "${TMPDIR_INSTALL}/x"
    tar -xzf "${TMPDIR_INSTALL}/${TARBALL}" -C "${TMPDIR_INSTALL}/x" ||
        die "failed to extract ${TARBALL}"

    # ── Install ─────────────────────────────────────────────────────────────
    step "Installing into ${BINDIR}"
    for bin in entangle entangled; do
        src="${TMPDIR_INSTALL}/x/${NAME}/${bin}"
        if [ ! -f "$src" ]; then
            src="$(find "${TMPDIR_INSTALL}/x" -type f -name "$bin" 2>/dev/null | head -n 1 || true)"
        fi
        [ -n "$src" ] && [ -f "$src" ] || die "'${bin}' not found inside ${TARBALL} — unexpected archive layout."
        # Copy to a temp name in the destination filesystem, then rename: this
        # is atomic and never leaves a half-written binary on the PATH.
        cp "$src" "${BINDIR}/.${bin}.new.$$"
        chmod 0755 "${BINDIR}/.${bin}.new.$$"
        mv -f "${BINDIR}/.${bin}.new.$$" "${BINDIR}/${bin}"
        info "    ${BINDIR}/${bin}"
    done

    # ── Smoke test ──────────────────────────────────────────────────────────
    step "Verifying the installed binary"
    if ! ver_out="$("${BINDIR}/entangle" --version 2>&1)"; then
        die "installed ${BINDIR}/entangle but it failed to run:
${ver_out}
  This usually means the tarball is for a different libc or architecture.
  Detected: ${OS}/${ARCH} -> ${TARGET}"
    fi
    info "    ${ver_out}"

    # ── PATH advice ─────────────────────────────────────────────────────────
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

    cat >&2 <<EOF

Entanglement ${TAG#v} installed.

Next steps:
  entangle init          # generate an Ed25519 identity + ~/.entangle/config.toml
                         # (add --non-interactive to accept the defaults)
  entangled run          # start the daemon in the foreground
  entangle doctor        # health check: identity, config, keyring, daemon

Then, in another terminal:
  entangle mesh status
  entangle plugins list

Shell completions:
  entangle completions bash   # also zsh, fish, powershell, elvish

Run it as a service (Linux):
  packaging/entangled.service — hardened systemd unit; see docs/install.md.

Want the stronger check? Every release is cosign-signed (keyless/sigstore) and
carries a BLAKE3 sidecar. From a repository checkout:
  curl -fsSLO ${TARBALL_URL}
  curl -fsSLO ${TARBALL_URL}.sha256
  curl -fsSLO ${TARBALL_URL}.b3
  curl -fsSLO ${TARBALL_URL}.sigstore
  ./scripts/verify-release.sh ${TARBALL}
EOF
}

main "$@"
