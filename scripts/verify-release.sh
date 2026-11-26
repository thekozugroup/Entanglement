#!/usr/bin/env bash
set -euo pipefail

CHECKSUMS_ONLY=0
if [ "${1:-}" = "--checksums-only" ]; then
    CHECKSUMS_ONLY=1
    shift
fi
if [ "$#" -ne 1 ]; then
    echo "usage: verify-release.sh [--checksums-only] <tarball>" >&2
    exit 1
fi
TARBALL="$1"

verify_digest() {
    local label="$1" sidecar="$2" expected actual
    shift 2
    expected=$(awk 'NR == 1 { print tolower($1); exit }' "${sidecar}")
    if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ ]]; then
        printf 'error: malformed %s checksum in %s\n' "${label}" "${sidecar}" >&2
        return 1
    fi
    # Hash the requested tarball. The filename in a checksum sidecar is data
    # and can refer to a different file or be relative to another directory.
    actual=$("$@" < "${TARBALL}" | awk 'NR == 1 { print tolower($1) }')
    if [ "${actual}" != "${expected}" ]; then
        printf 'error: %s mismatch for %s\n' "${label}" "${TARBALL}" >&2
        return 1
    fi
    printf '%s: %s matched\n' "${TARBALL}" "${label}"
}

# 1. Verify SHA-256 matches the .sha256 file on Linux or macOS.
if command -v sha256sum >/dev/null 2>&1; then
    verify_digest SHA-256 "${TARBALL}.sha256" sha256sum
elif command -v shasum >/dev/null 2>&1; then
    verify_digest SHA-256 "${TARBALL}.sha256" shasum -a 256
else
    echo "error: install sha256sum or shasum to verify SHA-256" >&2
    exit 1
fi

# 2. Verify BLAKE3 — but only when the sidecar was actually published.
#    Gate on the .b3 FILE first: if we gated on `command -v b3sum` alone and the
#    sidecar were missing, `set -e` would abort here (before the cosign check
#    below) the moment `b3sum -c` failed on the absent file.
if [ -f "${TARBALL}.b3" ]; then
    if command -v b3sum >/dev/null 2>&1; then
        verify_digest BLAKE3 "${TARBALL}.b3" b3sum
    else
        echo "warning: ${TARBALL}.b3 present but b3sum not installed — BLAKE3 check skipped" >&2
    fi
else
    echo "note: ${TARBALL}.b3 absent — no BLAKE3 sidecar for this artifact" >&2
fi

# 3. Authenticate official releases. Unsigned local builds opt out explicitly.
if [ "${CHECKSUMS_ONLY}" -eq 1 ]; then
    printf '%s: checksum verification passed\n' "${TARBALL}"
    exit 0
fi
if ! command -v cosign >/dev/null 2>&1; then
    echo "error: cosign is required to authenticate an official release" >&2
    exit 1
fi
if [ ! -f "${TARBALL}.sigstore" ]; then
    printf 'error: missing Sigstore bundle %s.sigstore\n' "${TARBALL}" >&2
    exit 1
fi

cosign verify-blob \
    --certificate-identity-regexp '^https://github\.com/thekozugroup/Entanglement/\.github/workflows/release\.yml@refs/tags/v[^/]+$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    --bundle "${TARBALL}.sigstore" \
    "${TARBALL}"

echo "✓ ${TARBALL} verified"
