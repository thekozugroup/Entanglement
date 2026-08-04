#!/usr/bin/env bash
set -euo pipefail

TARBALL="${1:?usage: verify-release.sh <tarball>}"

# 1. Verify SHA-256 matches the .sha256 file
sha256sum -c "${TARBALL}.sha256"

# 2. Verify BLAKE3 — but only when the sidecar was actually published.
#    Gate on the .b3 FILE first: if we gated on `command -v b3sum` alone and the
#    sidecar were missing, `set -e` would abort here (before the cosign check
#    below) the moment `b3sum -c` failed on the absent file.
if [ -f "${TARBALL}.b3" ]; then
    if command -v b3sum >/dev/null 2>&1; then
        b3sum -c "${TARBALL}.b3"
    else
        echo "warning: ${TARBALL}.b3 present but b3sum not installed — BLAKE3 check skipped" >&2
    fi
else
    echo "note: ${TARBALL}.b3 absent — no BLAKE3 sidecar for this artifact" >&2
fi

# 3. Verify sigstore bundle
if command -v cosign >/dev/null 2>&1; then
    cosign verify-blob \
        --certificate-identity-regexp 'https://github.com/thekozugroup/Entanglement/.+' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        --bundle "${TARBALL}.sigstore" \
        "${TARBALL}"
else
    echo "warning: cosign not installed — sigstore verification skipped"
fi

echo "✓ ${TARBALL} verified"
