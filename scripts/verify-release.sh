#!/usr/bin/env bash
set -euo pipefail

TARBALL="${1:?usage: verify-release.sh <tarball>}"

# 1. Verify SHA-256 matches the .sha256 file
sha256sum -c "${TARBALL}.sha256"

# 2. Verify BLAKE3 if b3sum is available
if command -v b3sum >/dev/null 2>&1; then
    b3sum -c "${TARBALL}.b3"
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
