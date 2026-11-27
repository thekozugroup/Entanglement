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
if [[ "${TARBALL}" != /* ]]; then
    TARBALL="${PWD}/${TARBALL}"
fi

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

release_filename='^entanglement-(v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?)-(x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|aarch64-apple-darwin|x86_64-apple-darwin)\.tar\.gz$'
if ! [[ "${TARBALL##*/}" =~ ${release_filename} ]]; then
    echo 'error: use the original release filename to identify the tagged workflow' >&2
    exit 1
fi
identity="https://github.com/thekozugroup/Entanglement/.github/workflows/release.yml@refs/tags/${BASH_REMATCH[1]}"
if ! command -v python3 >/dev/null 2>&1; then
    echo 'error: Python 3 is required to inspect the Sigstore bundle' >&2
    exit 1
fi
bundle_dir=$(mktemp -d)
trap 'rm -rf "${bundle_dir}"' EXIT
cp "${TARBALL}.sigstore" "${bundle_dir}/bundle.sigstore"
bundle_type=$(python3 - "${bundle_dir}" <<'PY'
import base64
import json
from pathlib import Path
import sys

directory = Path(sys.argv[1])
try:
    bundle = json.loads((directory / "bundle.sigstore").read_bytes())
    if bundle.get("mediaType") in (
        "application/vnd.dev.sigstore.bundle.v0.3+json",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
    ) and isinstance(bundle.get("messageSignature"), dict):
        print("v0.3")
    else:
        # Historic keyless cosign blob bundles carry the PEM certificate
        # directly or as base64. Never accept a raw key from bundle metadata.
        certificate = bundle["cert"].encode("ascii")
        if not certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
            certificate = base64.b64decode(certificate, validate=True)
        if not certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise ValueError("legacy bundle did not contain an X.509 certificate")
        (directory / "certificate.pem").write_bytes(certificate)
        print("legacy")
except (AttributeError, OSError, KeyError, TypeError, ValueError) as error:
    sys.exit(f"error: invalid Sigstore release bundle: {error}")
PY
)

cosign_arguments=(--certificate-identity "${identity}"
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
    --bundle "${bundle_dir}/bundle.sigstore")
if [ "${bundle_type}" = v0.3 ]; then
    cosign_arguments+=(--new-bundle-format --offline)
else
    cosign_arguments+=(--certificate "${bundle_dir}/certificate.pem")
fi
cosign verify-blob "${cosign_arguments[@]}" -- "${TARBALL}"

echo "✓ ${TARBALL} verified"
