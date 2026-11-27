#!/usr/bin/env bash
set -euo pipefail

command -v cosign >/dev/null || { echo 'Cosign v2.5.3 or compatible is required on PATH.' >&2; exit 1; }
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

fetch() {
    local url="$1" filename="$2" expected="$3" actual
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$url" -o "$fixture/$filename"
    if command -v sha256sum >/dev/null; then
        actual=$(sha256sum "$fixture/$filename" | awk '{print $1}')
    else
        actual=$(shasum -a 256 "$fixture/$filename" | awk '{print $1}')
    fi
    if [ "$actual" != "$expected" ]; then
        printf 'Fixture checksum mismatch for %s\n' "$filename" >&2
        exit 1
    fi
}

# This historical Sigstore conformance artifact was signed by a public test
# workflow, independently of Entanglement and this test's ephemeral publisher.
conformance=https://raw.githubusercontent.com/sigstore/sigstore-conformance/e275ffb5aab734681fe82b919cc4a9a1dd27fa2c/test/assets/bundle-verify
sigstore_go=https://raw.githubusercontent.com/sigstore/sigstore-go/cedac1b7e7d4ff3170c12f24f6b53d49a6396c51/pkg/testing/data/trusted-roots
fetch "$conformance/a.txt" artifact a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf
fetch "$conformance/happy-path-v0.3-new-mediaType/bundle.sigstore.json" bundle.sigstore.json 82382358bdf586d1a184820ac0d0ff06eb737f459fe03baebbbd2c76e80b54a9
fetch "$sigstore_go/public-good.json" trusted-root.json 4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c

cd "$repo_root"
ENTANGLE_RELEASE_TEST_FIXTURES="$fixture" cargo test --locked -p entangle-cli --bin entangle -- --ignored cmd::release::tests::dual_sig_pass

# Re-encode the historical certificate, blob signature and Rekor entry in
# Cosign's legacy format. All signed values and public trust roots are unchanged.
python3 - "$fixture" <<'PY'
import base64
import json
from pathlib import Path
import sys
import textwrap

directory = Path(sys.argv[1])
bundle = json.loads((directory / "bundle.sigstore.json").read_bytes())
root = json.loads((directory / "trusted-root.json").read_bytes())

def pem(kind, encoded):
    lines = "\n".join(textwrap.wrap(encoded, 64))
    return f"-----BEGIN {kind}-----\n{lines}\n-----END {kind}-----\n"

material = bundle["verificationMaterial"]
certificate = pem("CERTIFICATE", material["certificate"]["rawBytes"])
entry = material["tlogEntries"][0]
legacy = {
    "cert": base64.b64encode(certificate.encode()).decode(),
    "base64Signature": bundle["messageSignature"]["signature"],
    "rekorBundle": {
        "SignedEntryTimestamp": entry["inclusionPromise"]["signedEntryTimestamp"],
        "Payload": {"body": entry["canonicalizedBody"], "integratedTime": int(entry["integratedTime"]),
                    "logIndex": int(entry["logIndex"]), "logID": base64.b64decode(entry["logId"]["keyId"]).hex()},
    },
}
(directory / "certificate.pem").write_text(certificate)
(directory / "legacy.json").write_text(json.dumps(legacy))
certificates = {cert["rawBytes"] for ca in root["certificateAuthorities"] for cert in ca["certChain"]["certificates"]}
(directory / "fulcio.pem").write_text("".join(pem("CERTIFICATE", cert) for cert in sorted(certificates)))
(directory / "rekor.pem").write_text(pem("PUBLIC KEY", root["tlogs"][0]["publicKey"]["rawBytes"]))
(directory / "ctlog.pem").write_text(pem("PUBLIC KEY", root["ctlogs"][1]["publicKey"]["rawBytes"]))
PY

export SIGSTORE_ROOT_FILE="$fixture/fulcio.pem"
export SIGSTORE_CT_LOG_PUBLIC_KEY_FILE="$fixture/ctlog.pem"
export SIGSTORE_REKOR_PUBLIC_KEY="$fixture/rekor.pem"
cosign verify-blob --offline \
    --certificate-identity 'https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    --certificate "$fixture/certificate.pem" --bundle "$fixture/legacy.json" -- "$fixture/artifact"

archive="$fixture/entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
cp "$fixture/artifact" "$archive"
if command -v sha256sum >/dev/null; then
    sha256sum "$archive" > "$archive.sha256"
else
    shasum -a 256 "$archive" > "$archive.sha256"
fi
cp "$fixture/legacy.json" "$archive.sigstore"
if bash scripts/verify-release.sh "$archive" > "$fixture/legacy-output" 2>&1; then
    echo 'Legacy release verifier accepted a different publisher workflow' >&2
    exit 1
fi
grep -F 'expected identities' "$fixture/legacy-output"

python3 - "$fixture/rekor.pem" "$archive.sigstore" <<'PY'
import json
from pathlib import Path
import sys

Path(sys.argv[2]).write_text(json.dumps({"cert": Path(sys.argv[1]).read_text()}))
PY
if bash scripts/verify-release.sh "$archive" > "$fixture/key-output" 2>&1; then
    echo 'Legacy release verifier accepted a raw key as a certificate' >&2
    exit 1
fi
grep -F 'invalid Sigstore release bundle' "$fixture/key-output"
