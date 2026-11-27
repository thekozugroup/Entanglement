#!/usr/bin/env python3
"""Verify the externally supplied publisher signatures before release publication."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from native_release_layout import RELEASE_TARGETS, verify_archive_layout


BUNDLE_MEDIA_TYPES = (
    "application/vnd.dev.sigstore.bundle.v0.3+json",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
)


def publish_signatures(signatures):
    published = []
    try:
        for destination, staged in signatures.items():
            os.link(staged, destination)
            published.append((destination, staged))
    except OSError as error:
        rollback_errors = []
        for destination, staged in reversed(published):
            try:
                if os.path.samestat(destination.lstat(), staged.stat()):
                    destination.unlink()
            except FileNotFoundError:
                pass
            except OSError as rollback:
                rollback_errors.append(str(rollback))
        if rollback_errors:
            raise OSError(f"{error}. Signature rollback failed: {', '.join(rollback_errors)}") from error
        raise


def verify_release(directory, tag, signatures, publisher_key):
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?", tag, re.ASCII):
        raise ValueError("promotion requires an installable release tag")
    if not isinstance(signatures, dict) or set(signatures) != set(RELEASE_TARGETS):
        raise ValueError("publisher signatures must include exactly the four release targets")
    if not publisher_key.strip():
        raise ValueError("configure the independently trusted ENTANGLE_RELEASE_PUBLISHER_KEY")

    artifacts = {target: directory / f"entanglement-{tag}-{target}.tar.gz" for target in RELEASE_TARGETS}
    for suffix in ("", ".sha256", ".b3", ".sigstore"):
        expected = {Path(str(path) + suffix) for path in artifacts.values()}
        if set(directory.glob(f"entanglement-*.tar.gz{suffix}")) != expected:
            raise ValueError(f"staged files for {suffix or 'tarballs'} do not match the release matrix")
    if any(directory.glob("entanglement-*.tar.gz.sig")):
        raise ValueError("the staging run must contain no publisher signature files")

    issuer = "https://token.actions.githubusercontent.com"
    identity = f"https://github.com/thekozugroup/Entanglement/.github/workflows/release.yml@refs/tags/{tag}"
    checksums = Path(__file__).resolve().with_name("verify-release.sh")
    with tempfile.TemporaryDirectory(prefix=".entangle-promotion-", dir=directory) as scratch:
        key_path = Path(scratch) / "release.pub"
        key_path.write_text(publisher_key)
        # Check the configured key is Ed25519 SPKI before OpenSSL is allowed
        # to verify archive bytes with it.
        der = subprocess.check_output([
            "openssl", "pkey", "-pubin", "-in", key_path, "-pubout", "-outform", "DER"
        ])
        if len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
            raise ValueError("release publisher key must be Ed25519 SubjectPublicKeyInfo PEM")
        valid_signatures = {}
        for target, artifact in artifacts.items():
            encoded = signatures[target]
            if not isinstance(encoded, str) or not re.fullmatch(r"[0-9A-Fa-f]{128}", encoded):
                raise ValueError(f"invalid detached Ed25519 signature for {target}")
            signature = bytes.fromhex(encoded)
            staged_signature = Path(scratch) / f"{target}.sig"
            staged_signature.write_bytes(signature)
            subprocess.run([str(checksums), "--checksums-only", artifact], check=True)
            subprocess.run([
                "openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", key_path,
                "-in", artifact, "-sigfile", staged_signature,
            ], check=True)
            bundle = Path(str(artifact) + ".sigstore")
            bundle_header = json.loads(bundle.read_text())
            if (not isinstance(bundle_header, dict)
                    or bundle_header.get("mediaType") not in BUNDLE_MEDIA_TYPES
                    or not isinstance(bundle_header.get("messageSignature"), dict)):
                raise ValueError(f"expected a v0.3 Sigstore blob signature bundle for {target}")
            subprocess.run([
                "cosign", "verify-blob", "--new-bundle-format", "--offline",
                "--certificate-oidc-issuer", issuer, "--certificate-identity", identity,
                "--bundle", bundle, "--", artifact,
            ], check=True)
            verify_archive_layout(artifact, target)
            valid_signatures[Path(str(artifact) + ".sig")] = staged_signature

        publish_signatures(valid_signatures)


if __name__ == "__main__":
    try:
        verify_release(
            Path(sys.argv[1]).resolve(strict=True),
            os.environ["GITHUB_REF_NAME"],
            json.loads(os.environ["PUBLISHER_SIGNATURES"]),
            os.environ.get("ENTANGLE_RELEASE_PUBLISHER_KEY", ""),
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"Release promotion rejected: {error}")
