#!/usr/bin/env python3
"""Replay real manual and direct-network pairing using disposable PTYs."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import termios
import time
import tomllib


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(file):
    with file.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check(condition, explanation):
    if not condition:
        raise RuntimeError(explanation)


class Shell:
    def __init__(self, stack, binary, home, *arguments):
        self.argv = ["entangle", *arguments]
        self.data = bytearray()
        self.master, slave = pty.openpty()
        term = termios.tcgetattr(slave)
        term[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, term)
        env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
                   XDG_RUNTIME_DIR=str(home), TERM="dumb", RUST_LOG="warn")
        self.process = subprocess.Popen([binary, *arguments], stdin=slave, stdout=slave, stderr=slave, env=env)
        os.close(slave)
        self.eof = False
        stack.callback(self.cleanup)

    @property
    def transcript(self):
        return self.data.decode("utf-8").replace("\r\n", "\n")

    def read(self, seconds):
        if self.eof:
            return
        if select.select([self.master], [], [], seconds)[0]:
            try:
                payload = os.read(self.master, 8_192)
            except OSError as err:
                if err.errno != errno.EIO:
                    raise
                payload = b""
            self.eof = not payload
            self.data.extend(payload)

    def expect(self, pattern):
        end = time.monotonic() + 30
        while (match := re.search(pattern, self.transcript)) is None:
            remaining = end - time.monotonic()
            if self.eof or remaining <= 0:
                raise RuntimeError(f"expected PTY prompt {pattern!r} did not arrive")
            self.read(remaining)
        return match

    def put(self, value):
        line = value.encode() + b"\n"
        check(os.write(self.master, line) == len(line), "PTY input incomplete")

    def finish(self):
        end = time.monotonic() + 30
        while not self.eof and time.monotonic() < end:
            self.read(max(0, min(0.2, end - time.monotonic())))
        if not self.eof:
            raise RuntimeError("pairing program did not finish")
        return self.process.wait(timeout=5)

    def cleanup(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        os.close(self.master)


def fingerprint(pubkey, b3sum):
    digest = subprocess.check_output([b3sum, "--no-names"], input=pubkey, timeout=8).decode().strip()
    check(re.fullmatch(r"[0-9a-f]{64}", digest), "invalid independent BLAKE3 result")
    return digest[:32], "-".join(digest[index:index + 4] for index in range(0, 16, 4))


def get_identity(home, b3sum):
    public = subprocess.check_output(
        ["openssl", "pkey", "-in", home / ".entangle/identity.key", "-pubout", "-outform", "DER"],
        timeout=8, stderr=subprocess.PIPE,
    )
    check(len(public) == 44 and public[:12].hex() == "302a300506032b6570032100", "not Ed25519 public DER")
    peer_id, short = fingerprint(public[-32:], b3sum)
    return {"key": public[-32:].hex(), "peer": peer_id, "short": short}


def persisted_peer(home, expected, name, b3sum):
    path = home / ".entangle/peers.toml"
    store = tomllib.loads(path.read_text())
    check(list(store) == ["peer"] and len(store["peer"]) == 1, "peer store should contain exactly one peer")
    entry, = store["peer"]
    peer_id = bytes(entry["peer_id"]).hex()
    check(entry["public_key_hex"] == expected["key"] and peer_id == expected["peer"] and
          entry["display_name"] == name and entry["trust"] == "trusted", "peer store retained wrong trust or identity")
    check(fingerprint(bytes.fromhex(entry["public_key_hex"]), b3sum)[0] == peer_id, "peer ID/public key mismatch")
    return {"trusted": True, "matches_other_exact_ed25519_public_key": True,
            "matches_independent_peer_id": True, "display_name": name, "peer_store_mode": format(stat.S_IMODE(path.stat().st_mode), "04o")}


def scrub(text, temporary, actual):
    text = text.replace(str(temporary), "<disposable-directory>")
    for source, target in actual:
        text = text.replace(source, target)
    text = re.sub(r"(ENT-(?:REQ|ACC|FIN)-)[A-Za-z0-9_\-]{24,}", r"\1<redacted>", text)
    text = re.sub(r"\b[0-9]{3}-[0-9]{3}\b", "<pairing-code>", text)
    check("PRIVATE KEY-----" not in text and not re.search(r"ENT-(?:REQ|ACC|FIN)-[A-Za-z0-9_\-]{24,}", text),
          "private pairing material escaped redaction")
    return text


def run_pair(case, parent, binary, b3sum):
    dirs = {letter: parent / case / letter for letter in ("A", "B")}
    for path in dirs.values():
        path.mkdir(parents=True)
    with ExitStack() as stack:
        extra = ("--manual",) if case == "manual" else ("--bind", "127.0.0.1:0", "--no-mdns")
        b = Shell(stack, binary, dirs["B"], "pair", "--responder", *extra, "--display-name", "fixture-B")
        dynamic = []
        if case == "manual":
            b.expect(r"Paste REQUEST blob \(then press Enter\):\n> ")
            a = Shell(stack, binary, dirs["A"], "pair", "--manual", "--display-name", "fixture-A")
            code = a.expect(r"(?m)^Code:\s+([0-9]{3}-[0-9]{3}) ").group(1)
            request = a.expect(r"(?m)^(ENT-REQ-[A-Za-z0-9_\-]+)$").group(1)
            a.expect(r"Paste this REQUEST blob to the other device's `entangle pair --responder --manual`:")
            check(not (dirs["A"] / ".entangle/peers.toml").exists(), "initiator trusted before accepting signature")
            b.put(request)
            b.expect(r"Then enter the 6-digit code displayed on the initiator: ")
            ids = {k: get_identity(path, b3sum) for k, path in dirs.items()}
            check(a.expect(r"(?m)^Fingerprint:\s+([0-9a-f-]+)$").group(1) == ids["A"]["short"]
                  and b.expect(r"(?m)^Initiator fingerprint:\s+([0-9a-f-]+)$").group(1) == ids["A"]["short"]
                  and b.expect(r"(?m)^Your fingerprint:\s+([0-9a-f-]+)$").group(1) == ids["B"]["short"],
                  "manual prompts printed fingerprints inconsistent with the actual keys")
            b.put(code)
            accept = b.expect(r"(?m)^(ENT-ACC-[A-Za-z0-9_\-]+)$").group(1)
            a.put(accept)
            finalize = a.expect(r"(?m)^(ENT-FIN-[A-Za-z0-9_\-]+)$").group(1)
            check(a.expect(r"Paired with peer 'fixture-B' \(([0-9a-f-]+)\)").group(1) == ids["B"]["short"],
                  "manual initiator outcome has wrong responder fingerprint")
            check(not (dirs["B"] / ".entangle/peers.toml").exists(), "manual responder added trust before FINALIZE")
            b.put(finalize)
        else:
            code = b.expect(r"Pairing code:\s+([0-9]{3}-[0-9]{3}) ").group(1)
            target = b.expect(r"Direct address: entangle pair --peer ([0-9a-f]{64}@127\.0\.0\.1:[0-9]+)").group(1)
            dynamic.append((target, "<printed-loopback-long-address>"))
            dynamic.append((target.split("@")[1], "<loopback-address>"))
            a = Shell(stack, binary, dirs["A"], "pair", *extra, "--display-name", "fixture-A", "--peer", target)
            a.expect(r"Enter the 6-digit code shown on [^\n]+: ")
            a.put(code)
            ids = {k: get_identity(path, b3sum) for k, path in dirs.items()}
            for shell, other, own in ((a, "B", "A"), (b, "A", "B")):
                shell.expect(r"Do both fingerprints match the other device's screen\? \[y/N\] ")
                check(shell.expect(r"Their fingerprint: ([0-9a-f-]+)").group(1) == ids[other]["short"] and
                      shell.expect(r"Your fingerprint:\s+([0-9a-f-]+)").group(1) == ids[own]["short"],
                      "network CLI printed unexpected peer fingerprint")
            check(all(not (home / ".entangle/peers.toml").exists() for home in dirs.values()),
                  "network pairing added trust without confirmation")
            a.put("y")
            b.put("y")
        code_a, code_b = a.finish(), b.finish()
        check(code_a == code_b == 0, "one side did not exit successfully")
        check(ids["A"]["peer"] != ids["B"]["peer"], "pairing cases unexpectedly share identity")
        dynamic.append((code, "<pairing-code>"))
        dynamic += [(ids[k][field], f"<{k}-{field}>") for k in ("A", "B") for field in ("short", "peer", "key")]
        for shell in (a, b):
            check("✓ added to " in shell.transcript, "success did not report persisted store")
        return {
            "A": {"argv": [scrub(v, parent, dynamic) for v in a.argv], "exit_code": code_a,
                  "transcript": scrub(a.transcript, parent, dynamic),
                  "persisted_other": persisted_peer(dirs["A"], ids["B"], "fixture-B", b3sum)},
            "B": {"argv": [scrub(v, parent, dynamic) for v in b.argv], "exit_code": code_b,
                  "transcript": scrub(b.transcript, parent, dynamic),
                  "persisted_other": persisted_peer(dirs["B"], ids["A"], "fixture-A", b3sum)},
            "compared_both_independently_derived_short_fingerprints": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("repo", "manifest", "archive", "b3sum", "out"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    args = parser.parse_args()
    repo, manifest_file, archive, b3sum, out = map(Path.resolve, (
        args.repo, args.manifest, args.archive, args.b3sum, args.out
    ))
    manifest = json.loads(manifest_file.read_text())
    def stamp():
        source = subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"],
                                         cwd=repo, text=True).strip()
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        check(manifest["source_id"] == source == manifest["source_after"] and manifest["source_commit"] == commit,
              "checkout differs from the frozen release source")
        return source, commit
    started, before, commit = now(), *stamp()
    check(archive.name == manifest["name"] and sha(archive) == manifest["sha256"]
          and subprocess.check_output([b3sum, "--no-names", archive], text=True).strip() == manifest["blake3"],
          "release archive failed its bound checksum assertions")
    with tempfile.TemporaryDirectory(prefix="entangle-pairing-check-", dir="/tmp") as root:
        parent = Path(root)
        binary = parent / "entangle"
        with tarfile.open(archive) as tar:
            member = tar.getmember(f"{archive.name.removesuffix('.tar.gz')}/entangle")
            check(member.isfile(), "archived CLI isn't a regular file")
            with tar.extractfile(member) as source, binary.open("xb") as sink:
                shutil.copyfileobj(source, sink)
        binary.chmod(0o500)
        cli_sha = sha(binary)
        check(cli_sha == manifest["files_sha256"]["entangle"], "extracted ELF differs from manifest")
        help_output = subprocess.check_output([binary, "pair", "--help"], text=True, timeout=15)
        check("Use the copy-paste blob channel instead of the network." in help_output and
              "Implied by any of the `--*-file` blob options." in help_output and "--peer" in help_output,
              "help no longer matches channel assumptions")
        results = {name: run_pair(name, parent, binary, b3sum) for name in ("manual", "network-default")}
    after, _ = stamp()
    check(before == after and sha(archive) == manifest["sha256"], "source or artifact changed during PTY checks")
    out.mkdir(parents=True, exist_ok=False)
    result = {
        "source_commit": commit, "source_id": before, "source_before": before, "source_after": after,
        "started_utc": started, "finished_utc": now(), "exit_code": 0,
        "command": [sys.executable, *sys.argv], "cli_sha256": cli_sha,
        "archive_sha256": manifest["sha256"], "archive_blake3": manifest["blake3"],
        "archive_signing_status": manifest["signing_status"], "archive_manifest_sha256": sha(manifest_file),
        "driver_sha256": sha(Path(__file__)), "help_exact": help_output, "cases": results,
        "scope": "Disposable homes/Ed25519 keys on a single Linux host. Manual channel uses PTY transfers. Default network channel uses a direct loopback QUIC address with mDNS disabled to isolate the test.",
        "redactions": "Pairing codes, signed exchange blobs, disposable fingerprints, keys, peer IDs, temporary paths and ephemeral port are replaced. Fixed prompt wording is preserved.",
    }
    with (out / "pairing-receipt.json").open("x") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(f"Both pairing modes persisted matching bilateral trust. Receipt SHA-256 {sha(out / 'pairing-receipt.json')}")


if __name__ == "__main__":
    main()
