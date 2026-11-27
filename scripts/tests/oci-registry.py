#!/usr/bin/env python3
"""Install and invoke a signed WASI component from a real OCI Distribution v3 server."""
import argparse
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import ssl
import tarfile
import tempfile
import threading
import time
import tomllib
from urllib import parse, request

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = "registry@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c"
REPO = "test/hello-world"
IMAGE = "application/vnd.oci.image.manifest.v1+json"
MEDIA = {"entangle.toml": "application/vnd.entangle.manifest.+toml",
         "plugin.wasm": "application/wasm",
         "plugin.wasm.sig": "application/vnd.entangle.signature.+ed25519"}


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=150).strip()


def upload(base, data, media):
    endpoint = f"{base}/v2/{REPO}/blobs/uploads/"
    with request.urlopen(request.Request(endpoint, data=b"", method="POST"), timeout=8) as response:
        location = parse.urljoin(endpoint, response.headers["Location"])
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    location += ("&" if "?" in location else "?") + parse.urlencode({"digest": digest})
    with request.urlopen(request.Request(location, data=data, method="PUT",
                                        headers={"Content-Type": "application/octet-stream"}), timeout=8) as response:
        assert response.status == 201
    return {"mediaType": media, "digest": digest, "size": len(data)}


def signed_https_archive(package, temp, env, cli, plugin_id):
    """Serve a standard zstd/tar with a real detached signature and verified TLS chain."""
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        contents = {name: (package / name).read_bytes() for name in MEDIA}
        contents["rebuild.json"] = b'{"fixture":"transport verification"}'
        for name, value in contents.items():
            member = tarfile.TarInfo(name)
            member.size = len(value)
            tar.addfile(member, io.BytesIO(value))
    compressed = subprocess.check_output(["zstd", "-q", "-c"], input=archive.getvalue())
    digest = temp / "digest.bin"
    digest.write_bytes(hashlib.sha256(compressed).digest())
    signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-in", digest,
                                         "-inkey", temp / ".entangle/identity.key"])
    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=temp, check=True, capture_output=True)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=Ephemeral test CA",
            "-keyout", "test-ca.key", "-out", "ca.crt", "-addext", "basicConstraints=critical,CA:TRUE")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1",
            "-keyout", "server.key", "-out", "server.csr")
    (temp / "server.ext").write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "test-ca.key",
            "-CAcreateserial", "-days", "2", "-extfile", "server.ext", "-out", "server.crt")
    routes = {"/demo.tar.zst": compressed, "/demo.tar.zst.sig": signature}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in routes:
                self.send_error(404)
                return
            data = routes[self.path]
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *_):
            pass
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(temp / "server.crt", temp / "server.key")
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"https://127.0.0.1:{server.server_port}/demo.tar.zst"
        try:
            # Only the test CLI process sees this extra CA. Package authentication
            # still requires the publisher separately present in its keyring.
            trusted_env = {**env, "SSL_CERT_FILE": str(temp / "ca.crt")}
            args = ["install", "--expect-id", plugin_id, url]
            cli(*args, child_env=trusted_env)
            routes["/demo.tar.zst.sig"] = bytes([signature[0] ^ 1]) + signature[1:]
            cli(*args, error="archive signature did not verify", child_env=trusted_env)
        finally:
            server.shutdown()
            thread.join(timeout=5)


def exercise(bin_dir, base, temp):
    state = temp / ".entangle"
    env = {**os.environ, "HOME": str(temp), "TOKIO_WORKER_THREADS": "2"}
    def cli(*args, error=None, child_env=None):
        result = subprocess.run([bin_dir / "entangle", *args], text=True, capture_output=True,
                                env=child_env or env, timeout=40)
        if error:
            if result.returncode == 0 or error not in result.stderr:
                raise RuntimeError(f"expected {error}, got {result.returncode}, {result.stderr}")
        elif result.returncode:
            raise RuntimeError(f"{args} failed: {result.stderr}")
        return result.stdout

    cli("init", "--non-interactive")
    (state / "config.toml").write_text("[mesh]\ntransports = []\n")
    cli("plugins", "install", "hello-world", "--catalog", ROOT / "examples", "--wasm",
        ROOT / "crates/entangle-host/tests/fixtures/hello-pong.wasm")
    package = state / "plugins/hello-world"
    plugin_id = tomllib.loads((package / "entangle.toml").read_text())["plugin"]["id"]
    layers = [upload(base, (package / name).read_bytes(), media) for name, media in MEDIA.items()]
    config = upload(base, b"{}", "application/vnd.oci.empty.v1+json")
    image = json.dumps({"schemaVersion": 2, "mediaType": IMAGE, "config": config, "layers": layers}).encode()
    with request.urlopen(request.Request(f"{base}/v2/{REPO}/manifests/stable", method="PUT",
                                        data=image, headers={"Content-Type": IMAGE}), timeout=8) as response:
        assert response.status == 201
        digest = response.headers["Docker-Content-Digest"]
    assert digest == "sha256:" + hashlib.sha256(image).hexdigest()
    ref = f"oci://{parse.urlsplit(base).netloc}/{REPO}"
    wrong = plugin_id.replace("/hello-world@", "/another-plugin@")
    cli("install", "--http-loopback", "--expect-id", wrong, ref + ":stable", error="expected plugin")
    assert not (state / "plugins/installed").exists()
    # A loopback development registry must never send its plain HTTP requests
    # through an operator's auto-configured remote proxy.
    offline_proxy = {**env}
    for key in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]:
        offline_proxy[key] = "http://127.0.0.1:1"
    offline_proxy.update({"NO_PROXY": "", "no_proxy": ""})
    paths = []
    for suffix in [":stable", "@" + digest]:
        output = cli("install", "--http-loopback", "--expect-id", plugin_id, ref + suffix, child_env=offline_proxy)
        paths.append(Path(output.strip().splitlines()[-1]))
        assert plugin_id in output and (paths[-1] / "plugin.wasm").read_bytes() == (package / "plugin.wasm").read_bytes()
    assert paths[0] == paths[1]
    signed_https_archive(package, temp, env, cli, plugin_id)
    daemon = subprocess.Popen([bin_dir / "entangled", "run"], env=env, stdout=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if (state / "sock").is_socket():
                break
            if daemon.poll() is not None:
                raise RuntimeError("daemon exited")
            time.sleep(.1)
        cli("plugins", "load", paths[0])
        assert "Hello, OCI!" in cli("plugins", "invoke", plugin_id, "--input", "OCI")
        cli("keyring", "remove", plugin_id.split("/")[0])
        cli("install", "--http-loopback", ref + "@" + digest, error="ENTANGLE-E0101")
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=8)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
    print(f"OCI Distribution v3 tag and digest {digest} installed identical signed bytes; "
          "verified HTTPS archive, altered signature rejection, daemon invocation and revoked publisher rejection passed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bin_dir", type=Path)
    args = parser.parse_args()
    container = docker("run", "-d", "--rm", "-p", "127.0.0.1::5000", REGISTRY)
    try:
        port = docker("port", container, "5000/tcp").splitlines()[0]
        base = f"http://{port}"
        for _ in range(80):
            try:
                with request.urlopen(base + "/v2/", timeout=1):
                    break
            except OSError:
                time.sleep(.1)
        with tempfile.TemporaryDirectory() as temp:
            exercise(args.bin_dir.resolve(), base, Path(temp))
    finally:
        docker("stop", "-t", "2", container)


if __name__ == "__main__":
    main()
