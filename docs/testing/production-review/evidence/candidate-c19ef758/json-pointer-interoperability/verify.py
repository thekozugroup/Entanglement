#!/usr/bin/env python3
"""Exercise a signed RFC 6901 guest on a different trusted daemon."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import socket
import subprocess
import tarfile
import tempfile
import tomllib

import yaml

RFC = "https://www.rfc-editor.org/rfc/rfc6901.html"
OAI_REVISION = "c8e90dfa4ccf8054db1539f7a104c5ccfb1913c3"
OAI_PATH = "examples/v3.0/petstore.yaml"
OAI_DOCUMENT_HASH = "ab60f59da478d4ac312cd9fabcc6cbd06f8f975ab8a1a0c2029b2a41f65fedd5"
OAI_LICENSE_HASH = "4948367c65e1ce06690e2cadc6e86fce1a6a6db55ef874ce4b78c0f472ce5f13"

# Equivalent JSON bytes for the canonical example document. The formatted root
# also checks that the guest returns the original JSON rather than reencoding it.
RFC_DOC = rb'''{
  "foo": ["bar", "baz"],
  "": 0,
  "a/b": 1,
  "c%d": 2,
  "e^f": 3,
  "g|h": 4,
  "i\\j": 5,
  "k\"l": 6,
  " ": 7,
  "m~n": 8
}'''
RFC_CASES = [
    ("", "#", RFC_DOC),
    ("/foo", "#/foo", b'["bar", "baz"]'),
    ("/foo/0", "#/foo/0", b'"bar"'),
    ("/", "#/", b"0"),
    ("/a~1b", "#/a~1b", b"1"),
    ("/c%d", "#/c%25d", b"2"),
    ("/e^f", "#/e%5Ef", b"3"),
    ("/g|h", "#/g%7Ch", b"4"),
    (r"/i\j", "#/i%5Cj", b"5"),
    ('/k"l', "#/k%22l", b"6"),
    ("/ ", "#/%20", b"7"),
    ("/m~0n", "#/m~0n", b"8"),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(path.read_bytes())


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main(args):
    repo = args.repo.resolve(strict=True)
    cloud = lambda *cmd: subprocess.check_output(cmd, cwd=repo, text=True).strip()
    fingerprint = lambda: cloud("python3", "scripts/production_score.py", "--source-id")
    commit = cloud("git", "rev-parse", "HEAD")
    before = fingerprint()
    assert before == args.source_id
    evidence = args.output.resolve(strict=True)
    archive = args.archive.resolve(strict=True)
    wasm = args.wasm.resolve(strict=True)
    expected_release = json.loads(args.release_receipt.read_text())
    assert expected_release["source_commit"] == commit
    assert expected_release["source_id"] == expected_release["source_after"] == before
    assert sha(archive) == expected_release["sha256"]
    assert wasm.read_bytes()[:8] == b"\x00asm\x0d\x00\x01\x00"
    oai_yaml, oai_license = args.petstore.read_bytes(), args.license.read_bytes()
    assert digest(oai_yaml) == OAI_DOCUMENT_HASH and digest(oai_license) == OAI_LICENSE_HASH
    assert b"Apache License" in oai_license
    petstore = yaml.safe_load(oai_yaml)
    assert petstore["openapi"] == "3.0.0"
    assert petstore["paths"]["/pets"]["get"]["operationId"] == "listPets"
    assert petstore["paths"]["/pets/{petId}"]["get"]["operationId"] == "showPetById"
    assert petstore["paths"]["/pets"]["get"]["responses"]["200"]["description"] == "A paged array of pets"
    petstore_json = json.dumps(petstore, ensure_ascii=False, separators=(",", ":")).encode()

    as_helpers = importlib.util.spec_from_file_location("node_helpers", repo/"scripts/tests/distributed-rust-tests.py")
    helpers = importlib.util.module_from_spec(as_helpers)
    as_helpers.loader.exec_module(helpers)
    rows = []
    setup = []
    request_id = 0
    started = stamp()
    with tempfile.TemporaryDirectory(prefix="jp-remote-", dir="/tmp") as scratch, ExitStack() as nodes_running:
        work = Path(scratch)
        binaries = work / "bin"
        binaries.mkdir()
        elf_hashes = {}
        with tarfile.open(archive,"r:gz") as tar:
            prefix = archive.name.removesuffix(".tar.gz")
            for program in ("entangle","entangled"):
                m = tar.getmember(prefix+"/"+program)
                assert m.isfile()
                data = tar.extractfile(m).read()
                elf_hashes[program] = digest(data)
                assert elf_hashes[program] == expected_release["files_sha256"][program]
                p = binaries/program
                p.write_bytes(data)
                p.chmod(0o755)

        coordinator = helpers.Node(work/"coordinator", binaries)
        worker = helpers.Node(work/"worker", binaries)
        publisher = helpers.Node(work/"publisher", binaries)
        assert len({coordinator.peer, worker.peer, publisher.peer}) == 3

        def cli(node, *argv, expected=0):
            command = [binaries/"entangle", *argv]
            result = subprocess.run(command, env={**node.env,"ENTANGLE_ALLOW_LOCAL":"0"}, cwd=repo,
                                    capture_output=True, timeout=30)
            setup.append({"node":node.peer, "argv":list(map(str,command)), "exit_code":result.returncode,
                          "stdout":result.stdout.decode(), "stderr":result.stderr.decode(),
                          "stdout_sha256":digest(result.stdout)})
            assert expected is None or result.returncode == expected, setup[-1]
            return result

        def rpc(node, method, params=None):
            nonlocal request_id
            request_id += 1
            identity = f"jsonptr-{request_id}"
            frame = {"jsonrpc":"2.0","id":identity,"method":method,"params":params}
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(20)
                client.connect(str(node.socket))
                client.sendall(json.dumps(frame).encode()+b"\n")
                with client.makefile("rb") as read:
                    result = json.loads(read.readline(1024*1024))
            assert result["jsonrpc"] == "2.0" and result["id"] == identity
            return result

        def metrics(node):
            text = rpc(node,"metrics")["result"]
            matches = re.findall(r'^entangle_wasm_invocation_seconds_count\{result="(ok|error)"\} ([0-9]+)$',text,re.M)
            return {"ok":0, "error":0, **{key:int(value) for key,value in matches}}

        cli(coordinator,"mesh","trust",worker.peer,"--public-key-hex",worker.key,"--display-name","pointer worker")
        cli(worker,"mesh","trust",coordinator.peer,"--public-key-hex",coordinator.key,"--display-name","pointer coordinator")
        package = work/"signed"
        cli(publisher,"plugins","build",repo/"plugins/json-pointer","--wasm",wasm,"--out",package)
        manifest = tomllib.loads((package/"entangle.toml").read_text())["plugin"]
        plugin = manifest["id"]
        assert manifest["tier"] == 1 and manifest["runtime"] == "wasm" and plugin.endswith("/json-pointer@0.1.0")
        package_files = {p.name:sha(p) for p in package.iterdir() if p.is_file()}
        assert package_files["plugin.wasm"] == sha(wasm) and package_files.get("plugin.wasm.sig")
        worker_port = helpers.free_port()
        worker.start(nodes_running,worker_port,[])
        coordinator_port = helpers.free_port()
        coordinator.start(nodes_running,coordinator_port,[f"{worker.key}@127.0.0.1:{worker_port}"])
        for node in (coordinator,worker):
            status = json.loads(cli(node,"mesh","status","--json").stdout)
            assert status["local_peer_id"] == node.peer
        rejected = cli(worker,"plugins","load",package,expected=None)
        assert rejected.returncode and re.search(rb"trust|publisher|verification key|keyring", rejected.stderr,re.I)
        cli(worker,"keyring","add",publisher.key,"--name","disposable pointer qualification publisher")
        cli(worker,"plugins","load",package)
        assert rpc(worker,"plugins/list")["result"]["plugins"] == [plugin]
        assert rpc(coordinator,"plugins/list")["result"]["plugins"] == []
        start_worker = metrics(worker)
        start_coordinator = metrics(coordinator)
        pending = work/"input.json"

        def invoke(label, pointer, document, *, expected=None, error=None, output_file=False):
            payload = b'{"pointer":'+json.dumps(pointer,ensure_ascii=True).encode()+b',"data":'+document+b'}'
            pending.write_bytes(payload)
            argv = ["compute","dispatch",plugin,"--input-file",pending,"--timeout-ms","10000",
                    "--cpu-cores","0.01","--integrity","trusted-executor","--allow",worker.peer]
            prior = metrics(worker)
            if output_file:
                destination = work/"selected.json"
                assert not destination.exists()
                sink = ["--output-file",destination]
            else:
                sink = ["--raw"]
            reply = cli(coordinator,*argv,*sink,expected=None)
            if error is None:
                assert reply.returncode==0, setup[-1]
                chosen = re.search(rb"^Chosen: ([a-f0-9]{32}) ",reply.stderr,re.M)[1].decode()
                assert chosen == worker.peer, setup[-1]
                actual = destination.read_bytes() if output_file else reply.stdout
                assert actual == expected, (label,pointer,actual,expected)
                after = metrics(worker)
                assert after == {**prior,"ok":prior["ok"]+1}, (prior,after)
                rows.append({"case":label,"pointer":pointer,"input_sha256":digest(payload),
                    "expected_utf8":expected.decode(),"actual_utf8":actual.decode(),"output_sha256":digest(actual),
                    "executor_peer":chosen,"worker_counts_before":prior,"worker_counts_after":after,
                    "cli_exit":reply.returncode,"cli_stderr":reply.stderr.decode(),"output_sink":"file" if output_file else "stdout"})
            else:
                assert reply.returncode != 0 and reply.stdout == b"", (label,setup[-1])
                assert error in reply.stderr.decode(), (label,setup[-1])
                assert "ENTANGLE-E0403" in reply.stderr.decode(), setup[-1]
                after_cli = metrics(worker)
                assert after_cli == {**prior,"error":prior["error"]+1}, (prior,after_cli)
                parameters = {"plugin_id":plugin,"input":list(payload),"timeout_ms":10000,"cpu_cores":0.01,
                              "memory_bytes":0,"gpu_required":False,"gpu_vram_min_bytes":0,
                              "integrity":{"kind":"trusted-executor","allowlist":[worker.peer]}}
                rpc_error = rpc(coordinator,"compute/dispatch",parameters)
                assert rpc_error["error"]["code"] == -32000 and "result" not in rpc_error
                assert error in rpc_error["error"]["message"]
                assert worker.peer in rpc_error["error"]["message"].replace("-","").lower(), rpc_error
                after = metrics(worker)
                assert after == {**after_cli,"error":after_cli["error"]+1}, (after_cli,after)
                rows.append({"case":label,"pointer":pointer,"input_sha256":digest(payload),"expected_diagnostic":error,
                    "executor_peer":worker.peer,"cli_exit":reply.returncode,"cli_stderr":reply.stderr.decode(),
                    "rpc_response":rpc_error,"worker_counts_before":prior,"worker_counts_after":after})

        for ordinary, fragment, expected in RFC_CASES:
            invoke("RFC 6901 §5 JSON string", ordinary, RFC_DOC, expected=expected)
            invoke("RFC 6901 §6 URI fragment", fragment, RFC_DOC, expected=expected)
        invoke("OAI Petstore list operation", "/paths/~1pets/get/operationId", petstore_json, expected=b'"listPets"')
        invoke("OAI Petstore operation with RFC 3986 fragment encoding", "#/paths/~1pets~1%7BpetId%7D/get/operationId",
               petstore_json, expected=b'"showPetById"')
        invoke("OAI Petstore real response description", "#/paths/~1pets/get/responses/200/description", petstore_json,
               expected=b'"A paged array of pets"', output_file=True)
        special = rb'{"present":null,"preserved":{ "unicode":"\u00e9", "number":1e1000 },"seen":1,"\u0073een":2}'
        invoke("present JSON null", "/present", special, expected=b"null")
        invoke("raw JSON escape and number bytes", "/preserved", special, expected=rb'{ "unicode":"\u00e9", "number":1e1000 }')
        invoke("literal tilde escape applied once", "/~01", rb'{"~1":"tilde one","/":"slash"}', expected=b'"tilde one"')
        invoke("missing member (not a JSON null result)", "/absent", special, error="object has no member")
        invoke("ambiguous object member", "/seen", special, error="is ambiguous")
        invoke("invalid leading zero index", "/foo/00", RFC_DOC, error="invalid array index")
        invoke("array index out of bounds", "/foo/10", RFC_DOC, error="out of range")
        invoke("invalid UTF-8 fragment escape", "#/%FF", RFC_DOC, error="URI fragment must decode to UTF-8")
        invoke("invalid JSON Pointer token escape", "/~2", RFC_DOC, error="a '~' escape must be '~0' or '~1'")
        coordinator_after = metrics(coordinator)
        worker_after = metrics(worker)
        assert start_coordinator == coordinator_after == {"ok":0,"error":0}
        assert start_worker == {"ok":0,"error":0} and worker_after == {"ok":30,"error":12}
        assert rpc(coordinator,"plugins/list")["result"]["plugins"]==[]
        assert rpc(worker,"plugins/list")["result"]["plugins"]==[plugin]
        assert not (coordinator.state/"plugins").exists() or not any((coordinator.state/"plugins").iterdir())
        results = {"source_commit":commit,"source_before":before,"source_after":fingerprint(),"exit_code":0,
            "started_at_utc":started,"finished_at_utc":stamp(),"archive_sha256":sha(archive),"release_elf_sha256":elf_hashes,
            "runner_sha256":sha(Path(__file__)),"wasm_sha256":sha(wasm),"signed_package_sha256":package_files,
            "plugin":plugin,"peers":{"coordinator":coordinator.peer,"worker":worker.peer,"publisher":publisher.peer},
            "peer_transport":"authenticated Iroh QUIC over explicit loopback route between independent daemon processes",
            "publisher_public":publisher.key,"worker_inventory_before_and_after":[plugin],"coordinator_inventory_before_and_after":[],
            "worker_counts":{"before":start_worker,"after":worker_after},
            "coordinator_counts":{"before":start_coordinator,"after":coordinator_after},
            "standards":{"rfc_sections":[RFC+"#section-5",RFC+"#section-6"],"example_document_sha256":digest(RFC_DOC),
            "OpenAPI":{"upstream":"OAI/OpenAPI-Specification","tag":"3.0.3","commit":OAI_REVISION,
                "document_url":f"https://raw.githubusercontent.com/OAI/OpenAPI-Specification/{OAI_REVISION}/{OAI_PATH}",
                "license_url":f"https://raw.githubusercontent.com/OAI/OpenAPI-Specification/{OAI_REVISION}/LICENSE",
                "repository_license":"Apache-2.0","license_sha256":digest(oai_license),"source_yaml_sha256":digest(oai_yaml),
                "source_yaml_bytes":len(oai_yaml),"json_conversion":f"PyYAML {yaml.__version__} safe_load, Python compact UTF-8 JSON",
                "derived_json_sha256":digest(petstore_json),"derived_json_bytes":len(petstore_json),
                "scope":"Pointer selection in a real public OpenAPI example document."}},
            "cases":rows,"commands":setup}
        assert results["source_before"] == results["source_after"] == args.source_id
        assert sha(archive)==results["archive_sha256"] and sha(wasm)==results["wasm_sha256"]
        exit_errors = []
        nodes_running.close()
        for label,node in (("coordinator",coordinator),("worker",worker)):
            logfile = evidence / (label+"-daemon.log")
            logfile.write_bytes((node.directory/"daemon.log").read_bytes())
            results.setdefault("daemon_logs",{})[label]={"path":logfile.name,"sha256":sha(logfile)}
        (evidence/"interoperability.json").write_text(json.dumps(results,indent=2)+"\n")
    print(json.dumps({"source":before,"case_count":len(rows),"worker_counts":worker_after,"exit_code":0}))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for item in ("repo","output","archive","release-receipt","wasm","petstore","license"):
        parser.add_argument("--"+item,required=True,type=Path)
    parser.add_argument("--source-id",required=True)
    main(parser.parse_args())
