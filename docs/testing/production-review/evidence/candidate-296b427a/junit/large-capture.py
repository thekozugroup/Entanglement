"""Generate a large genuine sharder JSON report from signed disposable WASI tests."""
import argparse
from contextlib import ExitStack
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('repo', 'bin-dir', 'manifest', 'wasm', 'output'):
        parser.add_argument('--' + option, required=True, type=Path)
    arguments = parser.parse_args()
    root = arguments.repo.resolve()
    bin_dir = arguments.bin_dir.resolve()
    archive = json.loads(arguments.manifest.read_bytes())
    for name in ('entangle', 'entangled'):
        assert sha(bin_dir / name) == archive['files_sha256'][name]
    node_spec = importlib.util.spec_from_file_location('nodes', root / 'scripts/tests/distributed-rust-tests.py')
    nodes = importlib.util.module_from_spec(node_spec)
    node_spec.loader.exec_module(nodes)
    with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
        base = Path(scratch)
        coord = nodes.Node(base / 'coordinator', bin_dir)
        workers = [nodes.Node(base / name, bin_dir) for name in ('a', 'b')]
        plugin, package = nodes.signed_suite(coord, base, 'capture-fixture', arguments.wasm.resolve())
        routes = []
        command = ['python3', str(root / 'scripts/run-rust-tests.py'), plugin, '--socket', str(coord.socket)]
        for worker in workers:
            port = nodes.free_port()
            worker.trust(coord)
            coord.trust(worker)
            worker.cli('keyring', 'add', coord.key, '--name', 'Capture fixture publisher')
            worker.start(stack, port, [])
            worker.cli('plugins', 'load', package)
            routes.append(f'{worker.key}@127.0.0.1:{port}')
            command.extend(['--peer', worker.peer])
        coord.start(stack, 0, routes)
        output = subprocess.check_output(command, timeout=180)
        report = json.loads(output)
        assert report['counts'] == {'passed': 48, 'flaky': 0, 'failed': 0, 'ignored': 0, 'error': 0}
        suite, = report['suites']
        attempts = [r['attempts'][0] for r in suite['results']]
        assert {a['peer'] for a in attempts} == {w.peer for w in workers}
        assert all(a['stdout'].count('<record> λ & pass\x01\n') == 2048 for a in attempts)
        assert all(a['suite_identity'] == suite['suite_identity'] for a in attempts)
        arguments.output.write_bytes(gzip.compress(output, mtime=0))
        print(json.dumps({'source_id':archive['source_id'], 'candidate':archive['source_commit'],
                          'elf_sha256':{n:sha(bin_dir/n) for n in ('entangle','entangled')},
                          'fixture_wasm_sha256':sha(arguments.wasm),'cases':len(attempts),
                          'json_bytes':len(output),'json_sha256':hashlib.sha256(output).hexdigest(),
                          'gzip_sha256':sha(arguments.output)}, indent=2))


if __name__ == '__main__':
    main()
