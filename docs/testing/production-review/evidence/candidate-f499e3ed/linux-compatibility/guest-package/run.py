"""Build the frozen hello-world twice in separate, pinned Ubuntu userspaces."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile


HERE = Path(__file__).resolve().parent
ROOT = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip())
COMPAT = HERE.parent
RELEASE = json.loads((COMPAT.parent / 'linux-archive.json').read_text())
STAGE = json.loads((COMPAT / 'jammy-build/jammy-provision.json').read_text())
SEED = Path('/workspace/entangle-jammy-release-mjuyx5hl/fixture')
KEY = Path('/workspace/entangle-package-seed.2uvRiy/public-repro-fixture-seed.pem')
BUNDLE = Path(STAGE['source_bundle'])
STOCK = {'jammy': ('22.04', '2.35', 'ubuntu@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb'),
         'noble': ('24.04', '2.39', 'ubuntu@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b')}
COMPILER = {name: SEED / 'toolchain/bin' / name for name in ('rustc', 'cargo')}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def stamp():
    commit = subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip()
    assert commit == RELEASE['source_commit'] == STAGE['source_commit']
    source = subprocess.check_output([sys.executable,'-B','scripts/production_score.py','--source-id'], cwd=ROOT, text=True).strip()
    assert source == RELEASE['source_id'] == STAGE['source_before'] == STAGE['source_after']
    return source


def build(os_name, out, jammy_tool):
    out.mkdir(exist_ok=False)
    os_version, libc, image = STOCK[os_name]
    tool = jammy_tool if os_name == 'jammy' else ROOT / 'target/release/cargo-entangle'
    provenance = COMPAT / 'jammy-build/jammy-linux-archive.json' if os_name == 'jammy' else COMPAT.parent / 'linux-archive.json'
    tool_build = json.loads(provenance.read_text())
    assert tool_build['source_commit'] == RELEASE['source_commit'] and tool_build['source_after'] == RELEASE['source_id']
    assert sha(tool) == tool_build['tool_sha256']
    assert sha(BUNDLE) == STAGE['source_bundle_sha256']
    assert {k: sha(v) for k,v in COMPILER.items()} == STAGE['compiler']
    before = stamp()
    log = out / 'build.log'
    started = utc()
    receipt = dict(source_commit=RELEASE['source_commit'], source_before=before, source_id=before, started_utc=started,
                   os_version=os_version, glibc=libc, base_image=image, native_packager_sha256=sha(tool),
                   native_build_receipt=str(provenance.relative_to(ROOT)), native_build_receipt_sha256=sha(provenance),
                   compiler_sha256=STAGE['compiler'], source_bundle_sha256=STAGE['source_bundle_sha256'],
                   helper_sha256=sha(HERE/'build-guest.sh'), runner_sha256=sha(Path(__file__)),
                   command=['cargo','entangle','package','<fresh-checkout>/examples/hello-world','--source-url',
                            'https://github.com/thekozugroup/Entanglement.git','--key','/public-repro-fixture.pem',
                            '--out','/build/hello-world.tar.zst'], log=str(log.relative_to(ROOT)), exit_code=1)
    cid = None
    with log.open('x') as stream:
        def run(*args, stdin=None, timeout=60, binary=False):
            cmd = list(map(str,args))
            print(json.dumps(cmd),file=stream,flush=True)
            result = subprocess.run(cmd,input=stdin,capture_output=True,timeout=timeout)
            if not binary: print(result.stdout.decode(errors='replace'), file=stream,end='')
            print(result.stderr.decode(errors='replace'), file=stream,end='')
            print('exit='+str(result.returncode),file=stream,flush=True)
            result.check_returncode()
            return result.stdout if binary else result.stdout.decode().strip()
        try:
            assert 'name=rootless' in json.loads(run('docker','info','-f','{{json .SecurityOptions}}'))
            receipt['base_image_id']=run('docker','image','inspect','-f','{{.Id}}',image)
            cid = run('docker','create','--pull=never','--platform=linux/amd64','--network=bridge','--security-opt=no-new-privileges',
                      '--tmpfs=/build:rw,exec,nosuid,nodev,mode=1777,size=2g',
                      '--mount',f'type=bind,src={SEED},dst=/seed,readonly',
                      '--mount',f'type=bind,src={BUNDLE},dst=/source.bundle,readonly',
                      '--mount',f'type=bind,src={KEY},dst=/public-repro-fixture.pem,readonly',
                      receipt['base_image_id'],'sleep','infinity')
            run('docker','start',cid)
            run('docker','exec',cid,'sh','-ec','apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 update && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 install -y --no-install-recommends ca-certificates git gcc libc6-dev make pkg-config && apt-get clean',timeout=360)
            run('docker','network','disconnect','bridge',cid)
            assert json.loads(run('docker','inspect','-f','{{json .NetworkSettings.Networks}}',cid)) == {}
            run('docker','exec',cid,'mkdir','-p','/packager')
            run('docker','cp',tool,cid+':/packager/cargo-entangle')
            run('docker','exec',cid,'chmod','0555','/packager/cargo-entangle')
            confined=['docker','exec','--user=65534:65534',cid]
            observed = run(*confined,'sha256sum','/packager/cargo-entangle','/source.bundle','/seed/toolchain/bin/cargo','/seed/toolchain/bin/rustc')
            assert [line.split()[0] for line in observed.splitlines()] == [sha(tool),sha(BUNDLE),STAGE['compiler']['cargo'],STAGE['compiler']['rustc']]
            run('docker','exec','-i','--user=65534:65534',cid,'/usr/bin/timeout','--kill-after=10s','300s',
                'sh','-s','--',RELEASE['source_commit'],os_version,libc,stdin=(HERE/'build-guest.sh').read_bytes(),timeout=320)
            archive='/build/hello-world.tar.zst'
            data=run(*confined,'cat',archive,binary=True)
            size=int(run(*confined,'stat','-c','%s',archive)); digest=run(*confined,'sha256sum',archive).split()[0]
            assert len(data) == size > 0 and hashlib.sha256(data).hexdigest() == digest
            decoder=subprocess.run(['zstd','-dc'],input=data,capture_output=True,check=True)
            with tarfile.open(fileobj=io.BytesIO(decoder.stdout)) as tar:
                assert tar.getnames() == ['entangle.toml','plugin.wasm','plugin.wasm.sig','rebuild.json']
                items={name:tar.extractfile(name).read() for name in tar.getnames()}
            record=json.loads(items['rebuild.json'])
            assert record['source_commit'] == RELEASE['source_commit'] and items['plugin.wasm'].startswith(b'\0asm\r\0\x01\0')
            assert record['project'] == 'examples/hello-world' and record['rust_toolchain'] == '1.91.1'
            assert record['lock_sha256'] == sha(ROOT/'examples/hello-world/Cargo.lock')
            (out/'hello-world.tar.zst').write_bytes(data)
            receipt.update(archive_sha256=digest,archive_size=size,
                           members={name:{'sha256':hashlib.sha256(blob).hexdigest(),'size':len(blob)} for name,blob in items.items()},
                           signed_rebuild_record=record,exit_code=0)
        except Exception as exc:
            print(repr(exc), file=stream,flush=True)
            receipt['failure']=str(exc)
        finally:
            if cid:
                try: run('docker','rm','-f',cid)
                except Exception as exc: receipt.update(exit_code=1,cleanup_failure=str(exc))
    receipt.update(source_after=stamp(),finished_utc=utc(),sha256=sha(log))
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt['exit_code']


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('os_name',choices=STOCK)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--jammy-tool',type=Path,default=Path('/tmp/entangle-f499e3ed-portable-cargo-entangle'))
    args=parser.parse_args()
    sys.exit(build(args.os_name,args.out.resolve(),args.jammy_tool))
