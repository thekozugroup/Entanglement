"""Two consecutive native offline builds with empty targets. Requires explicit launch."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
import traceback

ROOT = Path('/workspace/Entanglement')
COMMIT = 'c19ef7587a2215ef9434b642413bebd0473caf20'
SID = 'sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644'
D = ROOT / 'docs/testing/production-review/evidence' / ('candidate-'+COMMIT[:8])
E = D/'clean-native-rebuild'
T = Path('/workspace/.entanglement-dev/rustup/toolchains/1.91.1-x86_64-unknown-linux-gnu')
CARGO = T/'bin/cargo'
CARGO_HOME = '/workspace/.entanglement-dev/cargo'
NAMES = ('entangle','entangled')


def output(*args, env=None):
    return subprocess.check_output(list(args), cwd=ROOT, text=True, env=env).strip()


def sha(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def source():
    return output('python3', 'scripts/production_score.py', '--source-id')


def write(p, j):
    tmp = p.with_suffix('.part')
    tmp.write_text(json.dumps(j, indent=2, sort_keys=True)+'\n')
    tmp.replace(p)


def elf_sections(data):
    hdr = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    assert hdr[0].startswith(b'\x7fELF\x02\x01')
    off,length,count,namesidx = hdr[6],hdr[11],hdr[12],hdr[13]
    headers=[struct.unpack_from('<IIQQQQIIQQ',data,off+length*i) for i in range(count)]
    nh=headers[namesidx]
    names=data[nh[4]:nh[4]+nh[5]]
    return {names[h[0]:].split(b'\0',1)[0].decode():(h[4],h[5])
            for h in headers if h[1] not in (0,8)}


def compare(left, right, path1, path2):
    a,b=left.read_bytes(),right.read_bytes()
    ans={'left_sha256':sha(left),'right_sha256':sha(right),'byte_equal':a==b,'sizes':[len(a),len(b)]}
    sa,sb=elf_sections(a),elf_sections(b)
    ans['different_sections']=[]
    for name in sorted(sa.keys()|sb.keys()):
        v=sa.get(name);w=sb.get(name)
        if v is None or w is None or a[v[0]:v[0]+v[1]]!=b[w[0]:w[0]+w[1]]:
            ans['different_sections'].append(name)
    def normalized(data,path,sections):
        t=bytearray(data)
        name='.note.gnu.build-id'
        if name in sections:
            o,n=sections[name]; t[o:o+n]=bytes(n)
        return bytes(t).replace(os.fsencode(path),b'<TARGET>')
    ans['embedded_target_path_counts']=[a.count(os.fsencode(path1)),b.count(os.fsencode(path2))]
    ans['equal_after_replacing_exact_target_paths_and_masking_build_id']=normalized(a,path1,sa)==normalized(b,path2,sb)
    return ans


def main():
    E.mkdir(exist_ok=False)
    shutil.copy2(__file__,E/'run.py')
    manifest=json.loads((D/'linux-archive.json').read_text())
    canonical=json.loads((D/'release-build.json').read_text())
    assert manifest['source_id']==manifest['source_after']==canonical['source_id']==canonical['source_after']==SID
    assert manifest['source_commit']==COMMIT and canonical['exit_code']==0 and source()==SID
    pristine=output('git','diff','--name-only',COMMIT,'--','Cargo.lock','Cargo.toml','crates','.cargo','scripts/package-native-release.py')
    assert not pristine,pristine
    # Purge compiler caches/wrappers and profile overrides. Preserve ordinary system build discovery.
    env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','SCCACHE','CCACHE'))}
    settings={'CARGO_HOME':CARGO_HOME,'RUSTUP_HOME':'/workspace/.entanglement-dev/rustup',
              'CARGO_INCREMENTAL':'0','CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'4',
              'CARGO_PROFILE_DEV_DEBUG':'0','RUSTC':str(T/'bin/rustc'),'RUSTDOC':str(T/'bin/rustdoc')}
    env.update(settings)
    env['PATH']=f"{T}/bin:{CARGO_HOME}/bin:"+env['PATH']
    cmd=shlex.split(canonical['command'])
    assert cmd[:4]==['cargo','build','--release','--locked']
    cmd=[str(CARGO),*cmd[1:],'--offline']
    runroot=Path(tempfile.mkdtemp(prefix='entangle-c19-clean-outputs-',dir='/tmp'))
    archive_path=ROOT/'target/release-candidate'/COMMIT[:12]/manifest['name']
    assert sha(archive_path)==manifest['sha256']
    canonical_bins=runroot/'canonical';canonical_bins.mkdir()
    import tarfile
    with tarfile.open(archive_path) as tf:
        for name in NAMES:
            f=canonical_bins/name
            with tf.extractfile(manifest['name'].removesuffix('.tar.gz')+'/'+name) as i, f.open('wb')as o:shutil.copyfileobj(i,o)
            assert sha(f)==manifest['files_sha256'][name]
    result={'commit':COMMIT,'source_before':source(),'started_utc':utc(),'host':platform.platform(),
            'cargo_lock_sha256':sha(ROOT/'Cargo.lock'),'packager_sha256':sha(ROOT/'scripts/package-native-release.py'),
            'plan_sha256':sha(D/'qualification-plan.md'),'script_sha256':sha(E/'run.py'),
            'tools':{},'build_env':settings,'native_host_target':'x86_64-unknown-linux-gnu',
            'canonical_command':canonical['command'],'build_command':cmd,'canonical_archive_sha256':sha(archive_path),
            'canonical_binary_sha256':{n:sha(canonical_bins/n) for n in NAMES},
            'official_manifest_sha256':sha(D/'linux-archive.json'),'retained_binaries_and_archives':str(runroot),
            'arms':[]}
    for name,c,args in [('cargo',CARGO,['-Vv']),('rustc',T/'bin/rustc',['-vV']),('rustdoc',T/'bin/rustdoc',['-V']),
                         ('cc',Path(shutil.which('cc')),['--version']),('ld',Path(shutil.which('ld')),['--version'])]:
        result['tools'][name]={'path':str(c),'sha256':sha(c),'version':output(c,*args,env=env)}
    for side in ('A','B'):
        r={'arm':side,'started_utc':utc(),'free_bytes_before':shutil.disk_usage('/tmp').free,
           'source_before':source(),'argv':cmd}
        result['arms'].append(r)
        keep=runroot/side; keep.mkdir()
        try:
            with tempfile.TemporaryDirectory(prefix='entangle-c19-clean-target-',dir='/tmp') as tmp:
                private=Path(tmp)
                r['empty_target_path']=tmp
                r['entries_at_start']=[i.name for i in private.iterdir()]
                assert not r['entries_at_start'] and r['source_before']==SID
                write(E/'results.json',result)
                log=E/f'build-{side}.log'
                start=time.monotonic()
                with log.open('xb') as out:
                    proc=subprocess.run(cmd,env={**env,'CARGO_TARGET_DIR':tmp},cwd=ROOT,stdout=out,stderr=subprocess.STDOUT)
                r.update(build_exit=proc.returncode,build_seconds=time.monotonic()-start,
                         build_log_sha256=sha(log),free_bytes_after_compile=shutil.disk_usage('/tmp').free)
                if proc.returncode==0:
                    for n in NAMES:shutil.copy2(private/'release'/n,keep/n)
                    r['binary_sha256']={n:sha(keep/n) for n in NAMES}
            r['private_target_reaped']=not private.exists()
            if r['build_exit']==0:
                pcmd=list(manifest['command'])
                pcmd[pcmd.index('--bin-dir')+1]=str(keep)
                pcmd[pcmd.index('--output-dir')+1]=str(keep/'packaged')
                with (E/f'package-{side}.log').open('xb') as out:
                    ret=subprocess.run(pcmd,cwd=ROOT,env=env,stdout=out,stderr=subprocess.STDOUT)
                r['packager_argv']=pcmd;r['package_exit']=ret.returncode
                if not ret.returncode:r['archive_sha256']=sha(keep/'packaged'/manifest['name'])
        except Exception as exc:
            r['exception']=repr(exc);r['exception_trace']=traceback.format_exc()
        finally:
            r.update(finished_utc=utc(),source_after=source(),free_bytes_after_cleanup=shutil.disk_usage('/tmp').free)
            write(E/'results.json',result)
    arms=result['arms']
    if all(r.get('build_exit')==0 and r.get('private_target_reaped') for r in arms):
        result['between_clean_builds']={n:compare(runroot/'A'/n,runroot/'B'/n,arms[0]['empty_target_path'],arms[1]['empty_target_path']) for n in NAMES}
        result['clean_vs_canonical']={r['arm']:{n:compare(runroot/r['arm']/n,canonical_bins/n,r['empty_target_path'],str(ROOT/'target')) for n in NAMES}for r in arms}
    result['source_after']=source();result['finished_utc']=utc()
    result['both_binaries_identical_across_empty_target_dirs']=all(v['byte_equal'] for v in result.get('between_clean_builds',{}).values()) if 'between_clean_builds' in result else None
    result['both_archives_identical_across_empty_target_dirs']=arms[0]['archive_sha256']==arms[1]['archive_sha256'] if all('archive_sha256' in r for r in arms)else None
    write(E/'results.json',result)
    return int(result['source_after']!=SID or 'between_clean_builds' not in result or any(r.get('package_exit')!=0 for r in arms))


if __name__=='__main__':
    raise SystemExit(main())
