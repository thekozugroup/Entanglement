"""Install the actual freshly rebuilt archive, verify the running daemon and signed output."""
import hashlib,json,os,secrets,shutil,stat,subprocess,tempfile,time,tomllib
from datetime import datetime,timezone
from pathlib import Path
root=Path('/workspace/Entanglement')
d=root/'docs/testing/production-review/evidence/candidate-c19ef758/clean-native-rebuild'
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def utc():return datetime.now(timezone.utc).isoformat()
def sid():return subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=root,text=True).strip()
j=json.loads((d/'results.json').read_text());arm=j['arms'][0];ar=json.loads((d/'package-A-corrected.json').read_text())
ver=json.loads((d.parent/'linux-archive.json').read_text());name=ver['name'];src=Path(j['retained_binaries_and_archives'])/'A/packaged-corrected'
before=sid();assert before==j['source_before']==ar['source_after'] and sha(src/name)==ar['archive_sha256']
fixture=root/'crates/entangle-host/tests/fixtures/hello-pong.wasm'
challenge='c19-clean-A-'+secrets.token_hex(12);expected=('Hello, '+challenge+'!').encode()
report={'source_before':before,'commit':j['commit'],'started_utc':utc(),'arm':'A','real_archive_sha256':sha(src/name),
        'installer_sha256':sha(root/'scripts/install.sh'),'guest_sha256':sha(fixture),'script_sha256':sha(Path(__file__)),
        'registry_transport':'local read-only stand-in for the two exact pinned GitHub release URLs (archive and sha256 sidecar)',
        'challenge':challenge,'expected_utf8':expected.decode(),'expected_bytes':len(expected),'commands':[]}
with tempfile.TemporaryDirectory(prefix='entangle-c19-signed-clean-')as tmp:
 t=Path(tmp);home=t/'home';home.mkdir();prefix=t/'installed';wr=t/'fixture';wr.mkdir()
 wrapper=wr/'curl';wrapper.write_text("""#!/bin/sh
set -eu
[ "$#" -eq 7 ] && [ "$1" = "-fsSL" ] && [ "$2" = "--proto" ] && [ "$3" = "=https" ] && [ "$4" = "--tlsv1.2" ] && [ "$5" = "-o" ]
case "$7" in
    "$IMMUTABLE_URL"|"$IMMUTABLE_URL.sha256") ;;
    *) exit 42 ;;
esac
printf '%s\\n' "$7" >> "$FETCH_LOG"
exec cp "$ARCHIVE_PARENT/${7##*/}" "$6"
"""); wrapper.chmod(0o700)
 url='https://github.com/thekozugroup/Entanglement/releases/download/v0.1.0/'+name;fetch=t/'fetch.log'
 env={'HOME':str(home),'PATH':str(wr)+':/usr/local/bin:/usr/bin:/bin','LANG':'C',
      'TOKIO_WORKER_THREADS':'2','RAYON_NUM_THREADS':'2','IMMUTABLE_URL':url,'FETCH_LOG':str(fetch),'ARCHIVE_PARENT':str(src)}
 def run(argv):
  r=subprocess.run(list(map(str,argv)),env=env,cwd=root,text=True,capture_output=True,timeout=60)
  report['commands'].append({'argv':list(map(str,argv)),'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  if r.returncode:raise RuntimeError(r.stderr)
  return r
 proc=None
 try:
  run(['sh','scripts/install.sh','--version','0.1.0','--prefix',prefix]);bdir=prefix/'bin'
  actual={k:sha(bdir/k)for k in arm['binary_sha256']};assert actual==ar['extracted_elf_sha256']==arm['binary_sha256']
  report['installed_sha256']=actual;report['fetch_urls']=fetch.read_text().splitlines()
  assert sorted(report['fetch_urls'])==sorted((url,url+'.sha256'))
  cli=bdir/'entangle';run([cli,'init','--non-interactive'])
  base=home/'.entangle';(base/'config.toml').write_text('[mesh]\ntransports=[]\n');uds=base/'sock'
  with (d/'clean-A-daemon.log').open('xb') as logs:
   proc=subprocess.Popen([bdir/'entangled','run'],env=env,cwd=t,stdout=logs,stderr=subprocess.STDOUT)
   try:
    end=time.monotonic()+25
    while not uds.is_socket() and proc.poll() is None and time.monotonic()<end:time.sleep(.05)
    assert uds.is_socket() and proc.poll() is None
    report['live_exe_sha256']=sha(Path(f'/proc/{proc.pid}/exe'));assert report['live_exe_sha256']==actual['entangled']
    report['uds_mode']=oct(stat.S_IMODE(uds.stat().st_mode));assert report['uds_mode']=='0o600'
    run([cli,'plugins','install','hello-world','--catalog',root/'examples','--wasm',fixture])
    manifest=base/'plugins/hello-world/entangle.toml';plugin=tomllib.loads(manifest.read_text())['plugin']['id']
    report['plugin_id']=plugin;report['signed_manifest_sha256']=sha(manifest)
    of=t/'actual.raw';run([cli,'compute','dispatch',plugin,'--cpu-cores','0.01','--input',challenge,'--output-file',of])
    result=of.read_bytes();assert result==expected
    report['actual_utf8']=result.decode();report['actual_sha256']=hashlib.sha256(result).hexdigest()
   finally:
    proc.terminate()
    try:proc.wait(timeout=10)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
    report['daemon_reaped']=proc.poll() is not None
 except Exception as exc:
  report['error']=repr(exc)
report.update(source_after=sid(),finished_utc=utc(),profile_reaped=not Path(tmp).exists())
report['pass']=report['source_after']==before and 'error' not in report and report['daemon_reaped'] and report['profile_reaped']
with (d/'clean-A-functional.json').open('x')as f:json.dump(report,f,indent=2,sort_keys=True);f.write('\n')
raise SystemExit(0 if report['pass'] else 1)
