"""Preserve initial packaging errors; correct only the discovered checksum tool PATH."""
import hashlib,json,os,subprocess,sys,tarfile,shutil
from pathlib import Path
from datetime import datetime,timezone
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def utc():return datetime.now(timezone.utc).isoformat()
w=Path('/workspace/Entanglement');e=w/'docs/testing/production-review/evidence/candidate-c19ef758/clean-native-rebuild'
j=json.loads((e/'results.json').read_text());side=sys.argv[1];a=next(r for r in j['arms'] if r['arm']==side)
assert a['build_exit']==0 and a['private_target_reaped']
a_root=Path(j['retained_binaries_and_archives'])/side
m=json.loads((e.parent/'linux-archive.json').read_text());before=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],text=True,cwd=w).strip()
assert before==j['source_before']==a['source_after']==m['source_id']
b3=Path('/workspace/.entanglement-dev/release-tools/bin/b3sum')
env={**os.environ,'PATH':str(b3.parent)+':'+os.environ['PATH']}
pcmd=a['packager_argv'].copy();pcmd[pcmd.index('--output-dir')+1]=str(a_root/'packaged-corrected')
start=utc()
with (e/f'package-{side}-corrected.log').open('xb') as log:
 r=subprocess.run(pcmd,cwd=w,env=env,stdout=log,stderr=subprocess.STDOUT)
rec={'commit':j['commit'],'arm':side,'source_before':before,'argv':pcmd,'original_exit':a['package_exit'],
 'original_error_log_sha256':sha(e/f'package-{side}.log'),'started_utc':start,'finished_utc':utc(),'exit_code':r.returncode,
 'corrected_log_sha256':sha(e/f'package-{side}-corrected.log'), 'packaging_tool':str(b3),'b3sum_binary_sha256':sha(b3),'b3sum_version':subprocess.check_output([b3,'--version'],text=True).strip()}
if r.returncode==0:
 p=a_root/'packaged-corrected'/m['name'];h=sha(p);b=subprocess.check_output([b3,p],text=True).split()[0]
 assert (Path(str(p)+'.sha256').read_text().split()[0],Path(str(p)+'.b3').read_text().split()[0])==(h,b)
 with tarfile.open(p)as tf:
  extracted={n:hashlib.sha256(tf.extractfile(m['name'].removesuffix('.tar.gz')+'/'+n).read()).hexdigest() for n in ('entangle','entangled')}
 assert extracted==a['binary_sha256']
 rec.update(archive_sha256=h,archive_blake3=b,archive_bytes=p.stat().st_size,canonical_archive_equal=m['sha256']==h,extracted_elf_sha256=extracted)
rec['source_after']=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],text=True,cwd=w).strip();assert rec['source_after']==before
(e/f'package-{side}-corrected.json').write_text(json.dumps(rec,indent=2,sort_keys=True)+'\n')
raise SystemExit(r.returncode)
