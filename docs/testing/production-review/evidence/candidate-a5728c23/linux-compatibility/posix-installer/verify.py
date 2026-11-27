"""Offline, unprivileged Ubuntu installer and signed-work check, using current release assets."""
import argparse,datetime,hashlib,json,os,re,shutil,subprocess,sys,tarfile,tempfile,traceback
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--repo',required=True,type=Path)
p.add_argument('--canonical',required=True,type=Path)
p.add_argument('--canonical-receipt',required=True,type=Path)
p.add_argument('--portable',type=Path)
p.add_argument('--portable-receipt',type=Path)
p.add_argument('--wasm',required=True,type=Path)
p.add_argument('--b3sum',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
a=p.parse_args()
r=a.repo.resolve();lab=Path(__file__).resolve().parent
commit='a5728c230e5049556b806cae8597fe823dd67987';source='sha256:a43296d252b79d7a0762861de1251b0e2e77fde20af2ea5dd43254617376fce5'
def stamp():
 head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip()
 sid=subprocess.check_output([sys.executable,'scripts/production_score.py','--source-id'],cwd=r,text=True).strip()
 assert head==commit and sid==source,(head,sid)
 return sid
def sha(f):
 with f.open('rb') as src:return hashlib.file_digest(src,'sha256').hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def copy(src,dest):
 shutil.copyfile(src,dest);dest.chmod(0o444)
def verified(file,receipt):
 meta=json.loads(receipt.read_text())
 assert meta['source_commit']==commit and meta['source_id']==source,meta.keys()
 if 'source_after' in meta:assert meta['source_after']==source
 name=file.name
 assert name==meta['name'] and sha(file)==meta['sha256']
 b3=subprocess.check_output([a.b3sum,'--no-names',file],text=True).strip()
 assert b3==meta['blake3']
 for ext,digest in [('.sha256',sha(file)),('.b3',b3)]:
  assert (file.parent/(name+ext)).read_text().split()==[digest,name]
 hashes={}
 with tarfile.open(file,'r:gz') as tar:
  for key in ['entangle','entangled']:
   member,=[m for m in tar if m.name==name.removesuffix('.tar.gz')+'/'+key and m.isreg()]
   with tar.extractfile(member) as f:hashes[key]=hashlib.file_digest(f,'sha256').hexdigest()
   assert hashes[key]==meta['files_sha256'][key]
 return dict(name=name,sha256=sha(file),blake3=b3,files_sha256=hashes,receipt_sha256=sha(receipt),sidecars_sha256={ext:sha(file.parent/(name+ext)) for ext in ['.sha256','.b3']})
def records(stdout):
 vals={}
 for line in stdout.splitlines():
  if not line.startswith('OBS\t'): continue
  _,key,value=line.split('\t',2);assert key not in vals
  vals[key]=value
 return vals
def run(result):
 files={'canonical':(a.canonical,a.canonical_receipt)}
 if a.portable:files['jammy']=(a.portable,a.portable_receipt)
 assets={k:verified(f,m) for k,(f,m) in files.items()};result['archives']=assets
 image_ids={k:subprocess.check_output(['docker','image','inspect','ubuntu:'+k,'--format','{{index .RepoDigests 0}}'],text=True).strip() for k in ['22.04','24.04']}
 mode='update' if a.portable else 'fresh-canonical'
 result.update(mode=mode,images=image_ids,cases={},installer_sha256=sha(r/'scripts/install.sh'),wasm_sha256=sha(a.wasm),wasm_manifest_sha256=sha(r/'plugins/json-pointer/entangle.toml'),curl_adapter_sha256=sha(lab/'curl-fixture.sh'),container_driver_sha256=sha(lab/'run-in-container.sh'),host_driver_sha256=sha(Path(__file__)))
 with tempfile.TemporaryDirectory(prefix='entangle-posix-inputs-',dir='/tmp') as t:
  stage=Path(t);stage.chmod(0o755)
  for variant,(file,receipt) in files.items():
   folder=stage/variant;folder.mkdir();folder.chmod(0o755)
   for ext in ['','.sha256','.b3']:copy(file.parent/(file.name+ext),folder/(file.name+ext))
  for f in ['run-in-container.sh','curl-fixture.sh']:copy(lab/f,stage/f)
  copy(r/'scripts/install.sh',stage/'install.sh')
  sample=stage/'sample';sample.mkdir();sample.chmod(0o755)
  copy(a.wasm,sample/'component.wasm');copy(r/'plugins/json-pointer/entangle.toml',sample/'entangle.toml')
  for v,im in image_ids.items():
   ca=assets['canonical'];po=assets.get('jammy',{}).get('files_sha256',{})
   flags=['--rm','--pull=never','--read-only','--network','none','--cap-drop=ALL','--security-opt','no-new-privileges','--user','65534:65534','--platform','linux/amd64','--tmpfs','/tmp:rw,nosuid,nodev,noexec,mode=1777','--tmpfs','/work:rw,nosuid,nodev,exec,mode=1777']
   result['container_flags']=flags
   cmd=['docker','run',*flags,'--mount',f'type=bind,src={stage},dst=/fixture,readonly',im,'/bin/sh','/fixture/run-in-container.sh',v,mode,ca['name'],ca['files_sha256']['entangle'],ca['files_sha256']['entangled'],po.get('entangle','-'),po.get('entangled','-')]
   reply=subprocess.run(cmd,capture_output=True,text=True,timeout=65)
   values=records(reply.stdout)
   result['cases'][v]={'container_exit':reply.returncode,'observations':values}
   if reply.returncode:
    result['cases'][v]['diagnostic']=reply.stderr[-1400:];raise AssertionError((v,reply.returncode,values,reply.stderr[-450:]))
   assert values['uid']=='65534' and values['distro']==v and 'dash' in values['posix_shell']
   assert values['libc']==('glibc 2.35' if v=='22.04' else 'glibc 2.39')
   if mode=='update':
    last='after_rejection' if v=='22.04' else 'after_upgrade'
    for field in ['peer','signature_sha256','plugin_id']:assert values['portable.'+field]==values[last+'.'+field]
    assert values['canonical_update.install_exit']==('1' if v=='22.04' else '0')
    assert values['portable.expected_output']!=values[last+'.expected_output']
if a.output.exists():raise FileExistsError(a.output)
result={'source_commit':commit,'source_before':stamp(),'started_utc':now(),'historical_reference':'candidate-c19ef758/transactional-installer/curl-fixture.sh is the offline adapter design; measurements here are fresh for a5728c23','exit_code':1}
try:run(result);result['exit_code']=0
except Exception as err:result.update(error=repr(err),traceback=traceback.format_exc())
result.update(source_after=stamp(),finished_utc=now())
with a.output.open('x') as f:json.dump(result,f,indent=2);print(file=f)
print(result['exit_code'],{v:x['container_exit'] for v,x in result.get('cases',{}).items()},result.get('error',''));sys.exit(result['exit_code'])
