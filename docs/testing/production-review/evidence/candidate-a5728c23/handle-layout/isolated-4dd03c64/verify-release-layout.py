from pathlib import Path
import hashlib,json,subprocess,re,tempfile
out=Path(__file__).resolve().parent;private=Path('/tmp/entangle-compact-cache/release');archive=Path('/workspace/Entanglement/target/release');rust='/workspace/.entanglement-dev/rustup/toolchains/1.91-x86_64-unknown-linux-gnu/bin/rustc'
def sha(p):
 with p.open('rb') as src:return hashlib.file_digest(src,'sha256').hexdigest()
def probe(profile,elf_sha):
 def dep(parent,name):
  value=next(d[-1] for d in json.loads(parent.read_text())['deps'] if d[1]==name).to_bytes(8,'little').hex()
  matches=[m for m in (profile/'.fingerprint').glob(name.replace('_','-')+'-*/lib-'+name) if m.read_text()==value];assert len(matches)==1,matches;return matches[0]
 tag=next(f.name.split('-')[1] for f in (profile/'deps').glob('entangled-*') if not f.suffix and f.is_file() and sha(f)==elf_sha)
 runtime=dep(profile/'.fingerprint'/('entangle-bin-'+tag)/'bin-entangled.json','entangle_runtime')
 host=dep(runtime.with_suffix('.json'),'entangle_host')
 m=profile/'deps'/('libentangle_host-'+host.parent.name.rsplit('-',1)[1]+'.rmeta')
 with tempfile.TemporaryDirectory(dir='/tmp') as td:
  q=Path(td)/'measure.rs';q.write_text('#[no_mangle] pub extern "C" fn packed_handle_size() -> usize { std::mem::size_of::<entangle_host::LoadedPlugin>() }')
  ir=Path(td)/'measure.ll';subprocess.run([rust,'--crate-type=lib','--edition=2021','-Copt-level=3','-Ccodegen-units=1','-Clto=thin','--emit=llvm-ir','-L','dependency='+str(profile/'deps'),'--extern','entangle_host='+str(m),q,'-o',ir],check=True)
  res=re.search(r'@packed_handle_size\(\)[^{]+\{\s*start:\s*ret i64 (\d+)',ir.read_text())
  assert res is not None
 return dict(elf_sha256=elf_sha,daemon_dep=tag,runtime_marker=runtime.parent.name,host_marker=host.parent.name,host_fingerprint=host.read_text(),host_metadata_sha256=sha(m),size_bytes=int(res[1]))
build=json.loads((out/'release-build.json').read_text());assert build['exit_code']==0
p=json.loads((out/'preregistration.json').read_text())
d={'revision':build['source_commit'],'source_id':build['source_after'],'compiler':subprocess.check_output([rust,'-vV'],text=True),'release_profile':'Both Cargo invocations used identical root build command and profile flags. Follow Cargo .fingerprint deps from exact ELF hashes through runtime and Wasmtime host. Query actual released host metadata using size_of::<LoadedPlugin>().','c19':probe(archive,p['inputs']['c19']['sha256']['entangled']),'frozen_296b':probe(archive,p['inputs']['A']['sha256']['entangled']),'compact_4dd':probe(private,build['files_sha256']['entangled'])}
assert [d[stage]['size_bytes'] for stage in ['c19','frozen_296b','compact_4dd']]==[144,208,136]
with (out/'release-layout.json').open('x') as stream:json.dump(d,stream,indent=2);print(file=stream)
