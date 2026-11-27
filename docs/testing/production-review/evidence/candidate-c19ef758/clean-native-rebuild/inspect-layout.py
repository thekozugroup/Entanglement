"""Independent ELF64 section, generated-source path, and toolchain evidence."""
from pathlib import Path
from collections import Counter
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
D=Path('/workspace/Entanglement/docs/testing/production-review/evidence/candidate-c19ef758/clean-native-rebuild')
wp=importlib.util.spec_from_file_location('build',D/'run.py')
b=importlib.util.module_from_spec(wp);wp.loader.exec_module(b)
j=json.loads((D/'results.json').read_text());root=Path(j['retained_binaries_and_archives'])
man=json.loads((D.parent/'linux-archive.json').read_text())
ph={x['arm']:x['empty_target_path']for x in j['arms']}
ph['canonical']=str(b.ROOT/'target')
STDLIB_SUFFIX=re.compile(rb'(?:/workspace/\.entanglement-dev/rustup/toolchains/[^/ ]+/lib/rustlib/src/rust|/rustc/[0-9a-f]{40})/library/[A-Za-z0-9_./-]+?\.rs')
GENERATED=re.compile(rb'/(?:workspace/Entanglement/target|tmp/entangle-c19-clean-target-[a-z0-9_]+)/release/build/[^/ ]+/out/[A-Za-z0-9_./-]+?\.rs')
sha=lambda v:hashlib.sha256(v).hexdigest()
def summary(data,target):
    sections=b.elf_sections(data)
    paths=[]
    for rx in [GENERATED,STDLIB_SUFFIX]:
        for m in rx.finditer(data):
            sec=next((k for k,(o,n)in sections.items() if o<=m.start()<o+n),None)
            paths.append({'offset':m.start(),'section':sec,'path':m.group().decode()})
    return {'sha256':sha(data),'file_size':len(data),'embedded_generated_and_std_paths':paths,
            'gnu_build_id_note_hex':data[slice(sections['.note.gnu.build-id'][0],sum(sections['.note.gnu.build-id']))].hex(),
            'comment':data[slice(sections['.comment'][0],sum(sections['.comment']))].decode().split('\0'),
            'sections':{k:{'offset':o,'bytes':n,'sha256':sha(data[o:o+n])}for k,(o,n)in sections.items()}}
def difference(name,ls,rs,x,y):
    lx,ry=summary(x,ph[ls]),summary(y,ph[rs]);l=lx['sections'];r=ry['sections']
    changed={k:{ls:l.get(k),rs:r.get(k)}for k in sorted(l.keys()|r.keys()) if l.get(k,{}).get('sha256')!=r.get(k,{}).get('sha256')}
    out={'changed_section_contents':changed,'file_size_difference_bytes':len(y)-len(x),'exactly_equal':x==y}
    if len(x)==len(y):
        xbuf=bytearray(x)
        originals=lx['embedded_generated_and_std_paths']
        xp=os.fsencode(ph[ls]);yp=os.fsencode(ph[rs]);delta=[]
        if len(xp)==len(yp):
            for p in originals:
                if p['path'].startswith(ph[ls]+'/release/build/'):
                    off=p['offset'];assert xbuf[off:off+len(xp)]==xp
                    xbuf[off:off+len(xp)]=yp
                    delta.append({'offset':off,'suffix':p['path'][len(ph[ls]):],'length':len(xp)})
            o=l['.note.gnu.build-id']['offset'];n=l['.note.gnu.build-id']['bytes']
            o2=r['.note.gnu.build-id']['offset'];n2=r['.note.gnu.build-id']['bytes']
            if (o,n)==(o2,n2):
                # Mask only the GNU build-id descriptor; preserve every other note header byte.
                namesz,descsz,ntype=struct.unpack_from('<III',x,o);data_off=o+12+((namesz+3)//4)*4
                assert ntype==3 and x[o+12:o+12+namesz]==b'GNU\0'
                xbuf[data_off:data_off+descsz]=y[data_off:data_off+descsz]
                out['offline_diagnostic_replay']={'patched_only_embedded_generated_roots':delta,
                    'copied_build_id_descriptor_bytes':descsz,'equal_to_other_entire_elf_after_replacements':xbuf==y,
                    'reconstructed_sha256':sha(xbuf),'other_elf_sha256':sha(y),
                    'remaining_mismatches_count':sum(a!=b for a,b in zip(xbuf,y)) if xbuf!=y else 0}
    return out
def report():
    sides=['canonical','A','B'] if (root/'B/entangled').exists() else ['canonical','A']
    data={'commit':j['commit'],'source':j['source_before'],'raw_build_receipt_sha256':b.sha(D/'results.json'),
          'source_manifest_sha256':j['official_manifest_sha256'],'scope':'Read-only diagnostic of retained unmodified ELF files, private in-memory substitution only. Reconstructed hashes are not newly built artifacts.', 'arms':{},'comparisons':{}}
    for n in b.NAMES:
        bufs={side:(root/side/n).read_bytes() for side in sides}
        data['arms'][n]={s:summary(bufs[s],ph[s]) for s in sides}
        data['comparisons'][n]={}
        for ls,rs in [('A','canonical'),('B','canonical'),('A','B')]:
            if ls in bufs and rs in bufs:
                data['comparisons'][n][ls+'-to-'+rs]=difference(n,ls,rs,bufs[ls],bufs[rs])
    dest=D/('elf-layout-verified.json' if 'B' in sides else 'elf-layout-preliminary.json')
    dest.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
if __name__=='__main__':report()
