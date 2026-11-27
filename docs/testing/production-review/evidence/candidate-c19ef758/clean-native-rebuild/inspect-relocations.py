"""Count normalized RO entries and trace actual changed x86 operands via GNU objdump."""
from collections import Counter
from pathlib import Path
import bisect,hashlib,json,os,re,struct,subprocess
import numpy as np
E=Path('/workspace/Entanglement/docs/testing/production-review/evidence/candidate-c19ef758/clean-native-rebuild')
j=json.loads((E/'results.json').read_text());assert not j['both_binaries_identical_across_empty_target_dirs']
arms={a['arm']:os.fsencode(a['empty_target_path']) for a in j['arms']};assert len(arms['A'])==len(arms['B'])
R=Path(j['retained_binaries_and_archives']);sh=lambda x:hashlib.sha256(x).hexdigest()
def elf(data):
 h=struct.unpack_from('<16sHHIQQQIHHHHHH',data);s=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+i*h[11])for i in range(h[12])]
 n=s[h[13]];names=data[n[4]:n[4]+n[5]];return {names[v[0]:].split(b'\0',1)[0].decode():dict(vma=v[3],offset=v[4],size=v[5]) for v in s if v[1] not in (0,8)}
def payload(dat,h):return dat[h['offset']:h['offset']+h['size']]
def instructions(path,interesting):
 cmd=['objdump','-d','-j','.text','--no-show-raw-insn',str(path)]
 run=subprocess.Popen(cmd,stdout=subprocess.PIPE);it=iter(interesting);cursor=next(it,None);previous=None;selected={}
 for line in run.stdout:
  if cursor is None:continue
  left,sep,right=line.partition(b':\t')
  if not sep:continue
  try:address=int(left,16)
  except ValueError:continue
  if previous and previous[0]<=cursor<address:
   selected[previous[0]]=(address,previous[1])
   while cursor is not None and cursor<address:cursor=next(it,None)
  previous=address,right.decode().strip()
 assert run.wait()==0 and cursor is None
 return selected
def noteq(x,y):return sum(v!=w for v,w in zip(x,y))
def read_target(s):
 return re.search(r'#\s*([\da-f]+)(?:\s|$)',s)
def without_addr(s):
 return re.sub(r'[-]?(?:0x)?[0-9a-f]+\(%rip\)','<displacement>(%rip)',s.split('#')[0].strip())
report={'raw_builds':sh((E/'results.json').read_bytes()),'tool':subprocess.check_output(['objdump','--version'],text=True).splitlines()[0],'results':{}}
for n in ('entangle','entangled'):
 store={}
 for side in 'AB':
  p=R/side/n;d=p.read_bytes();sects=elf(d);text=payload(d,sects['.text']);z=payload(d,sects['.rodata']).replace(arms[side],b'_stable_target_'.ljust(len(arms[side]),b'_'))
  rel=np.frombuffer(payload(d,sects['.rela.dyn']),dtype='<i8').reshape(-1,3)
  store[side]=(sects,text,z,rel)
 tva=store['A'][0]['.text']['vma'];rova=store['A'][0]['.rodata']['vma'];ta,ra,la=store['A'][1:];tb,rb,lb=store['B'][1:]
 assert store['B'][0]['.text']['vma']==tva and store['B'][0]['.rodata']['vma']==rova
 dz=np.flatnonzero(np.frombuffer(ta,dtype='u1')!=np.frombuffer(tb,dtype='u1'));interesting=[tva+int(i)for i in dz]
 countsA=Counter(ra.split(b'\0'));countsB=Counter(rb.split(b'\0'))
 # Use the normalized suffix up to the next NUL (a pointer may target the interior).
 def sval(data,v):
  if not rova<=v<rova+len(data):return None
  pos=v-rova;end=data.find(b'\0',pos);return data[pos:end] if end>=0 else data[pos:]
 assert np.array_equal(la[:,:2],lb[:,:2]);rcount=int(np.count_nonzero(la[:,2]!=lb[:,2]));rorefs=Counter()
 for a,b in zip(la[:,2],lb[:,2]):
  if a!=b:
   x,y=sval(ra,int(a)),sval(rb,int(b));rorefs['both_in_rodata']+=x is not None and y is not None;rorefs['normalized_nul_suffix_equal']+=x is not None and x==y
 ins={s:instructions(R/s/n,interesting)for s in 'AB'};assert ins['A'].keys()==ins['B'].keys()
 info=Counter();examples=[];other=[];unequal=[]
 for address,(end,a)in ins['A'].items():
  b=ins['B'][address][1];pa,pb=read_target(a),read_target(b)
  assert end==ins['B'][address][0]
  info['same_instruction_mnemonic']+=a.split()[0]==b.split()[0]
  pa=int(pa[1],16)if pa else None;pb=int(pb[1],16)if pb else None
  if pa is not None and pb is not None:
   xa,xb=sval(ra,pa),sval(rb,pb)
   if xa is not None and xb is not None:info['both_references_in_rodata']+=1
   if xa is not None and xa==xb:info['normalized_nul_suffix_equal']+=1
   elif xa is not None and xb is not None:
    limit=min(len(xa),len(xb))
    common=next((i for i in range(limit) if xa[i]!=xb[i]),limit)
    unequal.append({'pc_hex':hex(address),'a_target':hex(pa),'b_target':hex(pb),'common_prefix_bytes':common,'normalized_nul_suffix_len':[len(xa),len(xb)],'prefix_A_hex':xa[:24].hex(),'prefix_B_hex':xb[:24].hex()})
  exact=without_addr(a)==without_addr(b)
  if exact:info['same_instruction_text_except_rip_displacement_and_comment']+=1
  elif len(other)<12:other.append({'pc_hex':hex(address),'A':a,'B':b})
  if len(examples)<4:examples.append({'pc_hex':hex(address),'A':a,'B':b})
 report['results'][n]={'size_of_text':len(ta),'size_of_rodata':len(ra),'normalized_rodata_tokens':sum(countsA.values()),'normalized_missing_from_A':sum((countsB-countsA).values()),'normalized_missing_from_B':sum((countsA-countsB).values()),'relocation_offsets_and_types_equal':True,'relocations_with_different_addends':rcount,'relocation_checks':dict(rorefs),
                       'text_bytes_different':len(dz),'instructions_containing_different_bytes':len(ins['A']),'instruction_checks':dict(info),'normalized_suffix_not_equal':unequal,'instruction_examples':examples,'examples_with_additional_differences':other}
(E/'link-layout-correlation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
