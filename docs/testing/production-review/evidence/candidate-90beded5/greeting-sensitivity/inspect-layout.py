"""ELF64 little-endian section and absolute PCs from the linker's .eh_frame_hdr index."""
import collections
import hashlib
import json
from pathlib import Path
import struct
import subprocess

here=Path(__file__).resolve().parent
root=Path('/workspace/Entanglement')
base=Path('/tmp/entangle-link-performance-90beded5')
commits={'baseline':'a5728c23','candidate':'90beded5'}
def inspect(stage):
    p=base/stage/'entangled'
    data=p.read_bytes()
    assert data[:7]==b'\x7fELF\x02\x01\x01'
    section_start=struct.unpack_from('<Q',data,40)[0]
    step,count,names=struct.unpack_from('<HHH',data,58)
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,section_start+i*step) for i in range(count)]
    def piece(row): return data[row[4]:row[4]+row[5]]
    strings=piece(rows[names])
    sections={strings[r[0]:strings.index(b'\0',r[0])].decode():r for r in rows}
    desc={}
    for name,s in sections.items():
        desc[name]={'address':s[3],'file_offset':s[4],'bytes':s[5],'sha256':None if s[1]==8 else hashlib.sha256(piece(s)).hexdigest()}
    s=sections['.eh_frame_hdr']
    hdr=piece(s)
    assert hdr[:4]==b'\x01\x1b\x03\x3b' # pcrel sdata4 FDE pointer; count udata4; table datarel sdata4
    n=struct.unpack_from('<I',hdr,8)[0]
    starts=[s[3]+struct.unpack_from('<i',hdr,12+8*i)[0] for i in range(n)]
    text=sections['.text']
    starts=[v for v in starts if text[3]<=v<text[3]+text[5]]
    assert starts==sorted(starts)
    compact={'path':str(p),'elf_sha256':hashlib.sha256(data).hexdigest(),'sections':desc,
             'compiler_comment':piece(sections['.comment']).decode(errors='replace').split('\0'),
             'build_ids':subprocess.check_output(['readelf','-n',str(p)],text=True).strip(),
             'indexed_text_start_count':len(starts)}
    return compact, starts, text, piece(text)
a,sa,ta,ba=inspect('baseline')
b,sb,tb,bb=inspect('candidate')
diffs={}
for name in sorted(set(a['sections'])|set(b['sections'])):
    x,y=a['sections'].get(name),b['sections'].get(name)
    if x!=y:diffs[name]={'baseline':x,'candidate':y}
indexed={}
if len(sa)==len(sb):
    byte_equal=0; size_equal=0
    offsets=collections.Counter(); sequences=[]
    for i in range(len(sa)):
        aa = sa[i]-ta[3]; az=sa[i+1]-ta[3] if i+1<len(sa) else ta[5]
        cc = sb[i]-tb[3]; cz=sb[i+1]-tb[3] if i+1<len(sb) else tb[5]
        byte_equal+= ba[aa:az]==bb[cc:cz]
        size_equal+= az-aa==cz-cc
        offsets[cc-aa]+=1
        if not sequences or sequences[-1]['shift']!=cc-aa:
            sequences.append({'first_index':i,'first_baseline_PC':hex(sa[i]),'shift':cc-aa})
    indexed['same_index_span_bytes_equal_count']=byte_equal
    indexed['same_index_span_length_equal_count']=size_equal
    indexed['relative_start_difference_histogram']=dict(sorted(offsets.items()))
    indexed['contiguous_index_shift_ranges']=sequences
out={'stage':{'baseline':a,'candidate':b},'section_diff':diffs,'same_index_comparison':indexed,
     'limitation':'Indexed ranges are adjacent sorted unwind-entry starts, not named functions. Code positions may move or reorder. Matching a range by ordinal does not establish its identity or execution by the benchmark. Both artifacts lack a static symbol table.'}
(here/'elf-layout.json').write_text(json.dumps(out,indent=2)+'\n')
print('entries',len(sa),len(sb),{k:v for k,v in indexed.items() if 'ranges' not in k})
print('changed sections',list(diffs),'text movement ranges',len(indexed.get('contiguous_index_shift_ranges',[])))
