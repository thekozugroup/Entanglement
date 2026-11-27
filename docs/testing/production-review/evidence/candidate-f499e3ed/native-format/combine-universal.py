"""Wrap two actual Mach-O programs in the fat_arch and fat_arch_64 container formats."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
base = Path(__file__).resolve().parent
inputs = [((base / (name + "-minimal")).read_bytes()) for name in ("x86_64", "arm64")]
result = {}
alignment = 14
def aligned(value):
    n = 1 << alignment
    return (value+n-1) & -n
for magic, row, output in [(0xCAFEBABE, ">IIIII", "universal32"),(0xCAFEBABF, ">IIQQII", "universal64")]:
    offsets = []
    offset = aligned(8 + len(inputs) * struct.calcsize(row))
    table = bytearray(struct.pack(">II",magic,len(inputs)))
    for data in inputs:
        cpu, subtype = struct.unpack_from("<II",data,4)
        fields = (cpu, subtype, offset, len(data), alignment)
        table.extend(struct.pack(row,*(fields+(0,) if output=="universal64" else fields)))
        offsets.append(offset)
        offset = aligned(offset+len(data))
    for data, offset in zip(inputs, offsets):
        table.extend(bytes(offset-len(table)))
        table.extend(data)
    p = base / output
    p.write_bytes(table)
    p.chmod(0o755)
    result[output] = {"sha256":hashlib.sha256(table).hexdigest(),"slice_sha256":[hashlib.sha256(x).hexdigest() for x in inputs],"file":subprocess.check_output(["file","-b",str(p)],text=True).strip(),"offsets":offsets}
(base/"universal.json").write_text(json.dumps(result,indent=2)+"\n")
print({k:v["file"] for k,v in result.items()})
