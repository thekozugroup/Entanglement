"""Produce minimal Darwin executables with the installed LLVM and Mach-O linker for header validation."""
from pathlib import Path
from datetime import datetime, timezone
import ctypes as c
import hashlib
import json
import subprocess

out = Path(__file__).resolve().parent
libdir = Path("/workspace/.entanglement-dev/rustup/toolchains/1.91-x86_64-unknown-linux-gnu/lib")
library = next(libdir.glob("libLLVM.so.*-stable"))
linker = libdir / "rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
llvm = c.CDLL(str(library))
ptr, string, integer = c.c_void_p, c.c_char_p, c.c_int
def bind(name, result, *args):
    fn = getattr(llvm, name)
    fn.restype, fn.argtypes = result, list(args)
    return fn
def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
def checked(status, error):
    if status:
        raise RuntimeError(error.value.decode() if error.value else str(status))
for prefix in ("X86", "AArch64"):
    for suffix in ("TargetInfo", "Target", "TargetMC", "AsmPrinter"):
        bind("LLVMInitialize"+prefix+suffix, None)()
create_context = bind("LLVMContextCreate", ptr)
create_buffer = bind("LLVMCreateMemoryBufferWithMemoryRangeCopy", ptr, string, c.c_size_t, string)
parse = bind("LLVMParseIRInContext", integer, ptr, ptr, c.POINTER(ptr), c.POINTER(string))
get_target = bind("LLVMGetTargetFromTriple", integer, string, c.POINTER(ptr), c.POINTER(string))
machine = bind("LLVMCreateTargetMachine", ptr, ptr, string, string, string, integer, integer, integer)
emit = bind("LLVMTargetMachineEmitToFile", integer, ptr, ptr, string, integer, c.POINTER(string))
report = {"started_utc":datetime.now(timezone.utc).isoformat(),"llvm":library.name,"llvm_sha256":sha(library),
          "linker_sha256":sha(linker),"compile_only":True,"workload":"main returns 0","outputs":{}}
for arch, triple in (("x86_64","x86_64-apple-macos11.0"),("arm64","arm64-apple-macos11.0")):
    triple_bytes = triple.encode()
    ir = ('target triple = "'+triple+'"\ndefine i32 @main() { ret i32 0 }\n').encode()
    buf=create_buffer(ir,len(ir),b"main.ll")
    module,target,err=ptr(),ptr(),string()
    checked(parse(create_context(),buf,c.byref(module),c.byref(err)),err)
    checked(get_target(triple_bytes,c.byref(target),c.byref(err)),err)
    backend=machine(target,triple_bytes,b"generic",b"",2,0,0)
    assert backend
    obj=out/(arch+".o")
    checked(emit(backend,module,str(obj).encode(),1,c.byref(err)),err)
    binary=out/(arch+"-minimal")
    argv=[str(linker),"-flavor","darwin","-arch",arch,"-platform_version","macos","11.0","11.0","-e","_main","-o",str(binary),str(obj)]
    subprocess.run(argv,check=True)
    desc=subprocess.check_output(["file","-b",str(binary)],text=True).strip()
    assert "Mach-O" in desc and ("x86_64" if arch=="x86_64" else "arm64") in desc,desc
    report["outputs"][arch]={"description":desc,"size":binary.stat().st_size,"sha256":sha(binary),"ir":ir.decode(),"link":argv}
report["finished_utc"]=datetime.now(timezone.utc).isoformat()
(out/"build.json").write_text(json.dumps(report,indent=2)+"\n")
print([(k,v["description"]) for k,v in report["outputs"].items()])
