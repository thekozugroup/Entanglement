"""Read the available upstream Git object database; never checks out or executes upstream code."""
from pathlib import Path
import json
import re
import subprocess
import sys

repo=Path(sys.argv[1]).resolve()
def git(*args,stdin=None,check=True):
    return subprocess.run(["git","-C",repo,*args],input=stdin,capture_output=True,text=True,check=check)
def command(*args):return git(*args).stdout.strip()
revs=command("rev-list","--all").splitlines()
path="jaq-core/tests/named.rs"
keys=[r+":"+path for r in revs]
hashes=git("cat-file","--batch-check=%(objectname) %(objecttype)",stdin="\n".join(keys)+"\n").stdout.splitlines()
assert len(hashes)==len(revs)
blobs={h.split()[0] for h in hashes if h.endswith(" blob")}
test_pattern=re.compile(r'fn\s+now\s*\(\s*\)\s*\{[^}]*?"now\s*\|\s*round"[^}]*?\.as_secs\(\)',re.S)
affected_blobs={h for h in blobs if test_pattern.search(command("cat-file","blob",h))}
affected=[r for r,l in zip(revs,hashes) if l.split()[0] in affected_blobs]
history_names={"allocator_introduced":"c12729ad","allocator_optional_default_on":"274c90e0","golden_tests_introduced":"dadd1473","eight_goldens_present":"4b514394","clock_case_introduced":"90cabdc4","clock_case_removed":"191e5e67"}
hist={}
for name,short in history_names.items():
    commit,author,committer,parents,title=command("show","-s","--format=%H%x09%aI%x09%cI%x09%P%x09%s",short).split("\t")
    hist[name]={"commit":commit,"authored":author,"committed":committer,"parents":parents.split(),"title":title}
def file(r,p):return command("show",r+":"+p)
rows=[]
for r in sorted(affected):
    gold=file(r,"jaq/tests/golden.rs")
    cli=file(r,"jaq/Cargo.toml")
    upstream_docs=git("grep","-n","-i","-E","wasm32|webassembly|\\bwasi\\b",r,"--","*.md","*.yml","*.yaml","*.toml","*.sh",".cargo/*",check=False)
    assert upstream_docs.returncode in (0,1)
    meta={k:git("merge-base","--is-ancestor",v["commit"],r,check=False).returncode==0 for k,v in hist.items()}
    names=re.findall(r"#\[test\]\s*fn (\w+)\(",gold)
    details={"commit":r,"date":command("show","-s","--format=%cI",r),"ancestors":meta,"named_test_blob":command("rev-parse",r+":"+path),"golden_blob":command("rev-parse",r+":jaq/tests/golden.rs"),"golden_cases":names,"golden_has_build_time_input_path":'env!("CARGO_MANIFEST_DIR")' in gold,"golden_launches_external_binary":'process::Command::new(env!("CARGO_BIN_EXE_jaq"))' in gold,"mimalloc_default":bool(re.search(r'^default\s*=\s*\[\s*"mimalloc"\s*\]',cli,re.M)),"source_enables_allocator":'mimalloc::MiMalloc' in file(r,"jaq/src/main.rs"),"workspace_build_docs_wasm_matches":upstream_docs.stdout.strip().splitlines(),"upstream_workflow":file(r,".github/workflows/rust.yml")}
    assert len(names)==8 and details["mimalloc_default"] and details["golden_has_build_time_input_path"] and details["golden_launches_external_binary"] and details["source_enables_allocator"]
    rows.append(details)
print(json.dumps(dict(origin=command("remote","get-url","origin"),origin_main=command("rev-parse","origin/main"),shallow=command("rev-parse","--is-shallow-repository"),all_reachable_commits=len(revs),checked_file_path=path,distinct_blobs_in_history=len(blobs),whole_tree_rust_literal_changes=command("log","--all","-m","--format=%H %cs %s","-S",'"now | round"',"--","*.rs").splitlines(),events=hist,affected_revisions=rows), indent=2))
