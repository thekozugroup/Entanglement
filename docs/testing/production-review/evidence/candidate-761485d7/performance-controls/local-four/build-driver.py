"""Compile a local-only copy of the frozen integration harness using its Cargo dependency artifacts."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("root", type=Path)
parser.add_argument("cargo_built_driver", type=Path)
parser.add_argument("scratch", type=Path)
args = parser.parse_args()
root, original, scratch = (p.resolve() for p in (args.root, args.cargo_built_driver, args.scratch))
scratch.mkdir(parents=True, exist_ok=True)
suite = root / "crates/entangle-bin/tests"
main = (suite / "daemon_compute.rs").read_text().split("async fn exercise(")[0]
main = main.replace('#[path = "common/inference.rs"]\nmod inference;', "")
(scratch / "daemon_compute.rs").write_text(main)
shutil.copytree(suite / "common", scratch / "common", dirs_exist_ok=True)
bench = scratch / "common/dispatch_benchmark.rs"
code = bench.read_text()
begin = code.index("        for (route, home)")
end = code.index("\n    })", begin)
code = code[:begin] + """
        let socket = cluster.worker.home.join(".entangle/sock");
        sample(&socket, &cluster.plugin_id, &peer, 1_024, 4).await;
        let worker_pid = cluster.executor.child.id();
        let cgroup = "/sys/fs/cgroup/cpu.stat";
        let worker_stat = format!("/proc/{worker_pid}/stat");
        let read = |p: &str| std::fs::read_to_string(p).unwrap();
        let count = || vec![read("/proc/self/stat"), read(&worker_stat), read(cgroup)];
        let before = count();
        let samples = sample(&socket, &cluster.plugin_id, &peer, 4_096, 4).await;
        let after = count();
        let latency_ns: Vec<u64> = samples.latency.iter().map(|d|d.as_nanos() as u64).collect();
        let row = serde_json::json!({
            "worker_pid": worker_pid, "client_pid": std::process::id(),
            "client_affinity": read("/proc/self/status").lines().find(|l|l.starts_with("Cpus_allowed_list:")).unwrap(),
            "worker_affinity": read(&format!("/proc/{worker_pid}/status")).lines().find(|l|l.starts_with("Cpus_allowed_list:")).unwrap(),
            "latency_ns": latency_ns, "wall_ns": samples.wall.as_nanos() as u64,
            "before_client_worker_cgroup": before, "after_client_worker_cgroup": after,
        });
        std::fs::write(std::env::var_os("ENTANGLE_LOCAL_FOUR_DATA").unwrap(), row.to_string()).unwrap();
        samples.report("local", 4);
""" + code[end:]
bench.write_text(code)
target = original.parent.parent
fingerprints = target / ".fingerprint"
key = original.name.split("-")[-1]
spec = json.loads((fingerprints / f"entangle-bin-{key}/test-integration-test-daemon_compute.json").read_bytes())
cmd = ["rustc","--edition=2021","--test",str(scratch/"daemon_compute.rs"),"-C","debuginfo=0",
       "-L",f"dependency={original.parent}","-o",str(scratch / "local-four-driver")]
required = set("tokio hex entangle_rpc entangle_types entangle_peers entangle_signing serde_json blake3 tempfile toml toml_edit".split())
for _, name, _, stamp in spec["deps"]:
    if name not in required:
        continue
    matches = [p for p in fingerprints.glob("*/lib-"+name) if p.read_text().strip()==stamp.to_bytes(8,"little").hex()]
    if len(matches)!=1:
        raise ValueError((name,stamp,matches))
    artifact = original.parent / f"lib{name}-{matches[0].parent.name.split('-')[-1]}.rlib"
    cmd.extend(["--extern", f"{name}={artifact.resolve(strict=True)}"])
env = {**os.environ, "CARGO_MANIFEST_DIR":str(root/"crates/entangle-bin"), "CARGO_BIN_EXE_entangled":str(root/"target/release/entangled")}
subprocess.run(cmd, cwd=root, env=env, check=True)
