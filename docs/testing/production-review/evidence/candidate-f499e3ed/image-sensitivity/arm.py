"""Run the unchanged signed batch/oracles with the registered two ordered routes."""
import argparse
import json
from pathlib import Path
import sys

root=Path(__file__).resolve().parents[6]
sys.path.insert(0,str(root/"scripts"))
import benchmark_image_batch as original

parser=argparse.ArgumentParser()
parser.add_argument("--bin-dir",type=Path,required=True)
parser.add_argument("--results",type=Path,required=True)
args=parser.parse_args()
args.image=Path("/usr/share/matplotlib/mpl-data/sample_data/grace_hopper.jpg")
args.wasm=root/"target/catalog-smoke/wasm32-wasip2/release/entangle_image_resize.wasm"
args.route=None
args.worker_cpu_affinity=False
original.ROUTES=("local","one_remote")
r=original.run(args)
args.results.write_text(json.dumps(r,indent=2)+"\n")
