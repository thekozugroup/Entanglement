from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch
import hashlib
import json
import platform
import runpy
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path("scripts").resolve()))
import benchmark_raw_batch as current
image = runpy.run_path("scripts/tests/image-dehaze-batch.py")["encode_linear_png"]
baseline = ModuleType("baseline")
prior = subprocess.check_output(["git", "show", "f499e3e:scripts/benchmark_raw_batch.py"], text=True)
exec(compile(prior, "f499e3e:benchmark_raw_batch.py", "exec"), baseline.__dict__)
host = platform.uname()._asdict()
names = {"canon.cr2": 1, "nikon.nef": 2}

def pngs(output, peers, invalid=None):
    output.mkdir(exist_ok=True)
    rows = []
    for index, (name, pixel) in enumerate(names.items()):
        peer = peers[index % len(peers)]
        if invalid == "unauthorized":
            peer = "unexpected"
        output_name = name + ".dehazed.png"
        (output / output_name).write_bytes(image(1, 1, bytes([pixel]) * 6))
        workers = {peer: 2} if invalid == "wrong-tile-count" else {peer: 1}
        rows.append(dict(status="processed", input=name, output=output_name, width=1,
                         height=1, workers=workers, tile_workers=[peer], elapsed_ms=.5))
    rows.append(dict(status="summary", processed=2, resumed=0, failed=0))
    return "\n".join(json.dumps(row) for row in rows).encode()

def dispatch(cmd, **_opts):
    output = Path(cmd[cmd.index("--output-dir") + 1])
    peers = [cmd[i+1] for i, key in enumerate(cmd) if key == "--allow"]
    return subprocess.CompletedProcess(cmd, 0, pngs(output, peers), b"")

with tempfile.TemporaryDirectory(prefix="entangle-b90aac1-review-") as temp:
    root = Path(temp)
    sources = root / "sources"
    sources.mkdir()
    manifest = {}
    for name in names:
        data = name.encode()
        (sources / name).write_bytes(data)
        manifest[name] = hashlib.sha256(data).hexdigest()
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    args = SimpleNamespace(input_dir=sources, scratch=root, manifest=manifest_path,
                           cli=Path(sys.executable), single_home=root, mesh_home=root,
                           worker=["x", "y"], plugin="fixture", jobs=3, trials=3,
                           tile_edge=128, timeout=5.0)
    reports = []
    for module in (baseline, current):
        ticks = [value for duration in (8, 4, 3, 9, 10, 5, 6, 11) for value in (0, duration)]
        status = [{"local_peer_id": "x"}, {"local_peer_id": "coordinator"}, {"plugins": ["fixture"]}, {"plugins": []}]
        report = {}
        with patch.object(module.platform, "uname", return_value=SimpleNamespace(_asdict=lambda: host)), \
                patch.object(module, "cli_json", side_effect=status), \
                patch.object(module.subprocess, "run", side_effect=dispatch), \
                patch.object(module.time, "perf_counter", side_effect=ticks):
            module.benchmark(args, report)
        reports.append(report)
    assert reports[0] == reports[1]
    assert reports[1]["median_wall_s"] == {"single": 10, "mesh": 5}
    assert reports[1]["median_wall_speedup"] == 2
    assert [trial["route"] for trial in reports[1]["trials"]] == ["single","mesh","mesh","single","single","mesh","mesh","single"]
    print("Successful synthetic controls match the entire f499e3e report with fixed clock, route order, medians and speedup.")
    bad = root / "invalid"
    for kind in ("unauthorized", "wrong-tile-count"):
        raw = pngs(bad, ["x", "y"], kind)
        try:
            current.verify_run(raw, bad, names, {"x", "y"}, 128, None)
        except ValueError as error:
            assert type(error) is ValueError and "invalid placement receipt" in str(error)
        else:
            raise AssertionError(f"{kind} must be rejected")
    for invalid in (["x", "x"], ["x", "coordinator"]):
        args.worker = invalid
        with patch.object(current, "cli_json", side_effect=[{"local_peer_id": "x"}, {"local_peer_id": "coordinator"}]):
            try:
                current.benchmark(args, {})
            except ValueError as error:
                assert "provide distinct remote mesh workers" in str(error)
            else:
                raise AssertionError(f"{invalid} must be rejected")
    print("Unauthorized output workers, inconsistent tile counts, duplicate workers and coordinator workers remain rejected.")
