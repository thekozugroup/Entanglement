"""Compare available read-only Cargo fingerprints for the cached and fresh release."""

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import json
import sys


cached, fresh = (Path(p) for p in sys.argv[1:])
roots = (
    "entangle-cli-1438826a0f3d5a99/bin-entangle.json",
    "entangle-bin-86c910d20e950a7b/bin-entangled.json",
)
settings = ("rustc", "features", "declared_features", "target", "profile", "path", "rustflags", "config", "compile_kind")


def read(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


tokens = defaultdict(list)
for item in cached.glob("*/*.json"):
    stamp = item.with_suffix("")
    try:
        raw = stamp.read_text().strip()
        if len(raw) == 16:
            token = int.from_bytes(bytes.fromhex(raw), "little")
            tokens[token].append(item)
    except (FileNotFoundError, ValueError, UnicodeDecodeError):
        continue

todo = [cached / name for name in roots]
reachable = {}
unresolved = set()
while todo:
    path = todo.pop()
    if path in reachable:
        continue
    fingerprint = read(path)
    assert fingerprint is not None, path
    reachable[path] = fingerprint
    for _, name, _, token in fingerprint["deps"]:
        options = tokens[token]
        if len(options) == 1:
            todo.extend(options)
        else:
            unresolved.add((name, token, len(options)))

overlap, missing, differences, dependency_differences = [], [], [], []
for path, baseline in sorted(reachable.items()):
    suffix = path.relative_to(cached)
    other = read(fresh / suffix)
    if other is None:
        missing.append(str(suffix))
        continue
    overlap.append(str(suffix))
    delta = {key: [baseline[key], other[key]] for key in settings if baseline[key] != other[key]}
    if delta:
        differences.append({"unit": str(suffix), "settings": delta})
    old_deps = {row[1]: row[3] for row in baseline["deps"]}
    new_deps = {row[1]: row[3] for row in other["deps"]}
    changed = [key for key in sorted(set(old_deps) | set(new_deps)) if old_deps.get(key) != new_deps.get(key)]
    if changed:
        dependency_differences.append({"unit": str(suffix), "dependency_names_with_different_fingerprints": changed})

print(json.dumps({
    "collected_utc": datetime.now(timezone.utc).isoformat(),
    "cached_roots_entangle_and_entangled": {
        name: {key: reachable[cached / name][key] for key in settings} for name in roots},
    "cached_reachable_units": len(reachable), "cached_unresolved_dependency_refs": sorted(unresolved),
    "available_in_clean_B_by_same_unit_path": len(overlap),
    "cached_and_clean_B_feature_or_compiler_setting_differences": differences,
    "cached_and_clean_B_dependency_token_differences": dependency_differences,
    "clean_B_matched_root_configs": {name: name in overlap for name in roots},
    "clean_B_missing_at_sampling": missing,
}, indent=2))
