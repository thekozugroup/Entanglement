# JUnit interoperability check

The standalone converter consumes the JSON emitted by the distributed Rust test runner. Its implementation uses only the Python standard library. The independent reader here uses `junitparser` 5.0.3 (PyPI wheel SHA-256 `553535b8cd1672a9c8bd2c7326ae1ae69279267fbc562106b5aa44d3c5f769af`) and the standard library's XML parser. It compares case names, JUnit dispositions, elapsed units, both package digests, and the full ordered attempt records including output bytes representable by the runner's JSON strings.

`large-capture.py` creates a disposable coordinator and two paired workers, confirms the binary digests from the candidate archive manifest and signs the compiled `captures.rs` test module. Its 48 cases each write 2,048 lines containing markup, Unicode and an XML 1.0 control character. This is a generated stress workload. The release and selector checks supply separate reports from ordinary tests and upstream workspaces.

From the repository root, build the stress fixture with the pinned Rust toolchain. Substitute the directory containing the candidate binaries and the path of its archive manifest when reproducing the run.

```sh
proof=docs/testing/production-review/evidence/candidate-296b427a
rustc --target wasm32-wasip2 --test "$proof/junit/captures.rs" -o /tmp/entangle-captures.wasm
python3 "$proof/junit/large-capture.py" --repo . --bin-dir "$BIN_DIR" \
  --manifest "$proof/linux-archive.json" --wasm /tmp/entangle-captures.wasm \
  --output /tmp/entangle-captures.json.gz
python3 -m venv /tmp/entangle-junit-reader
/tmp/entangle-junit-reader/bin/pip install junitparser==5.0.3
/tmp/entangle-junit-reader/bin/python "$proof/junit/verify.py" --script scripts/rust-test-junit.py \
  --result /tmp/entangle-junit-comparison.json /tmp/entangle-captures.json.gz \
  "$proof/distributed-rust-release.json"
```
