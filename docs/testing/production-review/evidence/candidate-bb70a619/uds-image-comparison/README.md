# Local Unix socket image-dispatch comparison

The 27 November 2026 run compared the local Linux x86-64 release archives for candidate `bb70a619` and engineering comparator `42bb9a33`. It used six alternating pairs and one fresh, separately warmed daemon for each arm. Both versions loaded the same signed image-dehaze Wasm component and dispatched to the daemon’s own explicitly allowed identity. Each timed call sent the same deterministic 6,294,518-byte 1024 × 1024 high-entropy RGB16 PNG through the ordinary `entangle compute dispatch` command, then wrote the image to a local file. CLI wall time starts before process creation and ends at child exit. Linux `wait4` reports maximum CLI RSS, and `/proc/<pid>/status` reports daemon high-water RSS after three small warmup calls and after the timed request. The host had a four-core cgroup quota and a 32 GiB memory limit. No compiler or linker process appeared at the sampled arm boundaries. [Measurement plan](plan.json) · [Runner](compare.py)

| Metric | Comparator median | Candidate median | Median paired change |
|---|---:|---:|---:|
| CLI wall time | 1,482.52 ms | 1,030.47 ms | −30.6% |
| CLI peak RSS | 261,754 KiB | 43,482 KiB | −83.4% |
| Daemon peak RSS after measured request | 262,282 KiB | 110,444 KiB | −58.0% |
| Daemon peak RSS after warmup | 36,536 KiB | 35,482 KiB | −2.6% |

All 12 timed results matched byte-for-byte, with SHA-256 `9603f373ea8ae7af287f8956c9a1d59c0c5548a33cdb742a6470d25dcf07f744`. The 36 warmup results also matched within that input. The driver checked the selected peer, PNG profile, chunk CRCs and decompressed length independently on each call. The paired wall-time ratio ranged from 0.537 to 0.910. This measures a single large localhost request on one Linux host. The separate camera batch measures RAW ingest and multi-worker placement. [Validated 12-arm results](results.json) · [Run transcript](results.log)

The initial run completed all 12 arms and validated the responses. Its report formatter then raised an exception because Python’s `os.uname()` lacks `_asdict`. The retained transcript contains the original wall time and RSS values. The corrected run repeated the complete preregistered order without changing the input, guest, binaries, or measurements. The table uses the repeated run, which retained per-call hashes and host metadata. GNU `time` was unavailable, so the plan was amended to use `wait4` before either measurement began. [Initial series and formatter error](initial-series.log) · [Original plan](plan-original.json)

## Request parser allocation diagnostic

A separate parser probe measured peak live Rust allocation requests above its prebuilt JSON frame. For 8,388,608 input bytes represented by a 33,554,648-byte JSON frame, parsing through an intermediate `serde_json::Value` needed 276,825,402 additional bytes. Borrowing the raw parameters and deserializing directly into the typed `ComputeDispatchParams` needed 8,388,634 bytes. Both paths returned the same 8 MiB of input. The old daemon goes through the comparator’s `Req.params: Value` and subsequent typed conversion. The final daemon uses a borrowed `RawValue` and the same direct typed conversion shown in the probe. The isolated run predates the final freeze. The probe excludes the existing input frame from its counter and reports requested allocator bytes. The integrated measurement above reports actual process RSS. [Output and code provenance](allocator-probe/receipt.json) · [Probe source](allocator-probe/src/main.rs) · [Captured output](allocator-probe/run.log)

Copy the probe directory outside the Entanglement workspace and run it using `cargo run --release --locked`. It exercises successful request decoding only.
