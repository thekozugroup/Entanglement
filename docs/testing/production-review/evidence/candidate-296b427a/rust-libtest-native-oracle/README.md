# Native libtest selection and signed WASI execution

[results.json](results.json) records the source fingerprint before and after the run, the verified Linux release archive and extracted executable hashes, build commands for the three fixtures, package digests, worker identities, and each selected case's command, status, stdout and stderr. The coordinator and workers use isolated state directories. The two current workers and the compatibility daemons communicate over authenticated loopback QUIC on one Linux host.

The rows in `selection` compare genuine native libtest exits and named dispositions against the operator sharder, including repeated inclusion filters, repeated skips, exact filters and skips, and both ignored modes. The test sources for this comparison and for the diagnostic cases are [selectors.rs](selectors.rs) and [diagnostics.rs](diagnostics.rs). The diagnostics fixture uses a real failed first attempt to exercise retry attribution. The separate [deadline.rs](deadline.rs) fixture exercises a worker execution deadline. The fixture's local infinite loop is interrupted by the daemon's configured execution timeout.

The diagnostic rows also cover ordinary application text, captured summary-like text, a normal assertion failure, a Rust `Result` error, a clean process exit before libtest completes its footer, a legitimate empty selection, missing package discovery, post-deadline worker recovery, and a typed wrong-manifest-digest rejection. The named expected-panic case completes natively and is ignored by Rust's panic-abort WASI harness. The older-client protocol control omits the optional pin and sends an ordinary exact request to the current coordinator and worker.

Run the [driver](verify.py) with Python 3.11 or later, Rust 1.91.1 with the `wasm32-wasip2` standard library, `openssl`, and `b3sum`. Supply the checkout that matches the candidate release manifest, its local Linux release archive, and the historical c19ef758 Linux archive and manifest used for compatibility controls. The output directory must be new. The driver compiles the fixture sources alongside this file.

```sh
python3 -B verify.py \
  --repo "$REPO" \
  --archive "$CANDIDATE_ARCHIVE" \
  --verification "$CANDIDATE_VERIFICATION" \
  --legacy-archive "$C19_ARCHIVE" \
  --legacy-verification "$C19_VERIFICATION" \
  --rustc "$RUSTC" \
  --b3sum "$(command -v b3sum)" \
  --out "$NEW_RUN_DIRECTORY"
```
