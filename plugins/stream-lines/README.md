# stream-lines

A **streaming-task plugin** (spec §7.1): it emits its text input one line per
chunk, then reads the task's inbound stream and emits each line of every
inbound chunk, until the submitter finishes its input.

* Implements the `entangle:plugin@0.1.0` **`stream-plugin`** world
  (`crates/entangle-wit/wit/world.wit`): export `start-stream(input)`;
  imports `yield-chunk(0, bytes)` (output) and `next-chunk(1)` (input). It is
  not a `run` plugin: `entangle plugins invoke` cannot call it; use
  `entangle compute stream`.
* **Tier 1**, `runtime = "wasm"`, no capabilities.
* Lines keep their trailing `\n`; a final line without one is a chunk of its
  own; empty input is no chunks.
* Every `yield-chunk` blocks until the submitter has granted credit, so the
  plugin produces no faster than the submitter reads.

| Failure | Result |
|---|---|
| input, or an inbound chunk, is not UTF-8 | `invalid-input` (the stream closes with `plugin-failed` after the lines already sent) |
| `yield-chunk` / `next-chunk` fails (stream cancelled, lost, stalled out, over a cap) | `internal` |

## Build

```bash
cargo build --release --target wasm32-wasip2
cargo test        # the line splitting, natively
```

The built component is committed as
`crates/entangle-scheduler/tests/fixtures/stream-lines.wasm` (rebuild with
`crates/entangle-scheduler/tests/fixtures/build.sh`) and used by the
streaming acceptance tests and `entangle compute stream`'s CLI tests.

## Try it

```bash
entangle --allow-local compute stream <publisher>/stream-lines@0.1.0 \
  --input $'alpha\nbeta\ngamma' --plugin-dir <signed package dir>
```
