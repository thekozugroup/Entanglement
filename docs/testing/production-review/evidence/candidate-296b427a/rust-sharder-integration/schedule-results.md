# Two-worker Rust sharder scheduling

On Linux on November 27, 2026, the integrated sharder completed an eight-case signed suite in a median of 698 ms over four observations. The previous sharder took a median of 1,383 ms on the same running candidate workers and signed workload. That is a 49.5% reduction in suite time for this fixture. The suite times include discovery. [Timing receipt](schedule-first.json)

| Sharder | All four suite times (ms) | Maximum simultaneous guests on one peer | Time with two guests on one worker and the other idle (ms) |
|---|---|---:|---|
| Previous a837e6da | 1394, 1394, 1371, 1372 | 2 each run | 1331, 1355, 1305, 1317 |
| Integrated 296b427a | 689, 707, 1134, 683 | 1 each run | 0, 0, 0, 0 |

Each run executed eight distinct seeded arithmetic checks with no retries. The 64 accepted results record the chosen peer and guest entry/exit times. In all four integrated observations, the second worker started queued case c_long while the first worker was still executing a_long. The deterministic event-barrier test separately holds the first worker until the second has taken all three queued short cases. [Timing receipt](schedule-first.json) · [Barrier test log](../qa-runner-python.log)

The previous and integrated sharder scripts ran in ABBA/BAAB order. Both used the same frozen optimized Linux executables and two authenticated loopback workers pinned to different logical CPUs on one host. Raw per-CPU counters include concurrent system activity and the benchmark itself. This deliberately mixed-duration suite provides no estimate of the all-crate production speedup or naturally occurring flake rate. [CPU counters](schedule-cpu.json) · [Reproduction](reproduction.md)
