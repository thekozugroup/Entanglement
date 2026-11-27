# Signed libtest worker identity

The first run passed on Linux on November 27, 2026. The production sharder made 58 observed one-shot exchanges across 14 phases against the verified local release archive. Ten phases returned a test report. Four stopped during discovery. An additional invocation against the c19ef758 coordinator identified the missing dispatch-error protocol and requested an upgrade. [Live report](identity-first.json) · [Archive receipt](../linux-archive.json)

| Operator action | Observed result |
|---|---|
| Load identical signed suites on two workers | The selected arithmetic test passed. A separate ordinary first-attempt assertion followed by success on the second peer was classified as flaky. |
| Give the second worker a different module or a different signed manifest under the same plugin ID | Both runs stopped during discovery, before sending any exact test request. |
| Change the selected worker's module after discovery | The first exact request returned the typed suite-identity-mismatch error. The sharder stopped after that request. |
| Change the second worker's module after an actual failed assertion on the first worker | The retry returned suite-identity-mismatch. The report preserved the first test failure and classified the overall case as an error. |
| Replace the module while its selected test was running | The admitted original component finished in 1,351.64 ms. Unload acknowledged 11.07 ms after its guest exit. The worker rejected an original-suite pin after replacement and accepted a new listing and exact test against the replacement. |
| Unload the signed suite or revoke the submitter on the selected worker before its exact attempt | The worker returned plugin-not-loaded or not-authorized respectively. Each report ended after the first selected attempt. |
| Remove the publisher key on a worker with a loaded suite | The loaded suite completed. After explicit unload, the worker refused reloading it with ENTANGLE-E0101. Restoring the publisher key permitted loading and running it. |
| Include a c19ef758 worker | With the older worker first, the sharder requested a worker upgrade. With the older worker second, it stopped at the pinned listing with the remote diagnostic and a suite-pinning compatibility hint. |

All ten test reports passed through the production JUnit converter with matching signed suite properties, ordered attempt histories and error counts. The fixture uses authenticated loopback, synchronous Linux clocks and deliberately generated failure cases. It provides no estimates of naturally occurring flakes or physical-network performance. [JUnit corroboration](identity-junit.json) · [Reproduction](reproduction.md)
