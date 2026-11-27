# Performance comparison for the Tailscale recovery candidate

Recorded on 2026-11-27 before freezing or timing the successor. The engineering comparator is commit `864ae27bf3fd08e9d9c62abd4f43ff7bfd4c68c2`, the immediately preceding candidate with independently reviewed Linux measurements. Its retained daemon must match SHA-256 `5e11e7af5eae74c8cbec3f140e7322b98b9f5910cdb8cd269b53f9ae6d2b73f9`. Owner approval of this comparator is a separate condition for the production baseline gate.

Use the same Linux VM, CPU quota, binaries from the locked release profile, benchmark driver, CLI, image corpus and package bytes for both sides. Only the daemon under test changes. Record binary identities, CPU activity and elapsed time. Finish compilation, platform builds and model inference before timing.

- For signed greetings, use independent fresh clusters in baseline/candidate, candidate/baseline, baseline/candidate order. At one and four concurrent clients, exercise both Unix-socket local dispatch and authenticated remote dispatch. Warm each case with 16 requests and measure 1,024. Check the returned peer and greeting for every request.
- For image processing, use the same 24 encoded images and four clients for local, one-remote and three-remote placements. Keep three rotated topology trials per version, with the candidate build first. Independently verify the image bytes and executor placement and compare the corpus output digest between both builds.
- Apply the previously used engineering limits to each of the seven configurations. Compare medians of the three trial p95 latencies and of the three trial throughputs. Each candidate p95 must be at most 105% of its comparator, and each candidate throughput must be at least 95% of its comparator. Publish all trial values and results, including misses.

On a miss, retain the first run and investigate host contention, a difference in binary execution or a relevant code change. Any follow-up experiment must report its reason and raw values alongside the original. Real tailnet service-recovery timing is reported separately in the outage acceptance test.
