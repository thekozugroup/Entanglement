# First successor inference attempt

The first invocation reached the model listing and then received HTTP 503 Service Unavailable from the local inference backend during a mesh stream read. The previous test driver used the model listing as its readiness signal. This attempt produced no completed six-request receipt and contributes no successful inference or timing measurements.

The repeat waits for the llama.cpp health endpoint to return HTTP 200 with status `ok` and for the requested model ID to be listed. It retains the model-server log. Once a measured request starts, the driver propagates any backend error to the test without retrying the request.

The second attempt reached healthy inference on the completions endpoint, then opened a fresh coordinator for chat before its first worker inventory was available. The scheduler rejected the open with `invalid streaming task: no live workers in pool`. The test created no chat stream. The retained server log records the completed HTTP requests for this attempt. [Second-attempt server log](second-attempt.server.log)

For the first request from each newly initialized coordinator, the test now waits at most 45 seconds for this specific pre-dispatch error to clear. The receipt records time spent waiting for discovery and the number of refused opens. It measures first-chunk latency and throughput from the accepted open. Errors after peer selection fail the test immediately.
