# Two-host Tailscale compute acceptance

This check submits a JSON Pointer job on a coordinator and confirms that a second device executes it. It compares the authenticated executor ID to the worker daemon's own ID and checks the returned value against a fresh random input. Both daemons must report Tailscale as their only active mesh transport.

## Prepare the two hosts

Use two approved Linux or macOS devices with distinct Entanglement identities on the same tailnet. Each needs a working Tailscale interface with an assigned node address, a running local Tailscale daemon, the `tailscale` CLI on the test user's PATH, and Python 3.8 or later. Run the check as the user who owns each Entanglement daemon's default `~/.entangle/sock`.

1. Install the same Entanglement revision on both devices. Verify the devices' fingerprints and mutually pair their Entanglement identities. Configure Tailscale-only transport on both and a coordinator-to-worker mapping using the worker's stable Tailscale ID, Entanglement public key, and scheduler UDP port. The coordinator must be able to reach that port under the existing tailnet and host firewall policies. Restart both Entanglement daemons after configuration. [Worker configuration](../operations.md#running-a-worker-on-a-tailnet)
2. Load exactly one trusted, signed `json-pointer@0.1.0` package on the worker. The worker's catalog installation command is `entangle plugins install json-pointer`. Building it there requires the Rust `wasm32-wasip2` target and the Entanglement catalog. A previously signed package can also be loaded with `entangle plugins load <package-directory>` after its publisher has been trusted. Reserve this plugin for the designated worker during the check, including on any additional workers visible to the coordinator.
3. Use an existing authenticated SSH connection to the worker, or transfer the public snapshot between the two terminals. The snapshot contains the worker's two public identifiers and its loaded plugin ID. Tailscale credentials and Entanglement private keys stay on their respective hosts.

## Run from the coordinator

From the repository root on the coordinator, replace `WORKER_SSH_HOST` with the approved worker's SSH alias. The remote Python process reads the same script from standard input, so the worker only needs the running services and Python at this point.

```bash
set -o pipefail
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 \
    WORKER_SSH_HOST python3 - worker < scripts/tests/tailnet-compute.py |
  python3 scripts/tests/tailnet-compute.py verify
```

For separate terminals, run `python3 scripts/tests/tailnet-compute.py worker` on the worker. Pipe its single JSON line into `python3 scripts/tests/tailnet-compute.py verify` on the coordinator. Both commands exit nonzero on failure.

The coordinator checks that it sees the worker's stable node ID online, that the two daemons have distinct identities, and that the job's plugin is absent locally. It waits up to 60 seconds for the worker inventory to become available, requests 0.01 CPU cores, and lets the scheduler choose the executor. A successful run prints a JSON receipt with `transport`, `chosen_peer`, `plugin_id`, and `verified_output`. Save that receipt with the tested build and host OS versions. The check reads existing configuration and submits one job. Any service setup or pairing occurs before the check.

## Run on a private WireGuard network

The Linux Docker acceptance harness starts a private Headscale control plane and two Tailscale daemons on an internal bridge. Each node receives a kernel `tailscale0` interface in its own container network namespace. The application containers use the real Tailscale CLI and local daemon socket. The harness checks the direct WireGuard path, runs the signed remote compute check above and verifies that worker-side revocation denies another job. It creates disposable credentials and removes its containers and network on exit.

Use Python 3.11+, OpenSSL, a local Linux Docker engine with access to `/dev/net/tun`, and Linux Entanglement binaries compatible with the test image. Prepare the binaries, Wasm artifact and images before starting the isolated test.

```sh
cargo build --locked --release -p entangle-bin -p entangle-cli
cargo build --locked --release --target wasm32-wasip2 --manifest-path plugins/json-pointer/Cargo.toml
docker pull headscale/headscale:0.27.1
docker pull tailscale/tailscale:v1.92.5
docker pull python:3.12-slim-trixie
python3 scripts/tests/private-tailnet.py
```

Use `--bin-dir` and `--wasm` to select other built artifacts. The receipt includes the authenticated executor, generated plugin output, observed WireGuard path and revocation result.
