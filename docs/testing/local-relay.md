# Local Iroh relay test

This check exchanges a framed Entanglement request and response between two disposable Ed25519 identities through an upstream Iroh 1.5 relay on loopback. It verifies the authenticated peer ID on each end and inspects the selected QUIC path after exchanging the payload. Both endpoints have direct IP transports and gateway probing disabled.

Install the upstream test server once. This step fetches build dependencies from the Cargo registry.

```sh
cargo install --locked --version '=1.5.0' --features server iroh-relay
```

In a terminal, start the relay bound to a local TCP port.

```sh
relay_config=$(mktemp)
trap 'rm -f "$relay_config"' EXIT
cat >"$relay_config" <<'TOML'
http_bind_addr = "127.0.0.1:3340"
enable_relay = true
enable_quic_addr_discovery = false
enable_metrics = false
TOML
iroh-relay --config-path "$relay_config"
```

In another terminal, run the test from the source checkout. If port 3340 is in use, choose another available port in both commands. Stop the relay with Ctrl-C after the test.

```sh
ENTANGLE_TEST_RELAY_PORT=3340 cargo test --locked -p entangle-mesh-iroh --lib -- --ignored --exact transport::relay_test::authenticated_request_crosses_local_relay
```

The relay and both endpoints communicate over loopback. The test has a 30-second deadline. To verify network isolation, build the test executable with `cargo test --locked -p entangle-mesh-iroh --lib --no-run`, then run it and the relay in the same container with `--network=none`. The container needs only its loopback interface. Public relay access and NAT traversal between networks require separate checks.
