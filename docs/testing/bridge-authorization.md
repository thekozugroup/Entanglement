# Receiver bridge authorization

The receiving endpoint verifies two signed `mesh.relay` grants, one from the expected origin endpoint and one from its own signing key. Each authority must name the bridge peer authenticated by QUIC. Each chain must also carry a destination pin for the local receiver, a rate of at most 1 MiB/s, a lifetime budget of at most 1 GiB, a future expiry within one hour and a true bridge marker. Restriction facts can use the architecture names or the earlier Entanglement names. Every applicable signed Datalog check is evaluated, including receiver-supplied UTC time.

Use `entangle_signing::verify_bridge` to verify one delegation. It accepts the serialized Biscuit, trusted endpoint public key, authenticated bridge peer, desired destination peer and verifier time in Unix seconds. Its typed errors have these codes.

| Condition | RelayAuthorizationError variant | Code |
|---|---|---|
| Missing or excessive rate | Rate | E0118 |
| Missing or wrong destination | Destination | E0119 |
| Missing, elapsed or excessive expiry | Expiry | E0120 |
| Missing marker | Marker | E0121 |
| Missing or excessive lifetime bytes | LifetimeBytes | E0122 |

Existing plugin capability operations also emit E0120 for an undeclared grant and E0121 for an unloaded plugin. Include the operation and typed error when interpreting these codes. The general `entangle_biscuits::verify_bridge_cap` interface retains its original error variants and accepts application-specific capabilities.

## Frame delivery

Provision one private durable ledger per receiving node with `BridgeReceiver::initialize`. Open that file on every process and after restart with `BridgeReceiver::open`, supplying the destination peer and its own public signing key. A missing or unreadable ledger fails closed. Provision the ledger's directory on a local filesystem that supports exclusive file locks and atomic rename. Keep the ledger and lock file together throughout the lifetime of outstanding grants.

An application enabling a particular transport pair can pass each inbound QUIC request to `entangle_mesh_iroh::bridge::deliver_bridge_frame`, along with both grants, the trusted origin key and its local destination writer. The adapter obtains the bridge identity from QUIC. The receiver checks both grants, serializes shared accounting across concurrent processes and durably reserves both budgets before writing payload bytes. A write failure conservatively consumes the reservation. Across 100 ms accounting buckets it retains enough history to cover every byte in the preceding second. At most 4,096 live budgets are retained. Further attenuation of a verified cap shares the original signed budget ID until the earliest complete delegation expires.

## Forward a payload through three paired daemons

Pair the origin, bridge and destination with one another. The origin must have a scheduler route to the bridge. The bridge must have a route to the destination. Configure exactly one of the bridge's two links as a Tailscale route with a `[[scheduler.tailnet_peers]]` stable Tailscale device ID, paired Entanglement public key and port. Configure the other as a direct Iroh scheduler route.

On both the bridge and destination, create a ledger once in an existing private directory with `entangle mesh bridge init /absolute/private/relay.toml`. Add the following on the bridge, alongside its scheduler routes.

```toml
[mesh]
transports = ["iroh", "tailscale"]

[mesh.bridge]
enabled = true
pairs = ["iroh<->tailscale"]
ledger = "/absolute/private/relay.toml"

[scheduler]
bind = "0.0.0.0:7443"
relay = false
```

On the destination add `[mesh.bridge]` with `receive = true` and its own absolute `ledger` path. Start the daemons with their updated configuration. Forwarding validates the actual selected direct sockets and running Tailscale status against the configured device identity. Each hop checks paired-peer trust. The bridge and receiver verify and meter both endpoint grants independently, and log peer identities and byte count.

Run the grant command on each endpoint using its own identity. Transfer the destination grant to the origin using an approved channel. On the origin, use both signed grants and the intended payload file.

```sh
entangle mesh bridge grant --via "$BRIDGE" --destination "$DESTINATION" --rate 65536 --total 1048576 --ttl 300 --output endpoint.bsk
entangle mesh bridge send --via "$BRIDGE" --destination "$DESTINATION" --origin-grant origin.bsk --destination-grant destination.bsk --input message.bin
```

On the destination, `entangle mesh bridge read > received.bin` retrieves one verified payload and reports origin and bridge IDs on stderr. Each signed frame carries at most 64 KiB. The in-memory inbox has 16 slots and loses unread entries on restart. Budget charges survive restart and delivery failures. A repeated submission incurs another charge. Plugin compute requests continue to use normal scheduler routes. The bridge inbox delivers inert application bytes.

The private acceptance harness adds an ordinary Iroh origin to two kernel WireGuard devices and tests all three daemon roles. It requires Docker, the pinned local test images, kernel TUN, and the test prerequisites in `scripts/tests/private-tailnet.py`.

```sh
cargo test --locked -p entangle-signing --test bridge_attenuation --test total_bytes_cap
cargo test --locked -p entangle-mesh-iroh --test loopback signed_bridge_frame
python3 scripts/tests/private-tailnet.py --bridge --bin-dir target/release
```
