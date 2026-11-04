# native-echo

A minimal **tier-5 native** Entanglement plugin: an ordinary executable that
the daemon runs inside an OS sandbox and talks to over length-prefixed frames
on stdin/stdout. It echoes its input and counts requests in its own storage
directory (`$ENTANGLE_DATA_DIR/requests`).

```sh
entangle init                         # once — creates your publisher key
entangle plugins build examples/native-echo
entangle keyring add <YOUR_PUBLIC_KEY_HEX> --name self
entangle plugins load examples/native-echo/dist
entangle plugins invoke <FINGERPRINT>/native-echo@0.1.0 --input 'hello'
```

What the sandbox allows (derived from `[capabilities]` in `entangle.toml`):
read+exec of the plugin binary and system libraries, read of the package
directory, read+write of its own data directory. No network, no other files,
no signals to processes outside the sandbox. See `docs/operations.md`
("Native plugins and the OS sandbox").
