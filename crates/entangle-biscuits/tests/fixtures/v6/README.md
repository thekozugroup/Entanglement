# Biscuit 6 wire fixtures

These public test vectors were generated with upstream `biscuit-auth 6.0.0`, once with an Ed25519 root key and once with a P-256 root key. Each authority block grants `compute.cpu` to the Entanglement peer derived from 32 bytes of value 3, with Unix expiry 1000. An appended block checks for `capability("compute.cpu")` in the allowed token and `capability("compute.gpu")` in the denied token. Each PEM file contains the issuer's public key. Evaluation time 2 precedes expiry and evaluation time 1000 is the expiry boundary.

The candidate regression reads the original serialized bytes and verifies the signatures and authorization decisions with its own Biscuit dependency. Run it with `cargo test --locked -p entangle-biscuits --test roundtrip reads_v6_ed25519_and_p256_tokens_and_enforces_their_checks`.
