# Supply-chain audit (cargo-vet)

This directory holds `cargo-vet` audits per spec §10.1. To populate:

```bash
cargo install cargo-vet
cargo vet init
cargo vet
# Manually review and run `cargo vet certify <crate>` for trusted deps.
```

Phase 1 status: not yet populated. The release workflow will gate on `cargo vet` passing once we have an initial audit set.
