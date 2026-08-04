# Docker

This directory contains the `entangled` daemon container build. See spec §9.1 for
the rationale: Docker is the recommended Linux server install path.

## Build the image

Run from the **repository root** (the build context must include `crates/` and `Cargo.lock`):

```bash
docker build -f docker/Dockerfile -t entangledev/entangle .
```

## Run the daemon

```bash
docker run -d \
  --name entangled \
  -v ent:/var/lib/entangle \
  entangledev/entangle
```

The daemon listens on a Unix-domain socket inside the container at
`/var/lib/entangle/entangled.sock`. In Phase 1 there are no exposed TCP ports.

## docker-compose (local dev)

```bash
docker compose -f docker/docker-compose.yml up --build
```

## mDNS / network_mode: host

`docker-compose.yml` sets `network_mode: host` so the `entangled` daemon can
participate in `mesh.local` mDNS discovery on the LAN.

**Linux hosts**: this works as intended — the daemon binds directly to the host
network interface and mDNS multicast packets reach the physical LAN.

**Mac + Docker Desktop**: `network_mode: host` does NOT bridge to the macOS
network stack. Docker Desktop runs inside a lightweight Linux VM, so "host" means
the VM's network, not your Mac's. mDNS discovery will not reach your LAN.
Workaround options:
- Use a Linux VM or bare-metal Linux for testing mDNS-dependent scenarios.
- Or run `entangled` natively (outside Docker) on macOS for local development.

## Health check

The container ships a `HEALTHCHECK` (and `docker-compose.yml` a matching
`healthcheck`) that runs `entangled status`. Unlike `entangle doctor` — which
only *warns* on daemon unreachability and exits 0 — `entangled status` connects
to the Unix socket and round-trips a `version` RPC, so a hung or dead daemon is
reported as **unhealthy**.

## Running as a systemd service (bare metal)

For a non-Docker Linux install, use the hardened unit at
[`packaging/entangled.service`](../packaging/entangled.service). It sets
`User=entangle`, `Environment=HOME=/var/lib/entangle` (required — the daemon
resolves `$HOME/.entangle`; there is no config-dir flag), `StateDirectory=entangle`,
`Restart=on-failure`, and a full sandbox (`ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, dropped capabilities, …). Install steps are in the unit's header
comment.

## Phase-1 caveats

- No mesh ports are exposed, and the daemon listens **only** on a Unix-domain
  socket (`$HOME/.entangle/sock`) — there is no TCP listener, so the image no
  longer `EXPOSE`s a port. Phase 2 will add Iroh/mDNS transport ports.
- Single-binary mode only: `entangle` CLI is baked in but must exec inside the container.
- The daemon runs as a non-root `entangle` system user; the data directory is `chmod 700`.

## Verifying without building

```bash
docker --version   # confirm Docker is installed
# Full build is exercised by CI (too slow for local iter verification).
```
