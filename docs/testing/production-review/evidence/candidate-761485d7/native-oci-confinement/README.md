# Fixed rootless OCI confinement probe

The frozen-source probe starts an inert fixture from the cached official Ubuntu 24.04 image pinned by its OCI digest. It verifies the unprivileged UID, empty effective capabilities, enforced seccomp and no-new-privileges, loopback-only networking, read-only root filesystem, and a writable scratch mount that rejects direct execution. It mounts neither the project workspace nor an engine socket. [Runner](probe.sh) · [Receipt](receipt.json)

The rootless Docker engine reported `cgroupDriver=none`. It accepted flags requesting 32 MiB of memory, 16 PIDs and half of one CPU. In the container, the actual limits read back as 32 GiB, unbounded PIDs and four CPUs. The resource enforcement assertion exited 1. The successful suite status records the confinement observations and this measured limit failure. [Raw output](commands.log)

The native tier-5 gate still needs an enforceable resource hierarchy, a signed package-to-image binding, private supervisor IPC and a working authenticated MCP gateway. The released daemon authenticates the signed ELF test package and refuses admission because a native supervisor is unavailable. [Release tier-policy proof](../tier-policy-boundary/receipt.json)
