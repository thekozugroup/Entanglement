#!/bin/bash
# Exercise the current local rootless OCI engine using only a pinned inert fixture.
set -euo pipefail

image=ubuntu@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b
flags=(--rm --pull=never --network none --read-only --cap-drop ALL --user 65534:65534
    --security-opt no-new-privileges --ipc none --tmpfs /scratch:rw,nodev,nosuid,noexec,mode=1777,size=8m)

date -u +%FT%TZ
uname -srm
docker info --format '{{json .SecurityOptions}} cgroupDriver={{.CgroupDriver}} cgroupVersion={{.CgroupVersion}}'
docker image inspect "$image" --format '{{.Os}}/{{.Architecture}} ID={{.Id}} RepoDigests={{join .RepoDigests ","}}'

set +e
set -x
timeout 30s docker run "${flags[@]}" --memory 32m --pids-limit 16 --cpus 0.5 "$image" /bin/sh -euc '
    cat /proc/self/cgroup
    for setting in memory.max pids.max cpu.max; do
        printf "%s = " "$setting"
        cat "/sys/fs/cgroup/$setting"
    done
    test "$(cat /sys/fs/cgroup/memory.max)" = 33554432
    test "$(cat /sys/fs/cgroup/pids.max)" = 16
    test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
'
limits_exit=$?
set +x
set -e
printf 'Requested cgroup limits enforcement probe exit=%s\n' "$limits_exit"

set -x
timeout 30s docker run "${flags[@]}" "$image" /bin/sh -euc '
    id
    cat /etc/os-release
    test "$(id -u)" = 65534
    awk "/^(CapEff|NoNewPrivs|Seccomp):/" /proc/self/status
    grep -Eq "^CapEff:[[:space:]]+0+$" /proc/self/status
    grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status
    grep -Eq "^Seccomp:[[:space:]]+2$" /proc/self/status
    test "$(ls -1 /sys/class/net)" = lo
    cat /proc/net/route
    test "$(wc -l </proc/net/route)" -eq 1
    test ! -S /run/docker.sock && test ! -S /var/run/docker.sock
    test ! -d /workspace && test ! -d /root/.ssh
    if (umask 077; printf unexpected > /tmp/entangle-readonly-test); then
        echo "Container root filesystem unexpectedly allowed a /tmp write"
        exit 1
    fi
    printf "scratch-write-only-fixture\n" > /scratch/result
    test "$(cat /scratch/result)" = scratch-write-only-fixture
    printf "#!/bin/sh\\nexit 0\\n" > /scratch/noexec-fixture
    chmod 700 /scratch/noexec-fixture
    if /scratch/noexec-fixture; then
        echo "Scratch unexpectedly allowed direct execution"
        exit 1
    fi
    echo "Confirmed offline interface, missing host workspace/socket, read-only rootfs and noexec scratch"
'
set +x
date -u +%FT%TZ
