#!/bin/bash
# Repeat package and inference receipts without modifying a prior candidate.
set -euo pipefail

phase=$1
self=$(realpath "$0")
root=$(realpath "$2")
commit=$3
watermark=$4
shift 4
cd "$root"
test "$(git rev-parse HEAD)" = "$commit"
test "$(python3 scripts/production_score.py --source-id)" = "$watermark"
base=docs/testing/production-review/evidence
prior="$base/candidate-2602ce17"
evidence="$base/candidate-${commit:0:8}"

case "$phase" in
    prepare)
        for group in package-operator inference-compatibility pkg-linux-matrix; do
            mkdir -p "$evidence/$group"
            test ! -e "$evidence/$group/verify.py"
            cp -- "$prior/$group/verify.py" "$evidence/$group/verify.py"
        done
        cp -- "$prior/pkg-linux-matrix/run-in-container.sh" "$evidence/pkg-linux-matrix/run-in-container.sh"
        cp -- "$self" "$evidence/repeat-frozen-evidence.sh"
        ;;

    operator)
        export PATH="/workspace/.entanglement-dev/cargo/bin:$PATH"
        export CARGO_HOME=/workspace/.entanglement-dev/cargo RUSTUP_HOME=/workspace/.entanglement-dev/rustup
        export RUSTUP_TOOLCHAIN=1.91 CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true
        log_dir="$evidence/package-operator"
        python3 "$log_dir/verify.py" --candidate-root "$root" --cargo-entangle "$1" \
            --output "$log_dir" --expected-source "$watermark" \
            --source-url https://github.com/thekozugroup/Entanglement.git
        ;;

    inference)
        log_dir="$evidence/inference-compatibility"
        python3 "$log_dir/verify.py" --candidate-root "$root" --expected-source "$watermark" \
            --unit "$1" --integration "$2" --daemon "$3" --output "$log_dir"
        ;;

    provision)
        log_dir="$evidence/pkg-linux-matrix"
        test ! -e "$log_dir/seed.log"
        state=$(mktemp -d "/workspace/entangle-package-${commit:0:8}.XXXXXX")
        chmod 0755 "$state"
        printf '%s\n' "$state" > "/tmp/entangle-package-${commit:0:8}-seed-path"
        old_seed=$(cat /tmp/entangle-package-seed-path)

        (
            set -x
            date -u +%FT%TZ
            python3 scripts/production_score.py --source-id
            docker info --format '{{json .SecurityOptions}}'
            git bundle create "$state/source.bundle" HEAD
            git bundle verify "$state/source.bundle"
            cp -al -- "$old_seed/toolchain" "$old_seed/registry" "$old_seed/public-repro-fixture-seed.pem" "$state/"
            chmod 0644 "$state/source.bundle"
            install -m 0644 "$log_dir/run-in-container.sh" "$state/run-in-container.sh"
            sha256sum "$state/source.bundle" "$state/toolchain/bin/cargo" "$state/toolchain/bin/rustc"
            python3 scripts/production_score.py --source-id
            date -u +%FT%TZ
        ) > "$log_dir/seed.log" 2>&1

        provision() (
            distro=$1
            image=$2
            set -x
            date -u +%FT%TZ
            python3 scripts/production_score.py --source-id
            docker image inspect "$image" --format '{{.Os}}/{{.Architecture}} ID={{.Id}} RepoDigests={{join .RepoDigests ","}}'
            capsule=$(docker create --network bridge --security-opt no-new-privileges \
                --platform linux/amd64 --mount "type=bind,src=$state,dst=/fixture,readonly" \
                "$image" sleep infinity)
            printf '%s\n' "$capsule" > "$state/$distro-container-id"
            docker start "$capsule"
            docker exec "$capsule" sh -ec 'cat /etc/os-release; /fixture/toolchain/bin/rustc -Vv; apt-get -o Acquire::Retries=1 update; DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y ca-certificates git gcc libc6-dev make pkg-config; apt-get clean; rm -rf /var/lib/apt/lists/*'
            docker network disconnect bridge "$capsule"
            docker inspect "$capsule" --format '{{json .NetworkSettings.Networks}}'
            python3 scripts/production_score.py --source-id
            date -u +%FT%TZ
        )

        provision jammy ubuntu@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb \
            > "$log_dir/jammy-provision.log" 2>&1
        provision noble ubuntu@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b \
            > "$log_dir/noble-provision.log" 2>&1
        ;;

    matrix)
        state=$(cat "/tmp/entangle-package-${commit:0:8}-seed-path")
        log_dir="$evidence/pkg-linux-matrix"
        python3 "$log_dir/verify.py" --candidate-root "$root" --expected-source "$watermark" \
            --jammy-container "$(cat "$state/jammy-container-id")" \
            --noble-container "$(cat "$state/noble-container-id")" --output "$log_dir"
        ;;

    *)
        printf 'unknown phase %s\n' "$phase" >&2
        exit 2
        ;;
esac
