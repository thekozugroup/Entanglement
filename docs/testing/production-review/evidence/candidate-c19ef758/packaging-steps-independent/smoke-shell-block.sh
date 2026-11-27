HOST="$(rustc -vV | sed -n 's/^host: //p')"
if [ "${HOST}" = "${TARGET}" ]; then
  EXTRACT="$(mktemp -d)"
  trap 'rm -rf "${EXTRACT}"' EXIT
  tar -xzf "${TARBALL}" -C "${EXTRACT}"
  for bin in entangled entangle; do
    actual="$("${EXTRACT}/${TARBALL%.tar.gz}/${bin}" --version)"
    if [ "${actual}" != "${bin} ${VERSION#v}" ]; then
      echo "::error::Unexpected version in ${TARBALL}: ${actual}" >&2
      exit 1
    fi
  done
fi
