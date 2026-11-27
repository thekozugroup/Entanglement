python3 scripts/tests/test_package_native_release.py
# Use the checked-out tag's commit time for the tar and gzip headers.
SOURCE_DATE_EPOCH="$(git log -1 --no-show-signature --format=%ct HEAD)"
TARBALL="$(python3 scripts/package-native-release.py --version "${VERSION}" \
  --target "${TARGET}" --bin-dir "target/${TARGET}/release" \
  --source-date-epoch "${SOURCE_DATE_EPOCH}")"
echo "tarball=${TARBALL}" >> "$GITHUB_OUTPUT"
