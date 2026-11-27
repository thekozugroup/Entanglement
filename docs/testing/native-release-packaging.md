# Reproducing native release archives

Check out the release tag and build its two native executables. Use Python 3.12 and `b3sum` to package them with the tagged commit's committer time, in Unix seconds. The release workflow uses this same command.

```sh
tag=v0.1.0
target=x86_64-unknown-linux-gnu
git checkout --detach "refs/tags/$tag"
epoch=$(git log -1 --no-show-signature --format=%ct HEAD)
cargo build --release --workspace --bins --locked --target "$target"
python3 scripts/package-native-release.py \
  --version "$tag" --target "$target" --source-date-epoch "$epoch" \
  --bin-dir "target/$target/release" --output-dir target/native-archive
```

Each archive contains one version-and-target directory with the two executables and four release documents in a fixed order. The USTAR members have numeric owner and group zero, mode 0755 for the directory and executables, and mode 0644 for the documents. The source epoch is written to every member and the gzip header. The gzip header has no filename. The adjacent `.sha256` and `.b3` files name the archive by basename, so they can be checked from any directory containing the three files.

Repeat packaging into a different output directory and compare the archive and both checksum files byte for byte. Reproduction assumes byte-identical input files, the same tag, target and epoch, and the same DEFLATE implementation. The packaging check measures the results with fixed build outputs. Independent builds must establish whether they produce identical executables.
