from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import tempfile

repo=Path('/workspace/Entanglement')
new_installer=Path('/tmp/entangle-transactional-posix-install/scripts/install.sh')
archive='entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz'
stamp=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=repo,text=True).strip()
assert stamp=='sha256:a2848766dd5b69cf72246e7cba06c95afe1807d2556f00efec115cdd40cdca45'
old_installer=subprocess.check_output(['git','show','5c4ead3:scripts/install.sh'],cwd=repo)
with tempfile.TemporaryDirectory(prefix='entangle-native-installer-transaction-',dir='/workspace') as name:
    stage=Path(name)
    stage.chmod(0o755)
    for label, source in [('old-install.sh',old_installer),('new-install.sh',new_installer.read_bytes())]:
        path=stage/label
        path.write_bytes(source)
        path.chmod(0o644)
        print(label,hashlib.sha256(source).hexdigest(),flush=True)
    for variant,directory in [('jammy','a0926c6ef347-ubuntu22'),('canonical','a0926c6ef347')]:
        storage=stage/variant
        storage.mkdir()
        storage.chmod(0o755)
        for filename in [archive, archive+'.sha256']:
            src=repo/'target/release-candidate'/directory/filename
            dst=storage/filename
            shutil.copyfile(src,dst)
            dst.chmod(0o644)
        digest=hashlib.sha256((storage/archive).read_bytes()).hexdigest()
        assert digest==(storage/(archive+'.sha256')).read_text().split()[0]
        print(variant,digest,flush=True)
    curl=stage/'curl'
    curl.write_text(r'''#!/bin/sh
set -eu
[ "$#" -eq 7 ] && [ "$1" = "-fsSL" ] && [ "$2" = "--proto" ] && [ "$3" = "=https" ] && [ "$4" = "--tlsv1.2" ] && [ "$5" = "-o" ]
url="https://github.com/thekozugroup/Entanglement/releases/download/v0.1.0/$FIXTURE_ARCHIVE"
case "$7" in
 "$url") cp "/fixture/$FIXTURE_VARIANT/$FIXTURE_ARCHIVE" "$6" ;;
 "$url.sha256") cp "/fixture/$FIXTURE_VARIANT/$FIXTURE_ARCHIVE.sha256" "$6" ;;
 *) exit 2 ;;
esac
''')
    curl.chmod(0o644)
    shell=r'''
set -eu
expected=$1
. /etc/os-release
[ "$VERSION_ID" = "$expected" ]
[ "$(id -u)" -eq 65534 ]
id
ldd --version | head -1
readlink /bin/sh
home=$(mktemp -d /work/install-native.XXXXXX)
export HOME="$home" FIXTURE_ARCHIVE="$2"
mkdir "$home/stub"
cp /fixture/curl "$home/stub/curl"
chmod 0755 "$home/stub/curl"
export PATH="$home/stub:$PATH" TMPDIR=/tmp
test "$(wc -l </proc/net/route)" -eq 1
grep -Eq ' /tmp .*noexec' /proc/mounts
run_install() {
    status=0
    FIXTURE_VARIANT="$variant" /bin/sh "/fixture/$installer-install.sh" --version v0.1.0 --prefix "$prefix" "$@" >"$home/install.log" 2>&1 || status=$?
    grep -E '(^==>|^error:|GLIBC_2.39)' "$home/install.log"
    echo "$installer $variant installer exit: $status"
}
sha() { sha256sum "$prefix/bin/$1" | awk '{print $1}'; }
jammy_cli=2ba2a65fc301693fdce428b03568f99053114b8da243b72657cc678ec6a11098
jammy_daemon=607c2dca450a0717aedc5a259ee08118831e8b65352656eab6e5005b0239aed2
canonical_cli=dfd160a6158221624db5327ae3d1c86b94f36dc018ca82821bb0912604f45e33
canonical_daemon=ae746362f564f20a6ae00d81883a4873078ad9f847684145341d57315b6fc823
if [ "$VERSION_ID" = '22.04' ]; then
 for installer in old new; do
    prefix="$home/prefix $installer"
    variant=jammy
    run_install
    [ "$status" -eq 0 ]
    [ "$(sha entangle)" = "$jammy_cli" ]
    [ "$(sha entangled)" = "$jammy_daemon" ]
    mv "$prefix/bin/entangled" "$home/parked-daemon"
    run_install
    [ "$status" -eq 0 ]
    if [ "$installer" = old ]; then
       [ ! -e "$prefix/bin/entangled" ]
       echo "old same-version request skipped missing daemon"
       mv "$home/parked-daemon" "$prefix/bin/entangled"
    else
       [ "$(sha entangled)" = "$jammy_daemon" ]
       echo "new same-version request restored exact daemon"
       chmod a-w "$prefix/bin"
       run_install
       [ "$status" -eq 0 ]
       grep -Fq 'already installed' "$home/install.log"
       chmod u+w "$prefix/bin"
       echo "new read-only complete prefix remained usable"
    fi
    variant=canonical
    run_install --force
    [ "$status" -eq 1 ]
    grep -Fq 'GLIBC_2.39' "$home/install.log"
    [ ! -e "$prefix/bin/.entangle-install.lock" ]
    if [ "$installer" = old ]; then
       [ "$(sha entangle)" = "$canonical_cli" ]
       [ "$(sha entangled)" = "$canonical_daemon" ]
       echo "old failed replacement left both incompatible ELFs"
    else
       [ "$(sha entangle)" = "$jammy_cli" ]
       [ "$(sha entangled)" = "$jammy_daemon" ]
       "$prefix/bin/entangle" --version
       "$prefix/bin/entangled" --version
       echo "new failed replacement preserved both original and runnable ELFs"
    fi
 done
else
    installer=new
    prefix="$home/prefix Noble"
    variant=jammy
    run_install
    [ "$status" -eq 0 ]
    variant=canonical
    run_install --force
    [ "$status" -eq 0 ]
    [ "$(sha entangle)" = "$canonical_cli" ]
    [ "$(sha entangled)" = "$canonical_daemon" ]
    "$prefix/bin/entangle" --version
    "$prefix/bin/entangled" --version
    echo "new compatible forced replacement published both exact ELFs"
fi
'''
    for version in ('22.04','24.04'):
        image=subprocess.check_output(['docker','image','inspect','ubuntu:'+version,'--format','{{index .RepoDigests 0}}'],text=True).strip()
        print(version,image,flush=True)
        args=['docker','run','--rm','--pull','never','--network','none','--read-only','--security-opt','no-new-privileges','--user','65534:65534',
              '--tmpfs','/tmp:rw,nosuid,nodev,noexec,mode=1777','--tmpfs','/work:rw,nosuid,nodev,exec,mode=1777',
              '--mount',f'type=bind,src={stage},dst=/fixture,readonly',image,'/bin/sh','-ec',shell,'sh',version,archive]
        subprocess.run(args,check=True,timeout=60)
assert subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=repo,text=True).strip()==stamp
