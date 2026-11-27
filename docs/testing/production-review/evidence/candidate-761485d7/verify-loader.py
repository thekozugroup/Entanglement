#!/usr/bin/env python3
"""Check the direct RPC and configured startup path on a temporary signed Linux installation."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import tomllib


def verify(ok, message):
    if not ok:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', required=True, type=Path)
    bins = parser.parse_args().bin_dir.resolve()
    repo = Path.cwd().resolve()
    cases = {'entangle.toml': 1024 * 1024, 'plugin.wasm': 64 * 1024 * 1024, 'plugin.wasm.sig': 64 * 1024}
    with tempfile.TemporaryDirectory(prefix='ent-loader-check-', dir='/tmp') as temp:
        home = Path(temp)
        env = {**os.environ, 'HOME': str(home), 'TOKIO_WORKER_THREADS':'2', 'RAYON_NUM_THREADS':'2', 'RUST_LOG':'warn'}
        env.pop('ENTANGLE_ALLOW_LOCAL', None)
        env.pop('ENTANGLE_SOCKET', None)

        def cli(*args):
            return subprocess.run([bins/'entangle', *args], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12)

        def success(*args):
            res = cli(*args)
            verify(res.returncode == 0, f'{args[0]}: {res.stderr[:500]}')
            return res.stdout

        success('init','--non-interactive')
        state = home/'.entangle'
        public = subprocess.check_output(['openssl','pkey','-in',state/'identity.key','-pubout','-outform','DER'],timeout=5)[-32:].hex()
        success('keyring','add',public,'--name','temporary loader candidate publisher')
        package = state/'plugins'/'hello'
        package.parent.mkdir(exist_ok=True)
        success('plugins','build',repo/'examples/hello-world','--wasm',repo/'crates/entangle-host/tests/fixtures/hello-pong.wasm','--out',package)
        plugin = tomllib.loads((package/'entangle.toml').read_text())['plugin']['id']
        cfg = state/'config.toml'
        def configure(startup):
            cfg.write_text('[mesh]\ntransports = []\nmulti_node = false\n[runtime]\nplugins = ' + json.dumps([str(package)] if startup else []) + '\n')

        @contextlib.contextmanager
        def daemon():
            log = home/'daemon.log'
            with log.open('wb') as stream:
                child = subprocess.Popen([bins/'entangled','run'],env=env,stdin=subprocess.DEVNULL,stdout=stream,stderr=stream)
            try:
                until=time.monotonic()+12
                while time.monotonic()<until:
                    verify(child.poll() is None,'unexpected daemon startup exit: '+log.read_text()[-500:])
                    if cli('plugins','list').returncode==0: break
                    time.sleep(.05)
                else: raise RuntimeError('daemon readiness deadline')
                yield
            finally:
                if child.poll() is None: child.terminate()
                child.wait(timeout=8)

        @contextlib.contextmanager
        def invalid(name, kind):
            entry = package/name
            saved = home/('original-'+name)
            entry.rename(saved)
            try:
                if kind=='symlink':
                    entry.symlink_to(saved)
                else:
                    with entry.open('xb') as file: file.truncate(cases[name]+1)
                yield
            finally:
                entry.unlink(missing_ok=True)
                saved.rename(entry)

        def rejected(result,kind,name):
            text=(result.stderr+result.stdout).lower()
            verify(result.returncode!=0, f'{kind} {name} was admitted')
            if kind=='oversize':
                verify('exceeds' in text and str(cases[name]) in text, f'{name} did not stop at its byte limit')
            else:
                verify('too many levels of symbolic links' in text or 'os error 40' in text, f'{name} did not fail no-follow check')

        def invoke_good():
            challenge = secrets.token_hex(16)
            answer = success('plugins','invoke',plugin,'--input',challenge)
            verify(f'Hello, {challenge}!' in answer, 'valid signed invocation failed')

        configure(False)
        with daemon():
            for name in cases:
                for kind in ('symlink','oversize'):
                    with invalid(name,kind):
                        rejected(cli('plugins','load',package),kind,name)
                        verify(plugin not in success('plugins','list'),'failed package entered registry')
            success('plugins','load',package)
            invoke_good()

        configure(True)
        for name in cases:
            for kind in ('symlink','oversize'):
                with invalid(name,kind):
                    result = subprocess.run([bins/'entangled','run'],env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=12)
                    rejected(result,kind,name)
        with daemon():
            verify(plugin in success('plugins','list'), 'restored valid startup package was absent')
            invoke_good()
        print(json.dumps({'direct_rpc_refusals':6,'configured_startup_refusals':6,'files_checked':cases,
                          'conditions':['symlink to intact signed member','sparse regular file one byte above limit'],
                          'valid_signed_recovery':['rpc load and invoke','startup load and invoke']}))

if __name__=='__main__': main()
