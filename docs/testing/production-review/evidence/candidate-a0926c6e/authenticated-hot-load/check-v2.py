#!/usr/bin/env python3
"""Compare normal trusted Iroh jobs after a source-independent, observed empty inventory."""
import argparse
import concurrent.futures
import contextlib
import datetime as dt
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import tomllib
import traceback

BASE = Path(__file__).resolve().parent
REPO = Path('/workspace/Entanglement')
spec = importlib.util.spec_from_file_location('nodes', REPO/'scripts/tests/distributed-rust-tests.py')
nodes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nodes)
def checksum(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()
def now():
    return time.monotonic()
def require(value, message):
    if not value:
        raise ValueError(str(message))

class Catalog:
    def __init__(self, stack):
        self.samples = []
        self.unexpected = []
        self.first = threading.Event()
        catalog = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *unused):
                pass
            def do_GET(self):
                if self.path != '/v1/models':
                    catalog.unexpected.append(self.path)
                    self.send_error(404)
                    return
                body = b'{"object":"list","data":[]}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                catalog.samples.append(now())
                catalog.first.set()
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.1},daemon=True)
        thread.start()
        self.endpoint='http://127.0.0.1:'+str(server.server_port)+'/v1/chat/completions'
        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        stack.callback(stop)

def rpc(node, method, params=None):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(8)
        conn.connect(str(node.socket))
        conn.sendall(json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()+b'\n')
        with conn.makefile('rb') as response: data=json.loads(response.readline(1024*1024))
    require(data.get('id')==1 and data.get('jsonrpc')=='2.0', ('invalid envelope',data))
    return data
def metric(node):
    text=rpc(node,'metrics')['result']
    return sum(int(v) for v in re.findall(r'(?m)^entangle_wasm_invocation_seconds_count\{[^}]*\} (\d+)$',text))
def start(node,stack,port,routes,catalog=None):
    config=f'[mesh]\ntransports=["iroh"]\nmulti_node=true\n[scheduler]\nbind="127.0.0.1:{port}"\nrelay=false\npeers={json.dumps(routes)}\n'
    if catalog:
        config += f'[security]\nmax_tier_allowed=5\n[runtime.inference]\nendpoint={json.dumps(catalog.endpoint)}\nmodel="empty-catalog-observer"\n'
    (node.state/'config.toml').write_text(config)
    log=stack.enter_context((node.directory/'daemon.log').open('wb'))
    proc=subprocess.Popen([node.binaries/'entangled','run'],env=node.env,stdout=log,stderr=log)
    def stop():
        proc.terminate()
        try: proc.wait(timeout=6)
        except subprocess.TimeoutExpired: proc.kill();proc.wait(timeout=3)
    stack.callback(stop)
    deadline=now()+10
    while not node.socket.is_socket():
        require(proc.poll() is None and now()<deadline,(node.directory/'daemon.log').read_text()[-500:])
        time.sleep(.025)
    status=rpc(node,'mesh/status')['result']
    require(status['local_peer_id']==node.peer and status['transports_active']==['iroh'],status)
def job(coord,worker,plugin,nonce):
    return rpc(coord,'compute/dispatch',dict(plugin_id=plugin,input=list(nonce if isinstance(nonce,bytes) else nonce.encode()),timeout_ms=1500,cpu_cores=.01,memory_bytes=0,gpu_required=False,gpu_vram_min_bytes=0,integrity={'kind':'trusted-executor','allowlist':[worker.peer]}))
def is_miss(response):
    error=response.get('error',{})
    return error.get('code')==-32000 and 'no live workers in pool' in error.get('message','') and 'rejected' not in error.get('message','')
def assert_result(reply,peer,nonce):
    value=reply.get('result')
    require(value is not None, reply)
    require(value['chosen_peer']==peer and bytes(value['output'])==('Hello, '+nonce+'!').encode(),reply)
def trial(dir,bins,number):
    with contextlib.ExitStack() as stack:
        catalog=Catalog(stack)
        a=nodes.Node(dir/'A',bins);b=nodes.Node(dir/'B',bins)
        coord,worker=(a,b) if number%2 else (b,a)
        coord.trust(worker);worker.trust(coord)
        worker.cli('keyring','add',coord.key,'--name','inventory fixture publisher')
        pkg=dir/'signed'
        coord.cli('plugins','build',REPO/'examples/hello-world','--wasm',REPO/'crates/entangle-host/tests/fixtures/hello-pong.wasm','--out',pkg)
        plugin=tomllib.loads((pkg/'entangle.toml').read_text())['plugin']['id']
        worker_port=nodes.free_port()
        start(worker,stack,worker_port,[],catalog)
        require(rpc(worker,'plugins/list')['result']['plugins']==[], 'worker must start empty')
        require(len(catalog.samples)==0,'catalog probed without an incoming capability request')
        start(coord,stack,0,[f'{worker.key}@127.0.0.1:{worker_port}'])
        require(catalog.first.wait(5),'initial authenticated inventory was never observed')
        require(rpc(coord,'plugins/list')['result']['plugins']==[], 'coordinator must start empty')
        time.sleep(.10)
        require(len(catalog.samples)==1, ('expected exactly one initial authenticated inventory',len(catalog.samples)))
        require(metric(worker)==0 and metric(coord)==0,'initial guest invocation')
        worker.cli('plugins','load',pkg)
        loaded=now()
        require(rpc(worker,'plugins/list')['result']['plugins']==[plugin], 'worker hot load failed')
        nonce='measure-'+secrets.token_hex(12)
        misses=[]
        first=None
        while True:
            sent=now()
            reply=job(coord,worker,plugin,nonce)
            if first is None:
                first={'start_offset_s':round(sent-loaded,5),'finish_offset_s':round(now()-loaded,5),'successful': 'result' in reply,'error':reply.get('error')}
            if 'result' in reply: break
            require(is_miss(reply),reply)
            misses.append(round(sent-loaded,4))
            require(now()-loaded<24,('no successful dispatch within 24s',reply))
            time.sleep(.50)
        finished=now()
        assert_result(reply,worker.peer,nonce)
        require(metric(worker)==1 and metric(coord)==0, 'duplicated, missing, or local primary execution')
        queries_at_success=len(catalog.samples)
        values=['parallel-'+secrets.token_hex(12) for _ in range(4)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            answers=list(pool.map(lambda text:job(coord,worker,plugin,text),values))
        for response,text in zip(answers,values): assert_result(response,worker.peer,text)
        require(metric(worker)==5 and metric(coord)==0, 'incorrect number of parallel executions')
        result={'trial':number,'coordinator':coord.directory.name,'worker':worker.directory.name,'coordinator_peer':coord.peer,'worker_peer':worker.peer,'load_after_first_empty_report_s':round(loaded-catalog.samples[0],4),'load_to_authenticated_result_s':round(finished-loaded,4),'queries_to_success':queries_at_success,'initial_no_workers_misses':len(misses),'miss_offsets_s':misses,'first_submission':first,'first_job_nonce':nonce,'first_job_output':bytes(reply['result']['output']).decode(),'primary_completed':1,'parallel_valid_submissions':4,'parallel_valid_completions':4}
        if number==4:
            # Exit the measured demand cooldown, leaving over 10s until the next ordinary poll.
            time.sleep(2.2)
            absent=plugin.replace('/hello-world@','/absent-fixture@')
            require(absent!=plugin,'unexpected fixture id')
            initial=len(catalog.samples)
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                absent_replies=list(pool.map(lambda n:job(coord,worker,absent,'missing-'+str(n)),range(6)))
            require(all(is_miss(r) for r in absent_replies),absent_replies)
            time.sleep(2.0)
            burst_reads=len(catalog.samples)-initial
            require(burst_reads<=2 and metric(worker)==5 and metric(coord)==0,('burst generated excess probes or jobs',burst_reads))
            errors_before=metric(worker)
            rejected=job(coord,worker,plugin,bytes([255]))
            guest_error=rejected.get('error',{})
            require(guest_error.get('code')==-32000 and 'rejected the task (execution)' in guest_error.get('message','') and 'invalid' in guest_error.get('message','').lower(),rejected)
            require(metric(worker)==errors_before+1 and metric(coord)==0,'worker execution error was replayed or not delivered')
            worker.cli('mesh','revoke',coord.peer)
            denied=job(coord,worker,plugin,'revoked-'+secrets.token_hex(6))
            err=denied.get('error',{})
            require(err.get('code')==-32000 and 'trusted peer allowlist' in err.get('message',''),denied)
            require(metric(worker)==6 and metric(coord)==0,'revoked request executed')
            worker.trust(coord)
            nonce='restored-'+secrets.token_hex(10)
            assert_result(job(coord,worker,plugin,nonce),worker.peer,nonce)
            require(metric(worker)==7 and metric(coord)==0,'restored result count')
            result.update(guest_execution_error=guest_error['message'],guest_error_worker_attempts=1,parallel_absent_outcomes=6,burst_incremental_inventory_reads=burst_reads,worker_revocation_error=err['message'],revoked_new_completions=0,retrust_new_completions=1)
        result.update(all_readiness_offsets_relative_to_load_s=[round(i-loaded,4) for i in catalog.samples],expected_worker_completions=7 if number==4 else 5,actual_worker_completions=metric(worker),coordinator_completions=metric(coord))
        require(not catalog.unexpected,catalog.unexpected)
        return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--bin-dir',type=Path,required=True);parser.add_argument('--label',required=True)
    parser.add_argument('--revision',required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--expected-archive',type=Path)
    args=parser.parse_args()
    bins=args.bin_dir.resolve()
    hashes={n:checksum(bins/n) for n in ['entangle','entangled']}
    if args.expected_archive:
        expected=json.loads(args.expected_archive.read_text())
        require(all(expected['files_sha256'][k]==v for k,v in hashes.items()),'release hash mismatch')
        require(expected['source_commit']==args.revision,'wrong archive commit')
    report=dict(label=args.label,revision=args.revision,started_utc=utc(),binaries_sha256=hashes,plan_sha256=checksum(BASE/'plan-v2.md'),harness_sha256=checksum(Path(__file__)),component_sha256=checksum(REPO/'crates/entangle-host/tests/fixtures/hello-pong.wasm'),trials=[])
    require(not args.out.exists(),'receipt already exists')
    try:
        for n in range(1,5):
            with tempfile.TemporaryDirectory(prefix='entangle-inventory-case-',dir='/tmp') as tmp:
                row=trial(Path(tmp),bins,n);report['trials'].append(row)
                print(args.label,n,row['load_to_authenticated_result_s'],row['queries_to_success'],row['initial_no_workers_misses'],flush=True)
        values=[r['load_to_authenticated_result_s'] for r in report['trials']]
        report.update(first_submission_successes=sum(r["first_submission"]["successful"] for r in report["trials"]),first_submission_under_10s_successes=sum(r["first_submission"]["successful"] and r["first_submission"]["finish_offset_s"]<10 for r in report["trials"]),median_s=statistics.median(values),max_s=max(values),all_under_10s=all(i<10 for i in values),complete=True)
    except Exception as error:
        report.update(complete=False,error=f'{type(error).__name__}: {error}');raise
    finally:
        report['finished_utc']=utc()
        with args.out.open('x') as dest:json.dump(report,dest,indent=2);print(file=dest)
if __name__=='__main__':main()
