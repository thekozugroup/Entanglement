import argparse,json,sys,hashlib,subprocess,uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
parser=argparse.ArgumentParser(); parser.add_argument('result',type=Path); parser.add_argument('--peer-fingerprint',required=True,type=Path,help='path to the separately compiled BLAKE3 peer fingerprint helper'); args=parser.parse_args()
p=args.result;r=json.loads(p.read_text());count=0;rows=[]
expected='sha256:fcb2f28c293a30b2496d2a788442782aba96c3806d4e4d1e868d4c6db32dc348'
assert r['source_id']==r['source_after']==expected
for group in r['endpoints']:
 for row in group['samples']:
  assert row['executor']==group['worker_peer']
  public=bytes.fromhex(row['public_key_hex']); peer=subprocess.check_output([str(args.peer_fingerprint.resolve(strict=True))],input=public.hex(),text=True).strip();assert peer==row['executor']
  key=Ed25519PublicKey.from_public_bytes(public); aggregate=bytearray()
  for index,c in enumerate(row['chunks']):
   assert c['seq']==index
   payload=bytes.fromhex(c['payload_hex']); assert hashlib.sha256(payload).hexdigest()==c['sha256']
   msg=b'entangle/stream/chunk/1\x00'+uuid.UUID(row['task_id']).bytes+index.to_bytes(8,'big')+c['timestamp_ms'].to_bytes(8,'big')+hashlib.sha256(payload).digest()
   key.verify(bytes.fromhex(c['signature_hex']),msg);aggregate.extend(payload);count+=1
  assert aggregate.decode()==row['output'] and hashlib.sha256(aggregate).hexdigest()==row['output_sha256']
  direct=row['direct_response'];choice=direct['choices'][0];text=choice['message']['content'] if group['endpoint'].endswith('/chat/completions') else choice['text']
  assert text==row['output'] and direct['usage']['completion_tokens']==row['generated_tokens']
  assert len(row['chunks'])>=2 and 0<row['first_signed_chunk_ms']<=row['duration_ms']
  rows.append({'endpoint':group['endpoint'],'peer':peer,'chunks':len(row['chunks']),'first_ms':row['first_signed_chunk_ms'],'duration_ms':row['duration_ms'],'tokens':row['generated_tokens']})
print(json.dumps({'result_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'verified_ed25519_chunks':count,'samples':rows},indent=2))
