import importlib.util
from unittest.mock import patch
s=importlib.util.spec_from_file_location('runner','scripts/run-rust-tests.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Stream:
 def __init__(self,data):self.data=data
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def readline(self,size):return self.data[:size]
class Sock:
 def __init__(self,data):self.data=data
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def settimeout(self,value):pass
 def connect(self,path):pass
 def sendall(self,data):pass
 def makefile(self,mode):return Stream(self.data)
for name,data in [('truncated',b'{"jsonrpc":"2.0","id":1'),('oversized',b'x'*(m.MAX_RPC_LINE+1)+b'\n'),('invalid-envelope',b'{"jsonrpc":"2.0","id":2,"result":{}}\n')]:
 with patch.object(m.socket,'socket',return_value=Sock(data)):
  try:m.rpc('/tmp/unused','compute/dispatch',{},1)
  except m.DispatchError as e: print(name,'rejected',str(e))
  else:raise AssertionError(name+' accepted')
with patch.object(m.socket,'socket',return_value=Sock(b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n')):
 assert m.rpc('/tmp/unused','compute/dispatch',{},1)=={'ok':True}
print('valid-envelope passed')
