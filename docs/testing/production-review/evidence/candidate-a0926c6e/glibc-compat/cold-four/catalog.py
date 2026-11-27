"""Report local authorized inventory sampling without advertising an inference model."""
import datetime,http.server,json,time
def event(kind):
    print(json.dumps(dict(event=kind,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),monotonic_ns=time.monotonic_ns())),flush=True)
class Catalog(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        if self.path!='/v1/models':
            self.send_error(404);return
        event('inbound_models_get')
        body=b'{"data":[]}'
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers()
        self.wfile.write(body);self.wfile.flush()
        event('empty_response_written')
server=http.server.HTTPServer(('127.0.0.1',18678),Catalog)
event('ready')
server.serve_forever()
