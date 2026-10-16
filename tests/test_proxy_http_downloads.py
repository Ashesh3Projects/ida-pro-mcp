"""The legacy backend decoder handles framed outputs without any target fallback."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import pytest
from ida_pro_mcp.proxy_backend import ProxyProvider, ProxySession
from ida_pro_mcp.instance_contract import RoutingError


@pytest.mark.parametrize("framing", ["length", "chunked", "close"])
def test_output_body_is_decoded_with_explicit_generation(framing):
    paths=[]
    class Handler(BaseHTTPRequestHandler):
        protocol_version="HTTP/1.1"
        def log_message(self,*args): pass
        def do_GET(self):
            paths.append(self.path)
            body=b'{"source":"A"}'
            self.send_response(200)
            if framing=="length": self.send_header("Content-Length",str(len(body)))
            elif framing=="chunked": self.send_header("Transfer-Encoding","chunked")
            else:
                self.send_header("Connection","close")
                self.close_connection=True
            self.end_headers()
            if framing=="chunked": self.wfile.write(f"{len(body):x}\r\n".encode()+body+b"\r\n0\r\n\r\n")
            else: self.wfile.write(body)
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        session=ProxySession({"host":"127.0.0.1","port":server.server_port,"generation":"a"*16},ProxyProvider(discover=lambda:[]),None)
        assert session._download("output-1")=={"text":'{"source":"A"}'}
        assert paths==["/output/output-1.json?instance_id="+"a"*16]
    finally:
        server.shutdown();server.server_close();thread.join()
