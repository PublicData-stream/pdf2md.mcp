#!/usr/bin/env python3
"""Synthetic HTTPS PDF for an isolated test Pod, never a public service."""
import argparse
import http.server
import json
from pathlib import Path
import ssl
import subprocess
import time
import urllib.request

ADDRESS = "93.184.216.34"
HOSTNAME = "fixture.example"


def local_route():
    routes = json.loads(subprocess.check_output(["ip", "-j", "route", "get", ADDRESS]))
    if len(routes) != 1 or routes[0].get("dev") != "lo" or routes[0].get("type") != "local":
        raise RuntimeError("fixture destination is not a Pod-local loopback route")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("route", "serve", "ready"))
    args = parser.parse_args()
    if args.mode == "route":
        subprocess.run(["ip", "address", "replace", ADDRESS + "/32", "dev", "lo"], check=True)
        local_route()
        return
    local_route()
    if args.mode == "ready":
        context = ssl.create_default_context(cafile="/fixture-data/ca.crt")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        for _ in range(120):
            try:
                with opener.open("https://" + HOSTNAME + "/sample.pdf", timeout=2) as response:
                    if response.read() == Path("/fixture-data/sample.pdf").read_bytes():
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise RuntimeError("HTTPS fixture did not become ready")
    data = Path("/fixture-data/sample.pdf").read_bytes()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/sample.pdf":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer((ADDRESS, 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/fixture-data/fixture.crt", "/fixture-data/fixture.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
