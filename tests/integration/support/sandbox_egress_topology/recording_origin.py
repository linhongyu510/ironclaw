#!/usr/bin/env python3
"""Recording HTTP origin for the sandbox egress-proxy isolation test
(tests/integration/reborn_sandbox_egress_proxy.rs).

Plain `python3 -m http.server` cannot prove the origin observed a request's
actual bytes (request line + headers) -- it serves static files and doesn't
expose what it received. This tiny handler logs the exact request line and
headers of every request to a file (`/var/log/origin_requests.log`, one JSON
object per line) as well as stdout, then replies with a fixed, distinctive
body so the test can assert on bytes actually round-tripped through the real
proxy.
"""

import http.server
import json
import os
import sys

RESPONSE_BODY = os.environ.get("ORIGIN_RESPONSE_BODY", "hello-from-origin").encode()
LOG_PATH = os.environ.get("ORIGIN_LOG_PATH", "/var/log/origin_requests.log")


class RecordingHandler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        record = {
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers.items()),
        }
        line = json.dumps(record)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        print(f"ORIGIN_RECEIVED: {line}", flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(RESPONSE_BODY)))
        self.end_headers()
        self.wfile.write(RESPONSE_BODY)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        # Keep stderr quiet; we log structured records above instead.
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    open(LOG_PATH, "a", encoding="utf-8").close()
    server = http.server.HTTPServer(("0.0.0.0", port), RecordingHandler)
    print(f"recording_origin: listening on 0.0.0.0:{port}, logging to {LOG_PATH}", flush=True)
    server.serve_forever()
