"""A stand-in for Paddock's health endpoints: answers 200 to every GET.

    python scripts/tests/ok_server.py 8099

Used by .github/workflows/installers.yml so install.ps1 can be run end to end on
a Windows runner (which has no Linux containers) against a fake `docker`.
"""
import http.server
import sys


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
