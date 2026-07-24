#!/usr/bin/env python3
"""HTTPS web server for exploit delivery.

Serves static files from the current directory over HTTPS.
Generates a self-signed certificate if not found locally.

After the first request to index.html, a 60-second timer starts.
Once the timer expires, all subsequent index.html requests receive
a dummy page, preventing duplicate exploit triggers by the CUA agent.
All other files continue to be served normally.

Usage:
    python3 web_server.py [--port PORT] [--dir DIR]

Files:
    cert.pem   - self-signed certificate (auto-generated)
    key.pem   - private key (auto-generated)
    web_access.log - request log (appended)
"""

import ssl
import http.server
import os
import sys
import datetime
import logging
import argparse
import threading

from pathlib import Path

# Get the directory where web_server.py is located
BASE_DIR = Path(__file__).resolve().parent

# Create absolute paths to your certificate files
CERT_FILE = str(BASE_DIR / "server.pem")
KEY_FILE = str(BASE_DIR / "server.key")
LOG_FILE = "/tmp/web_access.log"
DEFAULT_PORT = 443
DEFAULT_DIR = "."

EXPIRY_SECONDS = 60
DUMMY_PAGE = (
    b"<!DOCTYPE html>\n"
    b"<html><head><meta charset=\"utf-8\"></head>\n"
    b"<body><h1>503 Service Temporarily Unavailable</h1></body>\n"
    b"</html>\n"
)

# One-shot expiry state for index.html
_first_visit = False
_expired = False
_timer = None


def _expire():
    """Set the expiry flag once the timer fires."""
    global _expired
    _expired = True
    print(f"[*] Timer expired — index.html is now blocked.")


def generate_cert():
    """Generate a self-signed TLS certificate."""
    import subprocess

    print(f"[*] Generating self-signed certificate ({CERT_FILE}, {KEY_FILE})...")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_FILE, "-out", CERT_FILE,
            "-days", "365", "-nodes",
            "-subj", "/CN=localhost/O=WebServer/OU=IT",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("[+] Certificate generated.")


class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that logs all requests to LOG_FILE and stdout.

    Intercepts index.html requests: after the first hit a 60 s
    timer fires; once expired, serves a dummy page instead.
    """

    # Silence default log output
    def log_message(self, fmt, *args):
        msg = f"{self.client_address[0]} - {fmt % args}"
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{now}  {msg}"

        # Print to console
        print(line)

        # Append to log file
        try:
            with open(LOG_FILE, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def end_headers(self):
        """Inject Cache-Control: no-store when flagged by do_GET."""
        if getattr(self, '_add_no_cache', False):
            self.send_header('Cache-Control',
                             'no-store, no-cache, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
        super().end_headers()

    def _is_index_request(self):
        """Return True if self.path targets index.html."""
        path = self.path.split("?")[0]           # strip query string
        return path == "/" or path.endswith("/index.html")

    def do_GET(self):
        global _first_visit, _timer, _expired

        if self._is_index_request():
            if not _first_visit:
                _first_visit = True
                _timer = threading.Timer(EXPIRY_SECONDS, _expire)
                _timer.start()
                print(f"[*] First index.html hit — "
                      f"{EXPIRY_SECONDS}s timer started.")
            elif _expired:
                self.send_response(503)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(DUMMY_PAGE)))
                self.send_header('Cache-Control',
                                 'no-store, no-cache, must-revalidate, max-age=0')
                self.end_headers()
                self.wfile.write(DUMMY_PAGE)
                return

            # Prevent browser cache so every revisit reaches the server
            self._add_no_cache = True

        super().do_GET()


def main():
    parser = argparse.ArgumentParser(description="HTTPS exploit delivery server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--dir", default=DEFAULT_DIR)
    args = parser.parse_args()
    
    # Generate cert if missing
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        generate_cert()
    
    os.chdir(args.dir)

    # Setup SSL context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    # Create and start server
    server = http.server.HTTPServer(("0.0.0.0", args.port), LoggingHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"[+] HTTPS server listening on 0.0.0.0:{args.port}")
    print(f"[+] Serving directory: {os.path.abspath(args.dir)}")
    print(f"[+] Logging to: {os.path.abspath(LOG_FILE)}")
    print(f"[+] Certificate: {os.path.abspath(CERT_FILE)}")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
