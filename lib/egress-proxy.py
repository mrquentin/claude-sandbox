#!/usr/bin/env python3
"""claude-sandbox egress filter proxy — lightweight HTTP/HTTPS CONNECT proxy
with hostname-based whitelist/blacklist filtering using glob patterns.

Usage:
    egress-proxy.py --config <config.json> --port <port> [--pidfile <path>]

Config format (JSON):
    {
        "whitelist": ["*.anthropic.com", "api.github.com"],
        "blacklist": ["*.evil.com", "malware.example.org"]
    }

Rules:
    - If whitelist is non-empty: ONLY whitelist entries are allowed (blacklist ignored)
    - If whitelist is empty: everything is allowed EXCEPT blacklist entries
    - Patterns use fnmatch glob syntax (*, ?, [seq])
"""

import argparse
import json
import http.server
import socket
import socketserver
import select
import sys
import os
import threading
from fnmatch import fnmatch


class EgressConfig:
    """Loads and evaluates egress filter rules."""

    def __init__(self, config_path):
        with open(config_path, "r") as f:
            data = json.load(f)
        self.whitelist = data.get("whitelist", [])
        self.blacklist = data.get("blacklist", [])
        self.use_whitelist = len(self.whitelist) > 0

    def is_allowed(self, hostname):
        """Check if a hostname is allowed by the filter rules."""
        hostname = hostname.lower()

        if self.use_whitelist:
            # Whitelist mode: only explicitly allowed hosts pass
            for pattern in self.whitelist:
                if fnmatch(hostname, pattern.lower()):
                    return True
            return False
        else:
            # Blacklist mode: everything allowed except blacklisted
            for pattern in self.blacklist:
                if fnmatch(hostname, pattern.lower()):
                    return False
            return True


class EgressProxyHandler(http.server.BaseHTTPRequestHandler):
    """Handles both CONNECT (HTTPS) and regular HTTP requests with filtering."""

    # Shared config — set by the server before starting
    egress_config = None

    def log_message(self, format, *args):
        """Suppress default logging to stderr."""
        pass

    def _extract_host(self, host_str):
        """Extract hostname from host:port or host string."""
        if host_str.startswith("["):
            # IPv6: [::1]:port
            bracket_end = host_str.find("]")
            if bracket_end != -1:
                return host_str[1:bracket_end]
            return host_str
        if ":" in host_str:
            return host_str.rsplit(":", 1)[0]
        return host_str

    def _check_and_block(self, hostname):
        """Check if hostname is allowed. Returns True if blocked."""
        if not self.egress_config.is_allowed(hostname):
            self.send_error(403, f"[claude-sandbox] BLOCKED: egress to '{hostname}' denied by filter")
            return True
        return False

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling with hostname filtering."""
        hostname = self._extract_host(self.path)
        port_str = self.path.rsplit(":", 1)[-1] if ":" in self.path else "443"

        try:
            port = int(port_str)
        except ValueError:
            port = 443

        if self._check_and_block(hostname):
            return

        try:
            upstream = socket.create_connection((hostname, port), timeout=30)
        except Exception as e:
            self.send_error(502, f"Cannot connect to {hostname}:{port}: {e}")
            return

        self.send_response(200, "Connection established")
        self.end_headers()

        # Tunnel data between client and upstream
        client_conn = self.connection
        conns = [client_conn, upstream]
        try:
            while True:
                readable, _, errored = select.select(conns, [], conns, 60)
                if errored:
                    break
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        raise ConnectionError("closed")
                    if sock is client_conn:
                        upstream.sendall(data)
                    else:
                        client_conn.sendall(data)
        except Exception:
            pass
        finally:
            upstream.close()

    def _proxy_request(self, method):
        """Forward an HTTP request with hostname filtering."""
        # Extract hostname from URL or Host header
        from urllib.parse import urlparse
        parsed = urlparse(self.path)
        hostname = parsed.hostname or self._extract_host(self.headers.get("Host", ""))

        if not hostname:
            self.send_error(400, "No hostname in request")
            return

        if self._check_and_block(hostname):
            return

        port = parsed.port or 80

        # Build the request to forward
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        try:
            upstream = socket.create_connection((hostname, port), timeout=30)
        except Exception as e:
            self.send_error(502, f"Cannot connect to {hostname}:{port}: {e}")
            return

        try:
            # Forward the request
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b""

            request_line = f"{method} {path} HTTP/1.1\r\n"
            headers = ""
            for key, value in self.headers.items():
                if key.lower() not in ("proxy-connection", "proxy-authorization"):
                    headers += f"{key}: {value}\r\n"
            headers += "\r\n"

            upstream.sendall((request_line + headers).encode() + body)

            # Read and forward the response
            response = b""
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                response += chunk

            self.wfile.write(response)
        except Exception:
            pass
        finally:
            upstream.close()

    def do_GET(self):
        self._proxy_request("GET")

    def do_POST(self):
        self._proxy_request("POST")

    def do_PUT(self):
        self._proxy_request("PUT")

    def do_DELETE(self):
        self._proxy_request("DELETE")

    def do_PATCH(self):
        self._proxy_request("PATCH")

    def do_HEAD(self):
        self._proxy_request("HEAD")

    def do_OPTIONS(self):
        self._proxy_request("OPTIONS")


class ThreadedProxyServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP proxy server."""
    daemon_threads = True
    allow_reuse_address = True


def find_free_port():
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description="claude-sandbox egress filter proxy")
    parser.add_argument("--config", required=True, help="Path to egress filter config JSON")
    parser.add_argument("--port", type=int, default=0, help="Port to listen on (0 = auto)")
    parser.add_argument("--bind", default="127.0.0.1", help="Address to bind to (default: 127.0.0.1)")
    parser.add_argument("--pidfile", help="Write PID to this file")
    parser.add_argument("--portfile", help="Write actual port to this file")
    args = parser.parse_args()

    config = EgressConfig(args.config)

    port = args.port if args.port > 0 else find_free_port()

    EgressProxyHandler.egress_config = config

    server = ThreadedProxyServer((args.bind, port), EgressProxyHandler)
    actual_port = server.server_address[1]

    # Write PID file
    if args.pidfile:
        with open(args.pidfile, "w") as f:
            f.write(str(os.getpid()))

    # Write port file (so the parent can read the actual port)
    if args.portfile:
        with open(args.portfile, "w") as f:
            f.write(str(actual_port))

    # Signal readiness on stdout
    print(f"READY:{actual_port}", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_shutdown()


if __name__ == "__main__":
    main()
