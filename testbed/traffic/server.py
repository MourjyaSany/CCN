#!/usr/bin/env python3
"""Cloud-side services for the Mininet testbed (runs on the 'cloud' host).

TCP 8883 (MQTT-like sink), TCP 80/443 (HTTP-like request/response with a
bounded worker pool), UDP 5683 (CoAP-like sink). Lab use inside Mininet only.
"""

from __future__ import annotations

import socket
import socketserver
import threading


class Sink(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            while self.request.recv(65536):
                pass
        except OSError:
            pass


class Http(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            data = self.request.recv(4096)
            if data:
                body = b"x" * 1500
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                                     + str(len(body)).encode() + b"\r\n\r\n" + body)
        except OSError:
            pass


class Pool(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


def udp_sink(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        s.recvfrom(65536)


def main() -> None:
    servers = [Pool(("0.0.0.0", 8883), Sink), Pool(("0.0.0.0", 80), Http),
               Pool(("0.0.0.0", 443), Sink)]
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    udp_sink(5683)


if __name__ == "__main__":
    main()
