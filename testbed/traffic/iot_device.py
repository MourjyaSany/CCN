#!/usr/bin/env python3
"""Legitimate IoT device behaviour for the Mininet testbed.

The four device classes match the simulator (src/netshield/traffic/
applications.py): periodic MQTT-like publishes on a persistent TCP session,
HTTP-like request/response transactions, periodic bulk uploads, and a
constant-bitrate UDP stream. Lab use inside Mininet only.
"""

from __future__ import annotations

import argparse
import random
import socket
import time


def mqtt(server: str, rng: random.Random, end: float) -> None:
    while time.time() < end:
        try:
            with socket.create_connection((server, 8883), timeout=5) as s:
                while time.time() < end:
                    s.sendall(b"m" * rng.randint(48, 220))
                    time.sleep(2.0 * rng.uniform(0.7, 1.3))
        except OSError:
            time.sleep(rng.uniform(1, 4))


def http(server: str, rng: random.Random, end: float) -> None:
    while time.time() < end:
        try:
            with socket.create_connection((server, 80), timeout=5) as s:
                s.sendall(b"GET /api HTTP/1.1\r\n\r\n" + b"q" * rng.randint(160, 620))
                s.recv(4096)
        except OSError:
            pass
        time.sleep(6.0 * rng.uniform(0.5, 1.5))


def bulk(server: str, rng: random.Random, end: float) -> None:
    while time.time() < end:
        time.sleep(20.0 * rng.uniform(0.6, 1.4))
        try:
            with socket.create_connection((server, 443), timeout=10) as s:
                s.sendall(b"b" * rng.randint(20000, 120000))
        except OSError:
            pass


def udp(server: str, rng: random.Random, end: float) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < end:
        s.sendto(b"c" * rng.randint(200, 400), (server, 5683))
        time.sleep(0.08 * rng.uniform(0.8, 1.2))


KINDS = {"mqtt_sensor": mqtt, "http_client": http, "tcp_uploader": bulk, "udp_streamer": udp}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--kind", choices=sorted(KINDS), required=True)
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    time.sleep(rng.uniform(0, 2))
    KINDS[args.kind](args.server, rng, time.time() + args.duration)


if __name__ == "__main__":
    main()
