#!/usr/bin/env python3
"""Lab-only flood generator for the isolated Mininet testbed.

Delegates to ``hping3`` (installed in the lab VM) for SYN and ICMP floods and
uses a plain UDP socket for UDP floods. It refuses any target outside the
testbed's 10.0.0.0/8 emulated address space, so it cannot be pointed at a
real network by accident.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import subprocess
import time

LAB_NET = ipaddress.ip_network("10.0.0.0/8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--kind", choices=["udp", "syn", "icmp", "http"], default="udp")
    ap.add_argument("--pps", type=int, default=1400)
    ap.add_argument("--duration", type=float, default=40.0)
    ap.add_argument("--port", type=int, default=8883)
    args = ap.parse_args()
    if ipaddress.ip_address(args.target) not in LAB_NET:
        raise SystemExit(f"refusing target {args.target}: outside the lab network {LAB_NET}")

    end = time.time() + args.duration
    if args.kind == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        gap = 1.0 / max(1, args.pps)
        payload = b"\x00" * 470
        while time.time() < end:
            s.sendto(payload, (args.target, args.port))
            time.sleep(gap)
    elif args.kind == "http":
        while time.time() < end:
            try:
                with socket.create_connection((args.target, 80), timeout=2) as c:
                    c.sendall(b"GET / HTTP/1.1\r\n\r\n")
                    c.recv(2048)
            except OSError:
                pass
            time.sleep(1.0 / max(1, args.pps))
    else:
        flag = ["-S", "-p", "80"] if args.kind == "syn" else ["--icmp"]
        interval = f"u{max(1, int(1e6 / max(1, args.pps)))}"
        proc = subprocess.Popen(["hping3", *flag, "-i", interval, args.target],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(args.duration)
        proc.terminate()


if __name__ == "__main__":
    main()
