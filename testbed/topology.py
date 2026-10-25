#!/usr/bin/env python3
"""Mininet emulation of the NetShield tree topology on real Open vSwitch.

Run on Ubuntu 22.04/24.04 as root (see testbed/README.md):

    sudo python3 testbed/topology.py --bots 4 --attack udp --duration 120

Topology (mirrors config/network.yaml)::

    cloud (10.0.0.1) --20 Mbit/12 ms-- gw0 --50 Mbit/3 ms-- r0, r1, r2 (OVS)
                                                            |
                                   24 IoT hosts + N bots, 4 / 12 Mbit, 1.5 ms

Every switch runs in standalone NORMAL (learning) mode; NetShield never
needs an SDN controller for forwarding. Packets crossing the gateway uplink
are captured in 5-second files by tcpdump, and ``testbed/netshield_agent.py``
scores each file and installs OpenFlow meter/drop rules on the access-switch
port of every flagged device.

Everything runs inside Mininet's network namespaces on one machine. No
traffic leaves the emulated network.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEVICE_MIX = [("mqtt_sensor", 0.50), ("http_client", 0.20), ("tcp_uploader", 0.15),
              ("udp_streamer", 0.15)]


def build(net_cls, n_iot: int, n_bots: int, seed: int):
    from mininet.link import TCLink  # noqa: PLC0415
    from mininet.node import OVSSwitch  # noqa: PLC0415

    rng = random.Random(seed)
    net = net_cls(link=TCLink, switch=OVSSwitch, controller=None, autoSetMacs=True)
    cloud = net.addHost("cloud", ip="10.0.0.1/8")
    gw = net.addSwitch("gw0", failMode="standalone", protocols="OpenFlow13")
    net.addLink(cloud, gw, bw=20, delay="12ms", max_queue_size=120)
    routers = []
    for r in range(3):
        sw = net.addSwitch(f"r{r}", failMode="standalone", protocols="OpenFlow13")
        net.addLink(gw, sw, bw=50, delay="3ms", max_queue_size=200)
        routers.append(sw)
    hosts, roles = [], {}
    classes = [c for c, w in DEVICE_MIX for _ in range(round(w * 100))]
    for i in range(n_iot + n_bots):
        bot = i >= n_iot
        name = f"atk{i - n_iot}" if bot else f"iot{i}"
        h = net.addHost(name, ip=f"10.0.{3 + i // 200}.{10 + i % 200}/8")
        sw = routers[i % 3]
        net.addLink(h, sw, bw=12 if bot else 4, delay="1.5ms",
                    max_queue_size=100 if bot else 60, loss=0 if bot else 0.05)
        roles[name] = {"bot": bot, "class": rng.choice(classes), "switch": sw.name}
        hosts.append(h)
    return net, cloud, hosts, roles


def port_map(net, hosts, roles) -> dict:
    """Map every host to (access switch, OpenFlow port) for rule export."""
    out = {}
    for h in hosts:
        intf = h.defaultIntf()
        link = intf.link
        peer = link.intf2 if link.intf1 == intf else link.intf1
        out[h.name] = {"ip": h.IP(), "bridge": peer.node.name,
                       "port": peer.node.ports[peer], "bot": roles[h.name]["bot"]}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iot", type=int, default=24)
    ap.add_argument("--bots", type=int, default=4)
    ap.add_argument("--attack", choices=["none", "udp", "syn", "icmp", "http"], default="udp")
    ap.add_argument("--attack-start", type=float, default=30.0)
    ap.add_argument("--attack-duration", type=float, default=40.0)
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--rate-pps", type=int, default=1400)
    ap.add_argument("--capture-dir", default="/tmp/netshield/capture")
    ap.add_argument("--agent", action="store_true", help="Run the NetShield agent too.")
    ap.add_argument("--model", default="graphsage")
    ap.add_argument("--models-dir", default="results/research/predictions/final__all")
    ap.add_argument("--dry-run", action="store_true", help="Agent prints rules only.")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    from mininet.log import setLogLevel  # noqa: PLC0415
    from mininet.net import Mininet  # noqa: PLC0415

    setLogLevel("info")
    net, cloud, hosts, roles = build(Mininet, args.iot, args.bots, args.seed)
    net.start()
    capture = Path(args.capture_dir)
    capture.mkdir(parents=True, exist_ok=True)
    pmap = port_map(net, hosts, roles)
    (capture.parent / "port_map.json").write_text(json.dumps(pmap, indent=2))

    # Capture what crosses the gateway uplink, rotated every 5 s.
    uplink = net.get("gw0").intfList()[1].name
    os.system(f"tcpdump -i {uplink} -s 128 -G 5 -w {capture}/win-%s.pcap "
              f"> /tmp/netshield/tcpdump.log 2>&1 &")

    py = "python3"
    cloud.cmd(f"{py} {HERE}/traffic/server.py > /tmp/netshield/server.log 2>&1 &")
    time.sleep(1.0)
    for h in hosts:
        h.cmd(f"{py} {HERE}/traffic/iot_device.py --server 10.0.0.1 "
              f"--kind {roles[h.name]['class']} --duration {args.duration} "
              f"--seed {args.seed + hash(h.name) % 1000} > /tmp/netshield/{h.name}.log 2>&1 &")
    if args.agent:
        dry = "--dry-run" if args.dry_run else ""
        os.system(f"{py} {HERE}/netshield_agent.py --capture-dir {capture} "
                  f"--port-map {capture.parent / 'port_map.json'} --model {args.model} "
                  f"--models-dir {args.models_dir} {dry} > /tmp/netshield/agent.log 2>&1 &")
    if args.attack != "none":
        time.sleep(args.attack_start)
        for h in hosts:
            if roles[h.name]["bot"]:
                h.cmd(f"{py} {HERE}/traffic/lab_flood.py --target 10.0.0.1 "
                      f"--kind {args.attack} --pps {args.rate_pps} "
                      f"--duration {args.attack_duration} > /tmp/netshield/{h.name}-flood.log "
                      f"2>&1 &")
        time.sleep(max(0.0, args.duration - args.attack_start))
    else:
        time.sleep(args.duration)
    os.system("pkill -f tcpdump; pkill -f iot_device.py; pkill -f lab_flood.py; "
              "pkill -f netshield_agent.py")
    net.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
