# NetShield-GNN emulated testbed (Mininet + Open vSwitch)

This testbed runs the NetShield closed loop on **real Linux networking**:
kernel TCP stacks, Open vSwitch forwarding, `tc` link shaping and real
OpenFlow 1.3 meter and drop rules. It complements the discrete-event
simulator: same topology, same device classes, same detector, same policy.

> Status: the agent loop (`netshield_agent.py`) and rule export are unit-tested
> offline against real captures. The Mininet run itself needs a Linux host and
> has not been executed on the Windows development machine.

## Requirements

Ubuntu 22.04 or 24.04 (a VM is fine), root access.

```bash
sudo apt-get install -y mininet openvswitch-switch tcpdump hping3 python3-pip
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt dpkt
```

Train the final models first (`python scripts/closed_loop_eval.py`), or copy
`results/research/predictions/final__all/` from another machine.

## Run

```bash
# 120 s run: 24 IoT hosts, 4 bots, UDP flood from t=30 s for 40 s,
# GraphSAGE agent installing real OpenFlow rules
sudo .venv/bin/python testbed/topology.py --bots 4 --attack udp --agent --model graphsage

# Same, but print rules instead of installing them
sudo .venv/bin/python testbed/topology.py --bots 4 --attack syn --agent --dry-run
```

Logs and artefacts are written to `/tmp/netshield/`:

| File | Content |
|---|---|
| `capture/win-*.pcap` | 5-second captures of the gateway uplink |
| `port_map.json` | host to (access switch, OpenFlow port) |
| `agent.log` | every rule command issued |
| `agent_actions.json` | the mitigation log in NetShield's schema |

Inspect installed rules while it runs:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows r0 | grep cookie=0x4e53
sudo ovs-ofctl -O OpenFlow13 dump-meters r0
```

## Replay offline

The agent can score any directory of captures without Mininet:

```bash
python testbed/netshield_agent.py --capture-dir path/to/captures \
    --port-map path/to/port_map.json --model graphsage --dry-run --once
```

## Safety

All hosts live in Mininet network namespaces on one machine. `lab_flood.py`
refuses any target outside `10.0.0.0/8`, the emulated address space.
