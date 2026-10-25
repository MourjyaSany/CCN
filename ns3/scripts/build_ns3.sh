#!/usr/bin/env bash
# =============================================================================
# Build and run the NetShield-GNN NS-3 model.
#
# This script is only useful on a host that already has a working NS-3
# installation. If you do not have one, you do not need one: the project runs
# its own discrete-event engine and labels every artefact accordingly.
#
#   export NS3_DIR=/path/to/ns-3-dev
#   bash ns3/scripts/build_ns3.sh                 # build only
#   bash ns3/scripts/build_ns3.sh --run           # build and run once
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODEL="$ROOT/ns3/simulations/netshield-topology.cc"
OUT="$ROOT/data/raw/ns3"

if [ -z "${NS3_DIR:-}" ]; then
  echo "ERROR: \$NS3_DIR is not set." >&2
  echo "       Install ns-3 (https://www.nsnam.org/releases/) and point" >&2
  echo "       NS3_DIR at the source tree, e.g." >&2
  echo "           export NS3_DIR=\$HOME/ns-3-dev" >&2
  echo >&2
  echo "       Without NS-3 the project still runs end to end using its own" >&2
  echo "       discrete-event engine; results are labelled" >&2
  echo "       'Python discrete-event emulation'." >&2
  exit 1
fi
[ -x "$NS3_DIR/ns3" ] || { echo "ERROR: $NS3_DIR/ns3 not found or not executable" >&2; exit 1; }

echo "==> Copying the model into the ns-3 scratch directory"
mkdir -p "$NS3_DIR/scratch"
cp "$MODEL" "$NS3_DIR/scratch/netshield-topology.cc"

echo "==> Building"
( cd "$NS3_DIR" && ./ns3 build )

if [ "${1:-}" = "--run" ]; then
  mkdir -p "$OUT"
  echo "==> Running (output -> $OUT)"
  ( cd "$NS3_DIR" && ./ns3 run \
      "netshield-topology --nIot=24 --nAttackers=4 --duration=90 \
       --attackStart=30 --attackDuration=30 --attackPps=1400 \
       --attackType=udp_flood --outputDir=$OUT" )
  echo
  echo "Flow records: $OUT/ns3_flows.csv"
  echo "Now set 'simulation.engine: ns3' in config/default.yaml so the project"
  echo "uses NS-3 and labels its artefacts 'NS-3 simulation'."
fi
