#!/usr/bin/env bash
# Steps 1-4 downstream jobs: closed loop, adversary, hardening, real captures.
set -e
PY=.venv/Scripts/python
CAP="--set detection.graphsage.epochs=120 --set detection.graphsage.patience=20"
$PY scripts/adversary_eval.py search --log-level WARNING
$PY scripts/adversary_eval.py harden --log-level WARNING
$PY scripts/adversary_eval.py report --log-level WARNING
$PY scripts/real_data_eval.py --captures data/external/ciciot2023/*.pcap --max-packets 1500000 --log-level WARNING
