#!/usr/bin/env python3
"""Set up NS-3 as the primary engine.

NS-3 is NetShield-GNN's primary simulation engine. On Linux it is used
directly; on Windows it runs inside WSL2, because native-Windows builds of
NS-3's shared libraries fail to initialise at load time. This script makes the
engine runnable from a clean machine:

  * On Windows: ensures WSL2 + an Ubuntu distro exist, installs the build
    toolchain inside it, downloads and builds NS-3, compiles the NetShield
    model, and verifies it runs.
  * On Linux: installs nothing it cannot, downloads and builds NS-3 under
    ``$NETSHIELD_NS3_DIR`` (default /opt/ns-3.48) and compiles the model.

Re-running is cheap: each step is skipped when already done. Installing the
WSL feature and the distro needs administrator rights once (the script
requests elevation for just those two steps).

    python scripts/setup_ns3.py                # full setup
    python scripts/setup_ns3.py --check        # report status only
    python scripts/setup_ns3.py --rebuild      # rebuild the model only
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

NS3_VERSION = "3.48"
DISTRO = os.environ.get("NETSHIELD_WSL_DISTRO", "Ubuntu-24.04")
NS3_DIR = os.environ.get("NETSHIELD_NS3_DIR", "/opt/ns-3.48")
NS3_USER = os.environ.get("NETSHIELD_NS3_USER", "ns")
MODULES = "core;network;internet;point-to-point;applications;traffic-control;mobility;netanim"
NETANIM_DIR = os.environ.get("NETSHIELD_NETANIM_DIR", "/home/ns/netanim")
REPO = Path(__file__).resolve().parents[1]
MODEL_DIR = REPO / "ns3" / "netshield"
WIN = os.name == "nt"


def _say(msg: str) -> None:
    print(f"\033[1;34m==>\033[0m {msg}", flush=True)


def _ps(cmd: str, timeout: float = 900, elevated: bool = False) -> int:
    """Run a PowerShell command (optionally elevated); return the exit code."""
    if elevated:
        inner = cmd.replace('"', '`"')
        cmd = (f"$p = Start-Process powershell -ArgumentList "
               f"'-NoProfile','-Command','{inner}' -Verb RunAs -PassThru -WindowStyle Hidden; "
               f"$p.WaitForExit({int(timeout * 1000)}); exit $p.ExitCode")
    proc = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], timeout=timeout)
    return proc.returncode


def _wsl(script: str, timeout: float = 3600, user: str = NS3_USER, check: bool = True):
    args = ["wsl.exe", "-d", DISTRO, "-u", user, "--", "bash", "-lc", script]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace")
    if check and proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"WSL step failed (rc={proc.returncode})")
    return proc


# --------------------------------------------------------------------------- #
# the build recipe (shared by WSL and native Linux)
# --------------------------------------------------------------------------- #
INSTALL_DEPS = ("export DEBIAN_FRONTEND=noninteractive; "
                "apt-get update -q && apt-get install -y -q "
                "g++ cmake ninja-build python3 python3-dev tar wget bzip2 ca-certificates "
                # for building the NetAnim GUI from source:
                "git qtbase5-dev qt5-qmake qtbase5-dev-tools libqt5core5a libxml2-dev make")

def _build_script(model_src: str) -> str:
    return (
        f"set -e; "
        f"if [ ! -x {NS3_DIR}/ns3 ]; then "
        f"  sudo mkdir -p $(dirname {NS3_DIR}); cd $(dirname {NS3_DIR}); "
        f"  wget -q https://www.nsnam.org/releases/ns-{NS3_VERSION}.tar.bz2 -O /tmp/ns3.tar.bz2; "
        f"  sudo tar xjf /tmp/ns3.tar.bz2 -C $(dirname {NS3_DIR}); rm /tmp/ns3.tar.bz2; "
        f"  sudo chown -R {NS3_USER}:{NS3_USER} {NS3_DIR}; "
        f"fi; "
        f"mkdir -p {NS3_DIR}/scratch/netshield; "
        f"cp {model_src}/netshield-sim.cc {model_src}/netshield-trace.h {NS3_DIR}/scratch/netshield/; "
        f"cd {NS3_DIR}; "
        f"./ns3 configure --build-profile=optimized --enable-modules='{MODULES}' "
        f"  --disable-examples --disable-tests --disable-python-bindings "
        f"  -- -DCMAKE_CXX_FLAGS=-DNETSHIELD_ANIM >/tmp/ns3cfg.log 2>&1; "
        f"./ns3 build netshield-sim >/tmp/ns3build.log 2>&1; "
        f"test -x {NS3_DIR}/build/scratch/netshield/ns3.{NS3_VERSION}-netshield-sim-optimized "
        f"  || {{ echo NS3_BUILD_FAILED; tail -5 /tmp/ns3build.log; exit 1; }}; "
        # NetAnim GUI (built once, from source, with Qt5).
        f"if [ ! -x {NETANIM_DIR}/build/netanim ]; then "
        f"  git clone -q https://gitlab.com/nsnam/netanim.git {NETANIM_DIR} 2>/dev/null || true; "
        f"  mkdir -p {NETANIM_DIR}/build && cd {NETANIM_DIR}/build && "
        f"  cmake .. -DCMAKE_BUILD_TYPE=Release >/tmp/na_cmake.log 2>&1 && "
        f"  make -j$(nproc) >/tmp/na_make.log 2>&1 || echo NETANIM_BUILD_FAILED; "
        f"fi; "
        f"echo BUILD_OK")


def _model_src_wsl() -> str:
    from netshield.simulation.ns3_wsl import win_to_wsl  # noqa: PLC0415

    return win_to_wsl(MODEL_DIR)


def check() -> bool:
    sys.path.insert(0, str(REPO / "src"))
    from netshield.simulation.ns3_wsl import environment_report  # noqa: PLC0415

    report = environment_report()
    _say("NS-3 engine status")
    for k, v in report.items():
        print(f"    {k}: {v}")
    return bool(report.get("available"))


def setup_windows(rebuild: bool) -> int:
    sys.path.insert(0, str(REPO / "src"))
    # 1. WSL feature
    status = subprocess.run(["wsl.exe", "--status"], capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
    if "Default Version" not in (status.stdout or ""):
        _say("Installing the WSL2 feature (needs administrator approval once)")
        _ps("wsl.exe --install --no-distribution", elevated=True, timeout=300)
    # 2. distro
    listing = subprocess.run(["wsl.exe", "--list", "--quiet"], capture_output=True,
                             text=True, encoding="utf-8", errors="replace")
    if DISTRO not in (listing.stdout or "").replace("\x00", ""):
        _say(f"Installing the {DISTRO} distribution (administrator approval once)")
        _ps(f"wsl.exe --install -d {DISTRO} --no-launch", elevated=True, timeout=600)
    # 3. build user
    _wsl(f"id {NS3_USER} >/dev/null 2>&1 || useradd -m -s /bin/bash {NS3_USER}; "
         f"usermod -aG sudo {NS3_USER}; "
         f"echo '{NS3_USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/netshield-ns3",
         user="root")
    # 4. deps
    _say("Installing the build toolchain inside WSL")
    _wsl(INSTALL_DEPS, user="root", timeout=1200)
    # 5. build ns-3 + model
    if rebuild:
        _wsl(f"rm -rf {NS3_DIR}/cmake-cache {NS3_DIR}/build", check=False)
    _say(f"Building NS-3 {NS3_VERSION} and the NetShield model (several minutes)")
    out = _wsl(_build_script(_model_src_wsl()), timeout=2400)
    if "BUILD_OK" not in (out.stdout or ""):
        print(out.stdout[-1500:])
        raise SystemExit("NS-3 build did not complete")
    _say("NS-3 is ready. Verifying...")
    return 0 if check() else 1


def setup_linux(rebuild: bool) -> int:
    def run(script: str, timeout: float = 2400) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", "-lc", script], timeout=timeout)

    _say("Installing the build toolchain (sudo)")
    run("sudo " + INSTALL_DEPS, timeout=1200)
    if rebuild:
        run(f"rm -rf {NS3_DIR}/cmake-cache {NS3_DIR}/build")
    _say(f"Building NS-3 {NS3_VERSION} and the NetShield model")
    proc = subprocess.run(["bash", "-lc", _build_script(str(MODEL_DIR))],
                          capture_output=True, text=True, timeout=2400)
    print(proc.stdout[-800:])
    return 0 if "BUILD_OK" in (proc.stdout or "") else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="Report status and exit.")
    ap.add_argument("--rebuild", action="store_true", help="Force a clean rebuild.")
    args = ap.parse_args()
    if args.check:
        return 0 if check() else 1
    if WIN:
        return setup_windows(args.rebuild)
    return setup_linux(args.rebuild)


if __name__ == "__main__":
    raise SystemExit(main())
