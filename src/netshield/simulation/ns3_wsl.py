"""Run the NetShield NS-3 model inside WSL and detect its availability.

NS-3 is the primary simulation engine. On Windows it runs inside a WSL2 Linux
distribution, where NS-3 is fully supported (native Windows/MinGW builds of
NS-3's shared libraries fail to initialise at load time). This module is the
thin invocation layer: it locates the built model, converts Windows paths to
their ``/mnt`` equivalents, runs the model over a scenario spec, and returns
the paths to the CSV/JSON output -- which the Windows side reads natively
because the model writes into a Windows-visible directory.

Nothing here constructs traffic or touches a network interface; it only
launches the NS-3 executable, which runs entirely inside its own simulated
topology.

Configuration (environment overrides, else these defaults):
    NETSHIELD_WSL_DISTRO   Ubuntu-24.04
    NETSHIELD_NS3_DIR      /opt/ns-3.48
    NETSHIELD_NS3_USER     ns
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)

WSL_DISTRO = os.environ.get("NETSHIELD_WSL_DISTRO", "Ubuntu-24.04")
NS3_DIR = os.environ.get("NETSHIELD_NS3_DIR", "/opt/ns-3.48")
NS3_USER = os.environ.get("NETSHIELD_NS3_USER", "ns")
EXE_REL = "build/scratch/netshield/ns3.48-netshield-sim-optimized"
NETANIM_BIN = os.environ.get("NETSHIELD_NETANIM", "/home/ns/netanim/build/netanim")
ENGINE_NS3 = "ns3-simulation"


class NS3Unavailable(RuntimeError):
    """Raised when the NS-3 model cannot be located or run."""


@dataclass(slots=True)
class WSLNs3:
    """Result of probing for a runnable NS-3 model in WSL."""

    available: bool
    distro: str = ""
    ns3_dir: str = ""
    version: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"available": self.available, "distro": self.distro,
                "ns3_dir": self.ns3_dir, "version": self.version, "reason": self.reason}


def _wsl() -> str | None:
    return shutil.which("wsl.exe") or shutil.which("wsl")


def win_to_wsl(path: str | Path) -> str:
    """Convert a Windows path to its WSL ``/mnt/<drive>/...`` form.

    Paths already in POSIX form (e.g. ``/opt/...``) are returned unchanged.
    """
    text = str(path)
    if text.startswith("/"):
        return text
    pw = PureWindowsPath(text)
    drive = pw.drive.rstrip(":").lower()
    rest = "/".join(pw.parts[1:]) if pw.drive else "/".join(pw.parts)
    return f"/mnt/{drive}/{rest}" if drive else "/" + rest


def _run(args: list[str], timeout: float, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise NS3Unavailable(
            f"command failed ({proc.returncode}): {' '.join(args[:4])} ...\n"
            f"{(proc.stderr or proc.stdout or '').strip()[:400]}")
    return proc


def _wsl_bash(script: str, timeout: float, check: bool = True) -> subprocess.CompletedProcess:
    wsl = _wsl()
    if not wsl:
        raise NS3Unavailable("wsl.exe is not on PATH")
    return _run([wsl, "-d", WSL_DISTRO, "-u", NS3_USER, "--", "bash", "-lc", script],
                timeout, check)


def detect(timeout_s: float = 30.0) -> WSLNs3:
    """Probe for a runnable NS-3 model. Never raises; reports the reason."""
    wsl = _wsl()
    if not wsl:
        return WSLNs3(False, reason="wsl.exe not found on PATH")
    try:
        listing = _run([wsl, "--list", "--quiet"], timeout_s, check=False)
        distros = (listing.stdout or "").replace("\x00", "").split()
        if WSL_DISTRO not in distros:
            return WSLNs3(False, reason=f"WSL distro {WSL_DISTRO!r} not installed "
                          f"(have: {', '.join(distros) or 'none'})")
        probe = _wsl_bash(
            f"test -x {NS3_DIR}/{EXE_REL} && echo FOUND || echo MISSING; "
            f"cat {NS3_DIR}/VERSION 2>/dev/null", timeout_s, check=False)
        out = (probe.stdout or "").strip().splitlines()
        if not out or out[0].strip() != "FOUND":
            return WSLNs3(False, distro=WSL_DISTRO,
                          reason=f"NS-3 model not built at {NS3_DIR}/{EXE_REL}")
        version = out[1].strip() if len(out) > 1 else "3.48"
        return WSLNs3(True, distro=WSL_DISTRO, ns3_dir=NS3_DIR,
                      version=f"ns-{version}")
    except (subprocess.TimeoutExpired, NS3Unavailable) as exc:
        return WSLNs3(False, reason=str(exc))


def run_model(spec_win_path: str | Path, timeout_s: float = 3600.0) -> dict[str, Any]:
    """Run the NS-3 model over a scenario spec written at *spec_win_path*.

    The spec's ``output_dir`` must already name a Windows directory; the model
    writes ``ns3_flows.csv``, ``ns3_windows.csv`` and ``ns3_run.json`` there.

    Returns:
        ``{"returncode", "stdout", "stderr", "wall_s"}``.
    """
    spec_wsl = win_to_wsl(spec_win_path)
    exe = f"{NS3_DIR}/{EXE_REL}"
    script = (f"test -f '{spec_wsl}' || {{ echo 'spec not found' >&2; exit 2; }}; "
              f"'{exe}' --spec='{spec_wsl}'")
    import time

    started = time.perf_counter()
    proc = _wsl_bash(script, timeout_s, check=False)
    wall = time.perf_counter() - started
    if proc.returncode != 0 or "NS3_OUTPUT_OK" not in (proc.stdout or ""):
        raise NS3Unavailable(
            f"NS-3 model run failed (rc={proc.returncode}):\n"
            f"{(proc.stderr or proc.stdout or '').strip()[:600]}")
    return {"returncode": proc.returncode, "stdout": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(), "wall_s": round(wall, 2)}


def netanim_available() -> bool:
    """True when the NetAnim GUI binary is present in WSL."""
    wsl = _wsl()
    if not wsl:
        return bool(shutil.which("netanim"))
    try:
        probe = _wsl_bash(f"test -x {NETANIM_BIN} && echo OK", 20.0, check=False)
        return "OK" in (probe.stdout or "")
    except (subprocess.TimeoutExpired, NS3Unavailable):
        return False


def launch_netanim(trace_win_path: str | Path) -> dict[str, Any]:
    """Open the NetAnim GUI on a trace file (a desktop window via WSLg).

    Args:
        trace_win_path: Path to the NetAnim ``.xml`` trace (Windows or WSL).

    Returns:
        ``{"launched": bool, "pid": int|None, "reason": str}``.
    """
    if not netanim_available():
        return {"launched": False, "pid": None,
                "reason": f"NetAnim GUI not found at {NETANIM_BIN}"}
    trace = win_to_wsl(trace_win_path)
    # Copy the trace to WSL-local storage first: NetAnim scrubs the file
    # continuously, and reading a multi-MB trace over the /mnt mount is slow.
    # setsid detaches the GUI so it keeps running after this call returns.
    script = (f"test -f '{trace}' || {{ echo 'trace not found' >&2; exit 2; }}; "
              f"mkdir -p ~/.netshield-anim; N=$(basename $(dirname '{trace}')); "
              f"L=~/.netshield-anim/$N.xml; cp -f '{trace}' \"$L\"; "
              f"export DISPLAY=${{DISPLAY:-:0}}; export QT_QPA_PLATFORM=xcb; "
              f"setsid {NETANIM_BIN} \"$L\" >/tmp/netanim.log 2>&1 "
              f"< /dev/null & disown; sleep 1; pgrep -n -f netanim/build/netanim "
              f"| sed 's/^/PID=/'")
    try:
        proc = _wsl_bash(script, 30.0, check=False)
    except subprocess.TimeoutExpired:
        return {"launched": False, "pid": None, "reason": "launch timed out"}
    out = (proc.stdout or "")
    if proc.returncode != 0 or "PID=" not in out:
        return {"launched": False, "pid": None,
                "reason": (proc.stderr or out).strip()[:200] or "launch failed"}
    pid = None
    for line in out.splitlines():
        if line.startswith("PID="):
            digits = line[4:].strip()
            pid = int(digits) if digits.isdigit() else None
    return {"launched": True, "pid": pid, "reason": "", "trace": trace}


def environment_report() -> dict[str, Any]:
    """Return a probe of the WSL/NS-3 environment for the dashboard/CLI."""
    probe = detect()
    report = probe.to_dict()
    report["netanim_available"] = netanim_available() if probe.available else False
    if probe.available:
        try:
            info = _wsl_bash("nproc; uname -r", 20.0, check=False)
            lines = (info.stdout or "").split()
            report["wsl_cores"] = lines[0] if lines else "?"
            report["wsl_kernel"] = lines[1] if len(lines) > 1 else "?"
        except Exception:  # noqa: BLE001
            pass
    return report
