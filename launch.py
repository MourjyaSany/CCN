#!/usr/bin/env python3
"""NetShield-GNN one-click launcher.

    Windows : double-click start.bat
    Linux   : ./start.sh
    any OS  : python launch.py [--fresh] [--no-browser] [--port 8000] [--platform]

What it does, idempotently (re-running skips finished steps):

1. creates ``.venv`` and installs every Python dependency (CPU PyTorch,
   PyTorch Geometric, LightGBM, ONNX Runtime, ...) plus this package;
2. finds Node.js 20+, or downloads a portable copy into ``.tools/``, then
   installs and builds the operations console (``frontend/dist``);
3. makes sure trained detectors exist in ``models/``: it copies the final
   research models when present, otherwise it generates a quick corpus and
   trains every detector (about 5-10 minutes on a laptop);
4. starts the API + console on http://127.0.0.1:8000/app and, with
   ``--platform``, the streaming pipeline services, then opens the browser.

Press Ctrl+C to stop all servers.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
import webbrowser
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
TOOLS = ROOT / ".tools"
WIN = os.name == "nt"
PY = VENV / ("Scripts/python.exe" if WIN else "bin/python")
NODE_VERSION = "20.18.1"
FINAL_MODELS = ROOT / "results/research/predictions/final__all"
DETECTORS = ("threshold", "autoencoder", "random_forest", "lightgbm", "gru_seq", "gat",
             "egraphsage", "graphsage", "temporal_gnn")


def step(msg: str) -> None:
    print(f"\n\033[1;34m==>\033[0m \033[1m{msg}\033[0m", flush=True)


def run(cmd: list[str], **kw) -> None:
    print("   $", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], check=True, cwd=kw.pop("cwd", ROOT), **kw)


def stamp(name: str) -> Path:
    return VENV / f".netshield-{name}.done"


# --------------------------------------------------------------------------- #
def ensure_python(fresh: bool) -> None:
    if sys.version_info < (3, 10):
        sys.exit("Python 3.10 or newer is required (found %s)." % platform.python_version())
    if fresh and VENV.exists():
        shutil.rmtree(VENV)
    if not PY.exists():
        step("Creating virtual environment (.venv)")
        run([sys.executable, "-m", "venv", str(VENV)])
    if stamp("deps").exists() and stamp("deps").read_text() == _deps_hash():
        print("   Python dependencies already installed.")
        return
    step("Installing Python dependencies (first run takes a few minutes)")
    run([PY, "-m", "pip", "install", "--upgrade", "pip", "-q"])
    run([PY, "-m", "pip", "install", "-q", "torch", "--index-url",
         "https://download.pytorch.org/whl/cpu"])
    run([PY, "-m", "pip", "install", "-q", "-r", "requirements.txt"])
    run([PY, "-m", "pip", "install", "-q", "-e", "."])
    stamp("deps").write_text(_deps_hash())


def _deps_hash() -> str:
    import hashlib

    return hashlib.sha1((ROOT / "requirements.txt").read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
def find_node() -> Path | None:
    for cand in (shutil.which("node"),):
        if cand:
            try:
                out = subprocess.run([cand, "--version"], capture_output=True, text=True).stdout
                if int(out.strip().lstrip("v").split(".")[0]) >= 18:
                    return Path(cand).parent
            except (OSError, ValueError):
                pass
    local = next(TOOLS.glob("node-v*"), None) if TOOLS.exists() else None
    if local:
        return local if WIN else local / "bin"
    return None


def download_node() -> Path:
    system = {"Windows": "win", "Linux": "linux", "Darwin": "darwin"}[platform.system()]
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"
    ext = "zip" if WIN else "tar.xz"
    name = f"node-v{NODE_VERSION}-{system}-{arch}"
    url = f"https://nodejs.org/dist/v{NODE_VERSION}/{name}.{ext}"
    step(f"Downloading portable Node.js {NODE_VERSION}")
    TOOLS.mkdir(exist_ok=True)
    archive = TOOLS / f"{name}.{ext}"
    urllib.request.urlretrieve(url, archive)
    if WIN:
        with zipfile.ZipFile(archive) as z:
            z.extractall(TOOLS)
    else:
        import tarfile

        with tarfile.open(archive) as t:
            t.extractall(TOOLS)
    archive.unlink()
    return TOOLS / name if WIN else TOOLS / name / "bin"


def ensure_frontend(skip: bool) -> None:
    dist = ROOT / "frontend/dist/index.html"
    if skip and dist.exists():
        return
    node_dir = find_node() or download_node()
    env = {**os.environ, "PATH": f"{node_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
    npm = str(node_dir / ("npm.cmd" if WIN else "npm"))
    front = ROOT / "frontend"
    if not (front / "node_modules").exists():
        step("Installing console dependencies (npm)")
        run([npm, "ci" if (front / "package-lock.json").exists() else "install",
             "--no-audit", "--no-fund"], cwd=front, env=env, shell=WIN)
    newest_src = max(p.stat().st_mtime for p in (front / "src").rglob("*") if p.is_file())
    if not dist.exists() or dist.stat().st_mtime < newest_src:
        step("Building the operations console")
        run([npm, "run", "build"], cwd=front, env=env, shell=WIN)
    else:
        print("   Console already built.")


# --------------------------------------------------------------------------- #
def ensure_models() -> None:
    models = ROOT / "models"
    have = [d for d in DETECTORS if (models / d / "manifest.json").exists()]
    if FINAL_MODELS.exists():
        final = [d for d in DETECTORS if (FINAL_MODELS / d / "manifest.json").exists()]
        missing = [d for d in final if d not in have]
        if missing:
            step(f"Installing research-trained detectors: {', '.join(missing)}")
            for d in missing:
                shutil.copytree(FINAL_MODELS / d, models / d, dirs_exist_ok=True)
            have += missing
    if len(have) >= 3:
        print(f"   Detectors ready: {', '.join(sorted(have))}")
        return
    step("No trained detectors found: generating a quick corpus and training")
    run([PY, "scripts/generate_dataset.py", "--quick", "--reuse", "--log-level", "WARNING"])
    run([PY, "scripts/train_models.py", "--log-level", "WARNING", "--detectors", "threshold",
         "random_forest", "lightgbm", "autoencoder", "graphsage", "egraphsage",
         "--set", "detection.graphsage.epochs=60"])


# --------------------------------------------------------------------------- #
def wait_http(url: str, timeout: float = 90.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except OSError:
            time.sleep(1.0)
    return False


def start_servers(port: int, with_platform: bool, browser: bool) -> None:
    procs: list[subprocess.Popen] = []
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    step(f"Starting API and console on http://127.0.0.1:{port}/app")
    env["NETSHIELD_PORT"] = str(port)
    procs.append(subprocess.Popen([str(PY), "scripts/serve.py", "--host", "127.0.0.1",
                                   "--port", str(port)], cwd=ROOT, env=env))
    if with_platform and not os.environ.get("NETSHIELD_BUS", "").startswith("redis"):
        print("   --platform needs a Redis bus: set NETSHIELD_BUS=redis://host:6379/0, or run the\n"
              "   full stack with: docker compose -f deploy/docker-compose.platform.yml up")
        with_platform = False
    if with_platform:
        step("Starting streaming pipeline services (Redis Streams bus)")
        for i, role in enumerate(("features", "inference", "policy")):
            procs.append(subprocess.Popen(
                [str(PY), "-m", "netshield.platform.service", role, "--models", "models",
                 "--metrics-port", str(9101 + i)], cwd=ROOT, env=env))
    if wait_http(f"http://127.0.0.1:{port}/api/health"):
        print(f"\n   \033[1;32mReady.\033[0m  Console : http://127.0.0.1:{port}/app")
        print(f"            API docs: http://127.0.0.1:{port}/docs")
        print(f"            Metrics : http://127.0.0.1:{port}/metrics")
        print("\n   Press Ctrl+C to stop.\n", flush=True)
        if browser:
            webbrowser.open(f"http://127.0.0.1:{port}/app/")
    else:
        print("   The API did not answer within 90 s; check the output above.")
    try:
        while all(p.poll() is None for p in procs[:1]):
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        print("   Servers stopped.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Set up and start NetShield-GNN.")
    ap.add_argument("--fresh", action="store_true", help="Recreate the virtual environment.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--platform", action="store_true",
                    help="Also start the streaming pipeline services.")
    ap.add_argument("--setup-only", action="store_true", help="Install and train, do not serve.")
    ap.add_argument("--skip-frontend-build", action="store_true")
    ap.add_argument("--ns3", action="store_true",
                    help="Also set up the NS-3 primary engine (WSL2 + NS-3 build; "
                         "needs administrator approval once).")
    args = ap.parse_args()
    os.chdir(ROOT)
    print("NetShield-GNN launcher  (Ctrl+C to stop at any time)")
    ensure_python(args.fresh)
    ensure_frontend(args.skip_frontend_build)
    ensure_models()
    if args.ns3:
        step("Setting up the NS-3 primary engine")
        run([PY, "scripts/setup_ns3.py"])
    if args.setup_only:
        step("Setup complete")
        return 0
    start_servers(args.port, args.platform, not args.no_browser)
    return 0


if __name__ == "__main__":
    sys.exit(main())
