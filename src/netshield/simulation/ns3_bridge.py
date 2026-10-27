"""NS-3 detection and invocation, with an explicit, labelled fallback.

Design contract
---------------
The project must never present emulated numbers as NS-3 numbers. Therefore:

* :func:`detect_ns3` performs a *real* capability probe (binary, source tree and
  Python bindings). It never guesses.
* :func:`resolve_engine` maps the configured ``simulation.engine`` policy plus
  the probe result onto a concrete engine, and returns the exact provenance
  label that is stamped into every artefact this run produces
  (``engine`` field of ``run.json``, the title of every figure, and the
  ``engine`` column of every metrics CSV).
* If NS-3 is requested but unavailable, the run either falls back with a loud
  warning (``engine: auto``) or fails outright (``engine: ns3``). It never
  silently pretends.

The NS-3 model source lives in ``ns3/simulations/netshield-topology.cc`` and is
built by ``ns3/scripts/build_ns3.sh``. On a machine with a working ns-3
installation, ``simulation.engine: ns3`` compiles and runs that model and parses
its FlowMonitor output through :func:`parse_ns3_flowmonitor`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..utils.logging_utils import get_logger
from ..utils.paths import repo_root, resolve

_LOG = get_logger(__name__)

#: Provenance labels stamped onto every artefact.
ENGINE_NS3: str = "ns3-simulation"
ENGINE_PYTHON: str = "python-des-emulation"

#: Human-readable descriptions used in figures and reports.
ENGINE_LABELS: dict[str, str] = {
    ENGINE_NS3: "NS-3 simulation",
    ENGINE_PYTHON: "Python discrete-event emulation",
}


class NS3Unavailable(RuntimeError):
    """Raised when NS-3 is explicitly required but cannot be located."""


#: WSL distributions are searched for an ns-3 tree at these paths (globs are
#: expanded inside the distribution). ``$NS3_WSL_DIR`` overrides the list.
#:
#: ``$HOME`` is reliable here only because :data:`WSL_PATH_PREAMBLE` repairs
#: the distribution's PATH first; without that the login shell cannot run the
#: binaries that populate it.
DEFAULT_WSL_NS3_GLOBS: tuple[str, ...] = (
    "$HOME/ns3/ns-allinone-*/ns-3.*",
    "$HOME/ns-allinone-*/ns-3.*",
    "/opt/ns3/ns-allinone-*/ns-3.*",
)


@dataclass(slots=True)
class NS3Availability:
    """Result of probing the host for a usable NS-3 installation.

    Attributes:
        available: True only when a runnable NS-3 was actually found.
        method: ``"ns3-cli"``, ``"wsl-ns3-cli"``, ``"python-bindings"`` or ``""``.
        version: Reported NS-3 version string, when obtainable.
        ns3_dir: Path to the NS-3 source/build tree, when found. For the WSL
            method this is a path *inside the distribution*, not a Windows path.
        detail: Human-readable explanation, always populated.
        checks: Per-probe outcomes, surfaced by ``scripts/check_env.py``.
        distro: WSL distribution name when ``method == "wsl-ns3-cli"``.
    """

    available: bool
    method: str = ""
    version: str = ""
    ns3_dir: str = ""
    detail: str = ""
    checks: dict[str, str] = field(default_factory=dict)
    distro: str = ""

    @property
    def via_wsl(self) -> bool:
        """True when NS-3 runs inside a WSL distribution."""
        return self.method == "wsl-ns3-cli"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the probe."""
        return {
            "available": self.available,
            "method": self.method,
            "version": self.version,
            "ns3_dir": self.ns3_dir,
            "detail": self.detail,
            "checks": dict(self.checks),
            "distro": self.distro,
        }


def _wsl_env() -> None:
    """Prepare this process's environment for a ``wsl.exe`` call.

    Returns ``None`` deliberately, so callers pass ``env=None`` to
    :func:`subprocess.run` and the child *inherits* the environment.

    Handing ``wsl.exe`` an explicit ``dict(os.environ)`` looks harmless and is
    not: the Windows ``PATH`` is forwarded into the distribution and replaces
    the Linux one, after which nothing in ``/usr/bin`` resolves any more.
    Shell builtins still work, so the failure is silent - ``getent``, ``id``
    and ``basename`` simply produce empty output and a perfectly good ns-3
    installation is reported as missing.

    Setting ``WSL_UTF8`` on our own environment (so the child inherits it)
    gets UTF-8 output without disturbing anything else.
    """
    os.environ.setdefault("WSL_UTF8", "1")
    return None


#: Prepended to every script sent into a WSL distribution.
#:
#: WSL interop merges the *Windows* PATH into the distribution's PATH. When the
#: parent process was itself launched from a POSIX-style shell on Windows (Git
#: Bash, MSYS2), that merged value can shadow the real Linux PATH, and then
#: ``getent``, ``id``, ``cut`` and ``basename`` are all "command not found"
#: (exit 126/127) while shell builtins still work - a silent, very confusing
#: failure. Pinning a known-good PATH first makes every script deterministic
#: regardless of how the caller was started.
WSL_PATH_PREAMBLE: str = (
    "export PATH=$HOME/tools/cmake/bin:$HOME/.local/bin:"
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "
)


def wsl_argv(distro: str, script: str) -> list[str]:
    """Return the argv running *script* inside WSL distribution *distro*.

    The script is base64-encoded and decoded inside the distribution rather
    than passed as literal shell text. This is not defensiveness for its own
    sake: a shell script handed to ``wsl.exe`` from a Windows process crosses
    Windows argv quoting, ``wsl.exe``'s own parsing and finally bash, and that
    path was observed to strip ``$var`` references and mangle nested double
    quotes - so ``for d in $HOME/...; do echo $d; done`` silently iterated with
    an empty ``d`` and every probe reported "not found". Base64 contains only
    ``[A-Za-z0-9+/=]``, so nothing in that chain can alter it.

    Args:
        distro: WSL distribution name.
        script: POSIX shell script to execute.

    Returns:
        The argv list for :func:`subprocess.run`.
    """
    import base64

    payload = base64.b64encode(
        (WSL_PATH_PREAMBLE + script).encode("utf-8")
    ).decode("ascii")
    wsl = shutil.which("wsl") or "wsl"
    return [wsl, "-d", distro, "--", "bash", "-lc",
            f"echo {payload} | base64 -d | bash"]


def wsl_distributions(timeout_s: float = 15.0) -> list[str]:
    """Return the installed WSL distribution names, best-effort.

    Returns:
        Distribution names, or an empty list when WSL is absent or unusable.
    """
    wsl = shutil.which("wsl")
    if not wsl:
        return []
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [wsl, "--list", "--quiet"],
            capture_output=True, text=True, timeout=timeout_s,
            env=_wsl_env(), check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    names = []
    for line in (proc.stdout or "").splitlines():
        # Defensive: some Windows builds still emit UTF-16 despite WSL_UTF8.
        name = line.replace("\x00", "").strip()
        if name and not name.startswith("docker-desktop"):
            names.append(name)
    return names


def _probe_wsl(checks: dict[str, str], timeout_s: float) -> NS3Availability | None:
    """Look for a built ns-3 tree inside a WSL distribution.

    This exists because the natural way to run NS-3 from a Windows host is
    inside WSL: NS-3 needs a POSIX C++ toolchain, which Windows does not
    provide. The probe is real - it executes ``ns3 show version`` inside the
    distribution and only reports success if that command works.

    Args:
        checks: Mutable probe log, appended to in place.
        timeout_s: Per-subprocess timeout.

    Returns:
        A populated availability record, or ``None`` when nothing was found.
    """
    wsl = shutil.which("wsl")
    if not wsl:
        checks["wsl"] = "wsl.exe not on PATH"
        return None

    forced = os.environ.get("NS3_WSL_DISTRO", "").strip()
    distros = [forced] if forced else wsl_distributions(timeout_s)
    if not distros:
        checks["wsl"] = "no WSL distributions found"
        return None

    globs = os.environ.get("NS3_WSL_DIR", "").strip()
    search = f'"{globs}"' if globs else " ".join(DEFAULT_WSL_NS3_GLOBS)
    # One shell command per distro: locate the tree, then prove it runs.
    # A tree only counts as usable if it has actually been built - the presence
    # of ./ns3 alone proves nothing, since that script ships with the source.
    # `show profile` succeeds only against a configured, built tree.
    #
    # `show version` needs --enable-build-version at configure time, so it is
    # not reliable; the release version is taken from the directory name, which
    # ns-3 releases always carry (ns-3.44), and only falls back to the command.
    # Note: nested double quotes inside a command substitution do not survive
    # the Windows -> wsl.exe argv boundary intact, so this script deliberately
    # keeps its quoting flat.
    script = (
        f"for d in {search}; do "
        '  if [ -x "$d/ns3" ] && [ -d "$d/build/lib" ]; then '
        '    if (cd "$d" && ./ns3 show profile >/dev/null 2>&1); then '
        '      v=$(basename "$d"); '
        '      p=$(cd "$d" && ./ns3 show profile 2>/dev/null | tail -1); '
        '      echo "NS3_FOUND|$d|$v ($p)"; exit 0; '
        "    fi; "
        "  fi; "
        "done; exit 1"
    )

    for distro in distros:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                wsl_argv(distro, script),
                capture_output=True, text=True, timeout=timeout_s * 4,
                env=_wsl_env(), check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            checks[f"wsl:{distro}"] = f"probe failed: {exc}"
            continue

        out = (proc.stdout or "").replace("\x00", "")
        line = next((l for l in out.splitlines() if l.startswith("NS3_FOUND|")), "")
        if line:
            _, ns3_dir, version = line.split("|", 2)
            checks[f"wsl:{distro}"] = "ok"
            return NS3Availability(
                available=True,
                method="wsl-ns3-cli",
                version=version.strip(),
                ns3_dir=ns3_dir.strip(),
                detail=f"NS-3 found in WSL distribution {distro!r} at {ns3_dir.strip()}",
                checks=checks,
                distro=distro,
            )
        checks[f"wsl:{distro}"] = "no built ns-3 tree found"
    return None


def detect_ns3(timeout_s: float = 15.0) -> NS3Availability:
    """Probe the host for a usable NS-3 installation.

    The probe is ordered from most to least capable:

    1. ``$NS3_DIR/ns3`` (or ``ns3`` on ``PATH``) - the ns-3.36+ CLI wrapper.
    2. ``import ns`` - the ns-3 Python bindings.

    Args:
        timeout_s: Per-subprocess timeout.

    Returns:
        A populated :class:`NS3Availability`. ``available`` is True only when a
        probe actually succeeded.
    """
    checks: dict[str, str] = {}

    ns3_dir = os.environ.get("NS3_DIR", "")
    candidates: list[Path] = []
    if ns3_dir:
        candidates.append(Path(ns3_dir) / "ns3")
    which = shutil.which("ns3")
    if which:
        candidates.append(Path(which))

    for candidate in candidates:
        if not candidate.exists():
            checks[f"cli:{candidate}"] = "not found"
            continue
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [str(candidate), "--version"],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                cwd=str(candidate.parent),
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            checks[f"cli:{candidate}"] = f"probe failed: {exc}"
            continue

        if proc.returncode == 0:
            version = (proc.stdout or proc.stderr).strip().splitlines()
            checks[f"cli:{candidate}"] = "ok"
            return NS3Availability(
                available=True,
                method="ns3-cli",
                version=version[0] if version else "unknown",
                ns3_dir=str(candidate.parent),
                detail=f"NS-3 CLI found at {candidate}",
                checks=checks,
            )
        checks[f"cli:{candidate}"] = f"exit {proc.returncode}"

    if not candidates:
        checks["cli"] = "no ns3 executable on PATH and $NS3_DIR unset"

    # WSL is checked before the Python bindings because it is the only way to
    # get a real NS-3 on a Windows host: NS-3 requires a POSIX C++ toolchain.
    wsl_result = _probe_wsl(checks, timeout_s)
    if wsl_result is not None:
        return wsl_result

    try:
        import ns  # type: ignore  # noqa: PLC0415

        version = getattr(ns, "__version__", "unknown")
        checks["python-bindings"] = "ok"
        return NS3Availability(
            available=True,
            method="python-bindings",
            version=str(version),
            ns3_dir=str(Path(getattr(ns, "__file__", ".")).parent),
            detail="NS-3 Python bindings importable",
            checks=checks,
        )
    except ImportError as exc:
        checks["python-bindings"] = f"import failed: {exc}"

    return NS3Availability(
        available=False,
        detail=(
            "No usable NS-3 installation found. Set $NS3_DIR to an ns-3 source "
            "tree, put the 'ns3' wrapper on PATH, or install the Python "
            "bindings. The project falls back to its own discrete-event engine."
        ),
        checks=checks,
    )


def resolve_engine(policy: str, probe: NS3Availability | None = None) -> tuple[str, str]:
    """Decide which engine to use and produce its provenance label.

    Args:
        policy: ``"auto"``, ``"ns3"`` or ``"python"`` from ``simulation.engine``.
        probe: A pre-computed probe result; performed on demand when omitted.

    Returns:
        ``(engine_id, reason)`` where ``engine_id`` is :data:`ENGINE_NS3` or
        :data:`ENGINE_PYTHON` and ``reason`` explains the choice in one line.

    Raises:
        NS3Unavailable: When ``policy == "ns3"`` but NS-3 is not installed.
        ValueError: When *policy* is not a recognised value.
    """
    policy = (policy or "auto").lower()
    if policy == "python":
        return ENGINE_PYTHON, "simulation.engine=python (NS-3 not consulted)"

    if policy not in {"auto", "ns3"}:
        raise ValueError(f"Unknown simulation.engine policy {policy!r}")

    result = probe if probe is not None else detect_ns3()

    if policy == "ns3":
        if result.available:
            return ENGINE_NS3, f"NS-3 detected via {result.method} ({result.version})"
        raise NS3Unavailable(
            "simulation.engine is set to 'ns3' but no usable NS-3 installation "
            f"was found. {result.detail}"
        )

    # policy == "auto".
    #
    # `auto` deliberately resolves to the Python engine even when NS-3 is
    # installed. That is a methodological decision, not a limitation:
    #
    #  * The Python engine is the reference implementation. Every topology
    #    family, all six attack families, rate shaping and the closed
    #    mitigation loop exist there; the C++ model implements a subset.
    #  * A corpus must come from ONE engine. If `auto` picked NS-3 for the
    #    scenarios it happens to support and the Python engine for the rest,
    #    the training set would be a mixture of two different simulators while
    #    the closed-loop evaluation stayed on one of them - a train/test
    #    mismatch that would quietly invalidate the comparison.
    #
    # NS-3 is therefore opt-in (`simulation.engine: ns3`), which is what the
    # cross-validation experiment uses. Availability is still reported, so the
    # user knows the option is there.
    if result.available:
        return (
            ENGINE_PYTHON,
            "simulation.engine=auto resolved to the Python reference engine. "
            f"NS-3 IS available here ({result.version} via {result.method}); "
            "set simulation.engine=ns3 to run this scenario in NS-3 instead. "
            "auto does not switch automatically so that a corpus is never a "
            "mixture of two simulators.",
        )

    return (
        ENGINE_PYTHON,
        "NS-3 unavailable; fell back to the built-in discrete-event engine "
        f"({result.detail.splitlines()[0]})",
    )


def engine_label(engine_id: str) -> str:
    """Return the human-readable provenance label for an engine id."""
    return ENGINE_LABELS.get(engine_id, engine_id)


# --------------------------------------------------------------------------- #
# NS-3 invocation (used only when NS-3 is genuinely present)
# --------------------------------------------------------------------------- #
NS3_MODEL_NAME: str = "netshield-topology"


def windows_path_to_wsl(path: Path, distro: str, timeout_s: float = 20.0) -> str:
    """Translate a Windows path to its path inside a WSL distribution.

    Uses ``wslpath`` inside the distribution rather than string surgery, so
    drive mappings the user has customised are honoured.

    Args:
        path: An absolute Windows path.
        distro: The WSL distribution name.
        timeout_s: Subprocess timeout.

    Returns:
        The translated POSIX path.

    Raises:
        RuntimeError: If the translation fails.
    """
    wsl = shutil.which("wsl")
    if not wsl:  # pragma: no cover - guarded by the caller
        raise RuntimeError("wsl.exe is not available")
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        wsl_argv(distro, f'wslpath -a -u "{path}"'),
        capture_output=True, text=True, timeout=timeout_s,
        env=_wsl_env(), check=False,
    )
    translated = (proc.stdout or "").replace("\x00", "").strip()
    if proc.returncode != 0 or not translated:
        raise RuntimeError(
            f"Could not translate {path} into WSL distribution {distro!r}: "
            f"{(proc.stderr or '').strip()}"
        )
    return translated


def ns3_command(
    availability: NS3Availability,
    params: dict[str, Any],
    output_dir: Path,
) -> list[str]:
    """Build the argv that runs the NetShield NS-3 model.

    Two transports are supported: a native ``ns3`` CLI, and an ns-3 tree living
    inside a WSL distribution (the usual arrangement on a Windows host, since
    NS-3 needs a POSIX toolchain). In the WSL case the output directory is
    translated with ``wslpath`` so the model writes straight into the
    repository.

    Args:
        availability: A successful probe result.
        params: Model parameters (mapped onto ``--key=value`` arguments).
        output_dir: Directory the model writes its CSV output into.

    Returns:
        The argv list for :func:`subprocess.run`.

    Raises:
        NS3Unavailable: If *availability* does not describe a usable NS-3.
    """
    if not availability.available or availability.method not in {"ns3-cli", "wsl-ns3-cli"}:
        raise NS3Unavailable(
            "ns3_command requires an ns3-cli or wsl-ns3-cli installation; "
            f"got method={availability.method!r}"
        )

    if availability.via_wsl:
        target = windows_path_to_wsl(output_dir, availability.distro)
        args = " ".join(f"--{key}={value}" for key, value in sorted(params.items()))
        # ``./ns3 run`` takes the whole program invocation as ONE string and
        # splits it on spaces, so a --outputDir containing a space (very common
        # under /mnt/c/Users/...) is silently truncated and the model aborts
        # writing to a nonexistent directory. Write to a space-free temporary
        # directory inside the distribution instead, then copy the artefacts
        # out with a properly quoted cp that we control.
        script = (
            "set -e; "
            f'cd "{availability.ns3_dir}"; '
            "OUT=$(mktemp -d /tmp/netshield-ns3-XXXXXX); "
            f'./ns3 run "{NS3_MODEL_NAME} {args} --outputDir=$OUT"; '
            f'mkdir -p "{target}"; '
            f'cp "$OUT"/. "{target}"/ -r; '
            'rm -rf "$OUT"'
        )
        return wsl_argv(availability.distro, script)

    args = " ".join(f"--{key}={value}" for key, value in sorted(params.items()))
    args = f"{NS3_MODEL_NAME} {args} --outputDir={output_dir}"
    return [str(Path(availability.ns3_dir) / "ns3"), "run", args]


def install_model(availability: NS3Availability, timeout_s: float = 120.0) -> str:
    """Copy the NetShield model into the ns-3 ``scratch`` directory and build it.

    ns-3 compiles anything in ``scratch/``, so installing the model is a file
    copy followed by a build. Only the scratch target is rebuilt, so this is
    fast after the first full build of the tree.

    Args:
        availability: A successful probe result.
        timeout_s: Build timeout in seconds.

    Returns:
        The build output (stdout + stderr), for logging.

    Raises:
        NS3Unavailable: If NS-3 is not usable.
        RuntimeError: If the copy or the build fails.
    """
    if not availability.available:
        raise NS3Unavailable("Cannot install the model: NS-3 is not available.")

    source = repo_root() / "ns3" / "simulations" / f"{NS3_MODEL_NAME}.cc"
    if not source.exists():
        raise RuntimeError(f"NS-3 model source not found: {source}")

    if availability.via_wsl:
        src_in_wsl = windows_path_to_wsl(source, availability.distro)
        script = (
            f'cp "{src_in_wsl}" "{availability.ns3_dir}/scratch/" && '
            f'cd "{availability.ns3_dir}" && ./ns3 build {NS3_MODEL_NAME}'
        )
        argv = wsl_argv(availability.distro, script)
        cwd = None
    else:
        target = Path(availability.ns3_dir) / "scratch" / f"{NS3_MODEL_NAME}.cc"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        argv = [str(Path(availability.ns3_dir) / "ns3"), "build", NS3_MODEL_NAME]
        cwd = availability.ns3_dir

    _LOG.info("Building the NS-3 model (%s)...", NS3_MODEL_NAME)
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv, capture_output=True, text=True, timeout=timeout_s,
        env=_wsl_env(), cwd=cwd, check=False,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise RuntimeError(
            f"Building the NS-3 model failed (exit {proc.returncode}).\n{output}"
        )
    return output


def run_ns3_simulation(
    availability: NS3Availability,
    params: dict[str, Any],
    output_dir: str | Path,
    timeout_s: float = 1800.0,
) -> dict[str, Any]:
    """Run the NS-3 model and return the paths of its output artefacts.

    Args:
        availability: A successful probe result.
        params: Model parameters.
        output_dir: Directory for the model's CSV/XML output.
        timeout_s: Wall-clock timeout for the NS-3 process.

    Returns:
        A mapping with ``returncode``, ``stdout``, ``stderr``, ``flow_csv`` and
        ``output_dir``.

    Raises:
        NS3Unavailable: If NS-3 is not usable.
        RuntimeError: If the NS-3 process exits non-zero.
    """
    target = resolve(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    argv = ns3_command(availability, params, target)

    _LOG.info("Running NS-3: %s", " ".join(argv))
    # A WSL invocation must not set cwd to the Linux-side ns3_dir, which is not
    # a valid Windows working directory; the script cds there itself.
    cwd = None if availability.via_wsl else (availability.ns3_dir or str(repo_root()))
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        env=_wsl_env(),
        cwd=cwd,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"NS-3 model exited with code {proc.returncode}.\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "flow_csv": str(target / "ns3_flows.csv"),
        "output_dir": str(target),
    }


def parse_ns3_flowmonitor(path: str | Path) -> list[dict[str, Any]]:
    """Parse the flow CSV emitted by the NetShield NS-3 model.

    The C++ model writes one row per FlowMonitor flow with the same column names
    the Python engine uses, so downstream feature extraction is engine-agnostic.

    Args:
        path: Path to ``ns3_flows.csv``.

    Returns:
        A list of row dicts.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    import csv

    source = resolve(path)
    if not source.exists():
        raise FileNotFoundError(f"NS-3 flow output not found: {source}")
    with source.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def environment_report() -> dict[str, Any]:
    """Return a full dependency report used by ``scripts/check_env.py``.

    Returns:
        A mapping describing Python, key libraries and NS-3 availability. Every
        entry reflects an actual import or probe - nothing is assumed.
    """
    import importlib
    import platform
    import sys

    libraries = [
        "numpy", "pandas", "scipy", "sklearn", "torch", "torch_geometric",
        "networkx", "matplotlib", "seaborn", "fastapi", "uvicorn", "pydantic",
        "yaml", "joblib", "pytest", "jinja2",
    ]
    found: dict[str, str] = {}
    missing: list[str] = []
    for name in libraries:
        try:
            module = importlib.import_module(name)
        except ImportError:
            missing.append(name)
            continue
        found[name] = str(getattr(module, "__version__", "unknown"))

    tools: dict[str, str] = {}
    for tool in ("node", "npm", "git", "docker", "g++", "cmake", "make"):
        path = shutil.which(tool)
        tools[tool] = path or "not found"

    probe = detect_ns3()
    # The primary engine on this platform is NS-3-in-WSL; probe it too.
    try:
        from .ns3_wsl import detect as _detect_wsl  # noqa: PLC0415

        wsl = _detect_wsl().to_dict()
    except Exception:  # noqa: BLE001 - never let a probe break the report
        wsl = {"available": False, "reason": "probe failed"}
    return {
        "python": {
            "version": sys.version.split()[0],
            "executable": sys.executable,
            "platform": platform.platform(),
        },
        "libraries": found,
        "missing_libraries": missing,
        "tools": tools,
        "ns3": probe.to_dict(),
        "ns3_wsl": wsl,
        "primary_engine": "ns3" if wsl.get("available") else "python",
        "repo_root": str(repo_root()),
    }


def write_environment_report(path: str | Path) -> Path:
    """Write :func:`environment_report` to *path* as JSON."""
    target = resolve(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(environment_report(), indent=2), encoding="utf-8")
    return target
