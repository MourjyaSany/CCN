#!/usr/bin/env python3
"""Probe the execution environment and report exactly what is available.

This script never guesses. It imports every library and executes every external
tool it reports on, so the resulting ``results/reports/environment.json`` is an
honest statement of what produced the project's numbers - in particular whether
NS-3 or the built-in Python engine was used, and whether PyTorch Geometric or
the pure-PyTorch fallback backs GraphSAGE.

Exit status is 0 when every *required* dependency is present, 1 otherwise.
Optional dependencies (NS-3, PyTorch Geometric, Node, Docker) are reported but
never fail the check - the project is designed to run without them.
"""

from __future__ import annotations

import sys

from _bootstrap import REPO_ROOT, banner, common_parser, fail, ok, warn  # noqa: E402

#: Libraries the project cannot run without.
REQUIRED = ["numpy", "pandas", "scipy", "sklearn", "torch", "networkx",
            "matplotlib", "yaml", "joblib"]
#: Libraries that enable a component but have a documented fallback.
OPTIONAL = {
    "torch_geometric": "GraphSAGE falls back to the pure-PyTorch MeanSAGEConv layer",
    "fastapi": "the REST API and dashboard will not start",
    "uvicorn": "the REST API and dashboard will not start",
    "seaborn": "only affects optional styling",
    "pytest": "the test suite cannot run",
    "jinja2": "the HTML dashboard template cannot render",
}


def main(argv: list[str] | None = None) -> int:
    """Run the environment probe.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv``).

    Returns:
        Process exit status.
    """
    parser = common_parser("Probe the environment and report dependency status.")
    parser.add_argument("--output", default="results/reports/environment.json",
                        help="Where to write the machine-readable report.")
    args = parser.parse_args(argv)

    from netshield.simulation.ns3_bridge import (  # noqa: PLC0415
        environment_report,
        write_environment_report,
    )
    from netshield.utils.logging_utils import setup_logging  # noqa: PLC0415

    setup_logging(level=args.log_level, force=True)
    report = environment_report()

    banner("NetShield-GNN :: environment check")
    print(f"  repository : {REPO_ROOT}")
    print(f"  python     : {report['python']['version']} "
          f"({report['python']['platform']})")

    banner("Required Python libraries")
    missing_required: list[str] = []
    for name in REQUIRED:
        version = report["libraries"].get(name)
        if version:
            ok(f"{name:<18} {version}")
        else:
            missing_required.append(name)
            fail(f"{name:<18} MISSING")

    banner("Optional Python libraries")
    for name, consequence in OPTIONAL.items():
        version = report["libraries"].get(name)
        if version:
            ok(f"{name:<18} {version}")
        else:
            warn(f"{name:<18} missing - {consequence}")

    banner("External tools")
    for tool, path in report["tools"].items():
        if path == "not found":
            warn(f"{tool:<18} not found")
        else:
            ok(f"{tool:<18} {path}")

    banner("Network simulator")
    ns3 = report["ns3"]
    if ns3["available"]:
        ok(f"NS-3 detected via {ns3['method']} ({ns3['version']})")
        ok("Results will be labelled: NS-3 simulation")
    else:
        warn("NS-3 not available on this host.")
        print(f"         {ns3['detail']}")
        warn("Results will be labelled: Python discrete-event emulation")
        print("         This is a supported, documented configuration - see")
        print("         docs/troubleshooting.md. The project is fully functional.")

    banner("GraphSAGE backend")
    try:
        from netshield.models.graphsage import BACKEND  # noqa: PLC0415

        ok(f"backend: {BACKEND}")
        report["gnn_backend"] = BACKEND
    except ImportError as exc:  # pragma: no cover - torch is required
        fail(f"cannot import the GraphSAGE module: {exc}")
        report["gnn_backend"] = "unavailable"

    report["engine_label"] = (
        "NS-3 simulation" if ns3["available"] else "Python discrete-event emulation"
    )
    report["ns3_available"] = bool(ns3["available"])
    report["missing_required"] = missing_required

    path = write_environment_report(args.output)
    import json

    path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    banner("Summary")
    if missing_required:
        fail(f"{len(missing_required)} required libraries missing: "
             f"{', '.join(missing_required)}")
        print("\n  Install them with:  pip install -r requirements.txt\n")
        return 1
    ok("All required dependencies are present.")
    print(f"\n  Machine-readable report: {path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
