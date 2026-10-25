"""Shared bootstrap for the command-line scripts.

Puts ``src/`` on ``sys.path`` so the scripts run straight from a clone with no
``pip install`` step, and exposes the argument parser fragments every script
shares (config overrides, logging level, seed).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def common_parser(description: str) -> argparse.ArgumentParser:
    """Return an argument parser carrying the options every script accepts.

    Args:
        description: Help text shown by ``--help``.

    Returns:
        A parser with ``--set``, ``--log-level``, ``--seed`` and ``--config``.
    """
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--set", dest="overrides", action="append", default=[], metavar="KEY=VALUE",
        help="Override any configuration key, e.g. --set simulation.duration_s=60. "
             "Repeatable.",
    )
    parser.add_argument(
        "--config", default="config/default.yaml",
        help="Base configuration file.",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Override the master seed.",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Console logging verbosity.",
    )
    return parser


def build_config(args: argparse.Namespace, extra: Sequence[str] = ()) -> Any:
    """Load the layered configuration honouring the shared CLI options.

    Args:
        args: Parsed arguments from :func:`common_parser`.
        extra: Additional ``key=value`` overrides applied before ``--set``.

    Returns:
        The merged :class:`netshield.utils.config.Config`.
    """
    from netshield.utils.config import load_config

    overrides = list(extra) + list(args.overrides or [])
    if getattr(args, "seed", None) is not None:
        overrides.append(f"seed={args.seed}")
    return load_config(default_file=args.config, set_args=overrides)


def setup(args: argparse.Namespace, log_name: str) -> Any:
    """Configure logging and return the merged configuration.

    Args:
        args: Parsed arguments.
        log_name: Basename of the run log written under ``results/logs``.

    Returns:
        The merged configuration.
    """
    from netshield.utils.logging_utils import setup_logging

    log_dir = REPO_ROOT / "results" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(level=args.log_level, log_file=log_dir / f"{log_name}.log", force=True)
    return build_config(args)


def banner(title: str) -> None:
    """Print a section banner to stdout."""
    line = "=" * 78
    print(f"\n{line}\n  {title}\n{line}", flush=True)


def ok(message: str) -> None:
    """Print a success line."""
    print(f"  [ok]   {message}", flush=True)


def warn(message: str) -> None:
    """Print a warning line."""
    print(f"  [warn] {message}", flush=True)


def fail(message: str) -> None:
    """Print a failure line."""
    print(f"  [FAIL] {message}", flush=True)
