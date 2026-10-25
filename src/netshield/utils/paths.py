"""Repository-root discovery and path helpers.

Nothing in NetShield-GNN hardcodes an absolute path. Every module resolves
locations through :func:`repo_root` so the project is relocatable and works
identically on Windows, Linux and inside the Docker image.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

# Sentinel files that mark the repository root.
_ROOT_MARKERS: Final[tuple[str, ...]] = ("config/default.yaml", "run.sh", "pyproject.toml")

_ENV_OVERRIDE: Final[str] = "NETSHIELD_ROOT"


def repo_root() -> Path:
    """Return the repository root directory.

    Resolution order:

    1. ``$NETSHIELD_ROOT`` if set (used by the Docker image and CI).
    2. Walk upwards from this file looking for a root marker.
    3. Fall back to three levels above this file (``src/netshield/utils``).

    Returns:
        Absolute :class:`~pathlib.Path` to the repository root.
    """
    env = os.environ.get(_ENV_OVERRIDE)
    if env:
        candidate = Path(env).expanduser().resolve()
        if candidate.is_dir():
            return candidate

    here = Path(__file__).resolve()
    for parent in here.parents:
        if any((parent / marker).exists() for marker in _ROOT_MARKERS):
            return parent
    return here.parents[3]


def resolve(path: str | os.PathLike[str]) -> Path:
    """Resolve *path* against the repository root when it is relative.

    Args:
        path: Absolute or repo-relative path.

    Returns:
        An absolute :class:`~pathlib.Path`.
    """
    p = Path(path)
    return p if p.is_absolute() else (repo_root() / p)


def ensure_dir(path: str | os.PathLike[str]) -> Path:
    """Create *path* (and parents) if missing and return it resolved."""
    target = resolve(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def ensure_parent(path: str | os.PathLike[str]) -> Path:
    """Create the parent directory of *path* and return the resolved file path."""
    target = resolve(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target
