"""Deterministic seeding across Python, NumPy and PyTorch.

Reproducibility is a hard requirement of this project: every experiment is
identified by ``(config, seed)`` and must yield byte-identical telemetry when
re-run.
"""

from __future__ import annotations

import os
import random
from typing import Any

import numpy as np

from .logging_utils import get_logger

_LOG = get_logger(__name__)


def seed_everything(seed: int, deterministic_torch: bool = True) -> int:
    """Seed every RNG this project touches.

    Args:
        seed: The master seed.
        deterministic_torch: Ask PyTorch for deterministic kernels. Disable if a
            required operator has no deterministic implementation.

    Returns:
        The seed that was applied (echoed for logging convenience).
    """
    seed = int(seed) % (2**32)
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)

    try:
        import torch  # noqa: PLC0415  (optional heavy import)

        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        if deterministic_torch:
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False
    except ImportError:  # pragma: no cover - torch is a declared dependency
        _LOG.debug("PyTorch not installed; skipped torch seeding.")

    return seed


def derive_seed(master: int, *parts: Any) -> int:
    """Derive a stable child seed from a master seed and arbitrary labels.

    Used so that, e.g., device #7's traffic RNG is independent of the attack
    RNG yet still fully determined by the master seed.

    Args:
        master: The experiment master seed.
        *parts: Any hashable-to-string components (node id, stream name, ...).

    Returns:
        A 32-bit seed.
    """
    import hashlib

    payload = "|".join([str(master), *(str(p) for p in parts)]).encode("utf-8")
    digest = hashlib.blake2b(payload, digest_size=4).digest()
    return int.from_bytes(digest, "big")


def rng_for(master: int, *parts: Any) -> np.random.Generator:
    """Return an independent, reproducible :class:`numpy.random.Generator`."""
    return np.random.default_rng(derive_seed(master, *parts))


class FastRandom:
    """Buffered scalar sampling on top of a seeded NumPy generator.

    The simulator draws a handful of scalars per packet (inter-arrival
    jitter, ports, sizes). A scalar ``Generator.uniform`` call costs several
    microseconds of call overhead, which dominated the attack path in
    profiling. This class draws uniforms in blocks of ``block`` and serves
    them from a Python list, so a scalar draw costs one index operation.

    It is exactly as reproducible as the underlying generator: the same seed
    yields the same sequence. Any method it does not implement is forwarded
    to the generator.
    """

    __slots__ = ("_gen", "_buf", "_i", "_block")

    def __init__(self, generator: np.random.Generator, block: int = 4096) -> None:
        self._gen = generator
        self._block = int(block)
        self._buf: list[float] = []
        self._i = 0

    def random(self) -> float:
        if self._i >= len(self._buf):
            self._buf = self._gen.random(self._block).tolist()
            self._i = 0
        value = self._buf[self._i]
        self._i += 1
        return value

    def uniform(self, low: float = 0.0, high: float = 1.0) -> float:
        return low + (high - low) * self.random()

    def integers(self, low: int, high: int | None = None) -> int:
        """Integer in ``[low, high)`` (NumPy semantics; ``high`` exclusive)."""
        if high is None:
            low, high = 0, low
        span = int(high) - int(low)
        if span <= 0:
            raise ValueError("high must be greater than low")
        return int(low) + min(span - 1, int(self.random() * span))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._gen, name)


def fast_rng_for(master: int, *parts: Any) -> FastRandom:
    """:func:`rng_for` wrapped in :class:`FastRandom` for per-packet draws."""
    return FastRandom(rng_for(master, *parts))
