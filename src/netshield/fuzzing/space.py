"""Parameter-space declaration and sampling for the dynamic fuzzer.

A fuzzing *space* maps dotted configuration keys onto the set of values the
fuzzer may assign them. Six declaration forms are supported, all of which appear
in ``config/fuzzing.yaml``:

============================  ===============================================
Declaration                   Meaning
============================  ===============================================
``[a, b, c]``                 Explicit value list (grid sweep)
``{choice: [...]}``           Uniform pick from a list
``{uniform: [lo, hi]}``       Continuous uniform
``{loguniform: [lo, hi]}``    Log-uniform - correct for rates spanning decades
``{int_uniform: [lo, hi]}``   Integer uniform, inclusive
``{pair_uniform: [lo, hi]}``  An ordered ``[a, b]`` pair with ``a <= b``
``{subset: [...], size: []}`` Random subset of a pool (e.g. destination ports)
============================  ===============================================

Every sampler takes an explicit :class:`numpy.random.Generator`, so a campaign
seed fully determines the generated corpus. This is what makes fuzzing runs
reproducible and therefore citable in the report.
"""

from __future__ import annotations

import itertools
import math
from typing import Any, Iterator, Mapping, Sequence

import numpy as np

from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)

#: Recognised distribution keys inside a mapping-style declaration.
DISTRIBUTION_KEYS: frozenset[str] = frozenset(
    {"choice", "uniform", "loguniform", "int_uniform", "pair_uniform", "subset"}
)


class SpaceError(ValueError):
    """Raised when a parameter-space declaration is malformed."""


def validate_space(space: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate a parameter-space declaration.

    Args:
        space: Mapping of dotted config key to a declaration.

    Returns:
        The same mapping (for call chaining).

    Raises:
        SpaceError: On the first malformed declaration, naming the key.
    """
    if not space:
        raise SpaceError("Fuzzing space is empty; nothing to mutate.")

    for key, spec in space.items():
        if isinstance(spec, (list, tuple)):
            if not spec:
                raise SpaceError(f"Parameter '{key}': explicit value list is empty.")
            continue
        if not isinstance(spec, Mapping):
            raise SpaceError(
                f"Parameter '{key}': expected a list or a distribution mapping, "
                f"got {type(spec).__name__}."
            )
        keys = set(spec) & DISTRIBUTION_KEYS
        if len(keys) != 1:
            raise SpaceError(
                f"Parameter '{key}': declaration must name exactly one of "
                f"{sorted(DISTRIBUTION_KEYS)}, found {sorted(set(spec))}."
            )
        name = keys.pop()
        payload = spec[name]
        if name in ("uniform", "loguniform", "int_uniform", "pair_uniform"):
            if not isinstance(payload, (list, tuple)) or len(payload) != 2:
                raise SpaceError(f"Parameter '{key}': '{name}' needs a [lo, hi] pair.")
            lo, hi = float(payload[0]), float(payload[1])
            if hi < lo:
                raise SpaceError(f"Parameter '{key}': '{name}' has hi < lo.")
            if name == "loguniform" and lo <= 0:
                raise SpaceError(f"Parameter '{key}': loguniform requires lo > 0.")
        elif name == "choice":
            if not isinstance(payload, (list, tuple)) or not payload:
                raise SpaceError(f"Parameter '{key}': 'choice' needs a non-empty list.")
        elif name == "subset":
            if not isinstance(payload, (list, tuple)) or not payload:
                raise SpaceError(f"Parameter '{key}': 'subset' needs a non-empty pool.")
            size = spec.get("size", [1, len(payload)])
            if not isinstance(size, (list, tuple)) or len(size) != 2:
                raise SpaceError(f"Parameter '{key}': 'subset' needs size: [lo, hi].")
            if int(size[0]) < 1 or int(size[1]) > len(payload) or int(size[0]) > int(size[1]):
                raise SpaceError(
                    f"Parameter '{key}': subset size {list(size)} is outside "
                    f"1..{len(payload)}."
                )
    return space


def sample_value(spec: Any, rng: np.random.Generator) -> Any:
    """Draw one value from a single parameter declaration.

    Args:
        spec: The declaration (list or distribution mapping).
        rng: Seeded random generator.

    Returns:
        A sampled value of the appropriate Python type.

    Raises:
        SpaceError: If *spec* is malformed.
    """
    if isinstance(spec, (list, tuple)):
        return _coerce(spec[int(rng.integers(0, len(spec)))])

    if not isinstance(spec, Mapping):
        raise SpaceError(f"Cannot sample from declaration of type {type(spec).__name__}")

    if "choice" in spec:
        options = list(spec["choice"])
        return _coerce(options[int(rng.integers(0, len(options)))])

    if "uniform" in spec:
        lo, hi = float(spec["uniform"][0]), float(spec["uniform"][1])
        return round(float(rng.uniform(lo, hi)), 4)

    if "loguniform" in spec:
        lo, hi = float(spec["loguniform"][0]), float(spec["loguniform"][1])
        value = math.exp(float(rng.uniform(math.log(lo), math.log(hi))))
        return round(value, 4)

    if "int_uniform" in spec:
        lo, hi = int(spec["int_uniform"][0]), int(spec["int_uniform"][1])
        return int(rng.integers(lo, hi + 1))

    if "pair_uniform" in spec:
        lo, hi = int(spec["pair_uniform"][0]), int(spec["pair_uniform"][1])
        a = int(rng.integers(lo, hi + 1))
        b = int(rng.integers(lo, hi + 1))
        return [min(a, b), max(a, b)]

    if "subset" in spec:
        pool = list(spec["subset"])
        size_spec = spec.get("size", [1, len(pool)])
        size = int(rng.integers(int(size_spec[0]), int(size_spec[1]) + 1))
        picked = rng.choice(len(pool), size=size, replace=False)
        return [_coerce(pool[int(i)]) for i in sorted(picked)]

    raise SpaceError(f"Unrecognised parameter declaration: {sorted(spec)}")


def _coerce(value: Any) -> Any:
    """Convert NumPy scalars to plain Python types for YAML/JSON round-tripping."""
    if isinstance(value, np.generic):
        return value.item()
    return value


def grid_points(space: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    """Enumerate the full Cartesian product of an explicit-list space.

    Args:
        space: Mapping of dotted key to an explicit value list.

    Yields:
        One ``{dotted_key: value}`` assignment per grid point, in a
        deterministic order.

    Raises:
        SpaceError: If any parameter is not declared as an explicit list.
    """
    keys = sorted(space)
    for key in keys:
        if not isinstance(space[key], (list, tuple)):
            raise SpaceError(
                f"Grid strategy requires explicit value lists; parameter '{key}' "
                f"is declared as {type(space[key]).__name__}."
            )
    for combination in itertools.product(*(list(space[k]) for k in keys)):
        yield {k: _coerce(v) for k, v in zip(keys, combination)}


def grid_size(space: Mapping[str, Any]) -> int:
    """Return the number of points in a grid space."""
    total = 1
    for spec in space.values():
        total *= len(spec) if isinstance(spec, (list, tuple)) else 1
    return total


def sample_point(space: Mapping[str, Any], rng: np.random.Generator) -> dict[str, Any]:
    """Draw one independent assignment for every parameter in *space*."""
    return {key: sample_value(spec, rng) for key, spec in sorted(space.items())}


def mutate_point(
    base: Mapping[str, Any],
    space: Mapping[str, Any],
    rng: np.random.Generator,
    mutation_rate: float = 0.4,
    scale: float = 0.5,
) -> dict[str, Any]:
    """Perturb an existing assignment to produce a nearby variant.

    Numeric parameters are scaled by a factor drawn from
    ``[1 - scale, 1 + scale]`` and then clamped to their declared bounds;
    categorical parameters are resampled outright. At least one parameter is
    always mutated, so a mutation step can never return an identical point.

    Args:
        base: The parent assignment.
        space: The declared space (supplies bounds and types).
        rng: Seeded random generator.
        mutation_rate: Per-parameter probability of being perturbed.
        scale: Maximum relative perturbation of a numeric parameter.

    Returns:
        The mutated assignment.
    """
    child = {k: _coerce(v) for k, v in base.items()}
    keys = sorted(space)
    mutated_any = False

    for key in keys:
        if float(rng.random()) >= mutation_rate:
            continue
        mutated_any = True
        child[key] = _perturb(child.get(key), space[key], rng, scale)

    if not mutated_any and keys:
        key = keys[int(rng.integers(0, len(keys)))]
        child[key] = _perturb(child.get(key), space[key], rng, scale)

    return child


def _perturb(
    current: Any, spec: Any, rng: np.random.Generator, scale: float
) -> Any:
    """Perturb a single value, respecting its declared type and bounds."""
    if isinstance(spec, Mapping):
        if "uniform" in spec or "loguniform" in spec:
            key = "uniform" if "uniform" in spec else "loguniform"
            lo, hi = float(spec[key][0]), float(spec[key][1])
            if not isinstance(current, (int, float)):
                return sample_value(spec, rng)
            factor = 1.0 + float(rng.uniform(-scale, scale))
            return round(float(np.clip(float(current) * factor, lo, hi)), 4)

        if "int_uniform" in spec:
            lo, hi = int(spec["int_uniform"][0]), int(spec["int_uniform"][1])
            if not isinstance(current, (int, float)):
                return sample_value(spec, rng)
            delta = max(1, int(round(abs(float(current)) * scale)))
            value = int(current) + int(rng.integers(-delta, delta + 1))
            return int(np.clip(value, lo, hi))

        if "pair_uniform" in spec:
            lo, hi = int(spec["pair_uniform"][0]), int(spec["pair_uniform"][1])
            if not isinstance(current, (list, tuple)) or len(current) != 2:
                return sample_value(spec, rng)
            factor = 1.0 + float(rng.uniform(-scale, scale))
            a = int(np.clip(round(float(current[0]) * factor), lo, hi))
            b = int(np.clip(round(float(current[1]) * factor), lo, hi))
            return [min(a, b), max(a, b)]

    # choice / subset / explicit list: resample outright.
    return sample_value(spec, rng)


def describe_space(space: Mapping[str, Any]) -> dict[str, str]:
    """Return a human-readable one-line description of each parameter."""
    described: dict[str, str] = {}
    for key, spec in sorted(space.items()):
        if isinstance(spec, (list, tuple)):
            described[key] = f"grid over {len(spec)} explicit values: {list(spec)}"
        elif isinstance(spec, Mapping):
            name = next(iter(set(spec) & DISTRIBUTION_KEYS), "?")
            described[key] = f"{name}{spec.get(name)}"
        else:  # pragma: no cover - guarded by validate_space
            described[key] = str(spec)
    return described


def parameter_names(space: Mapping[str, Any]) -> Sequence[str]:
    """Return the sorted dotted keys of a space."""
    return sorted(space)
