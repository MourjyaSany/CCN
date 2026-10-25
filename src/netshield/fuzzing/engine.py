"""Dynamic fuzzing engine for DDoS attack parameters.

Purpose
-------
A detector trained on six hand-written attack scenarios has only been shown six
points of a large parameter space. The fuzzer explores that space systematically
so we can answer the question the report actually needs to answer: *does the
detector still work when the attacker changes the knobs?*

Safety
------
The fuzzer mutates **configuration values only**. Its output is a list of
:class:`FuzzCase` objects, each of which is a sparse override merged onto the
project configuration and handed to the in-memory simulator. It has no network
access, no filesystem write path outside ``data/`` and ``results/``, and it
cannot address anything outside the simulated topology.

Strategies
----------
``grid``
    Exhaustive Cartesian sweep of explicit value lists. Deterministic and
    complete; used for the one-dimensional robustness sweeps in the report.
``random``
    Independent draws from the declared distributions. Explores combinations no
    human would think to write down.
``mutation``
    A seeded random walk: each generation perturbs a parent by a bounded
    multiplicative delta, producing a locally dense sample around a baseline.
``adaptive``
    Greedy evasion search. Cases are scored by a caller-supplied objective (in
    this project, the detector's recall on the attacker nodes) and the
    lowest-scoring cases are preferentially re-mutated. This is a coverage-guided
    fuzzer in the classical sense, with "coverage" replaced by "detector
    weakness", and it is what produces the evidence for the Limitations section.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import numpy as np

from ..utils.config import Config, deep_merge, load_fuzzing_config, set_path
from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_parent, resolve
from ..utils.seeding import rng_for
from .space import (
    SpaceError,
    describe_space,
    grid_points,
    grid_size,
    mutate_point,
    sample_point,
    validate_space,
)

_LOG = get_logger(__name__)

#: Strategies understood by :class:`FuzzEngine`.
STRATEGIES: tuple[str, ...] = ("grid", "random", "mutation", "adaptive")

#: Hard cap on the number of cases a single campaign may generate, so a badly
#: written grid cannot launch thousands of simulations by accident.
MAX_CASES_PER_CAMPAIGN: int = 512


class FuzzError(ValueError):
    """Raised when a campaign definition is invalid."""


@dataclass(slots=True)
class FuzzCase:
    """One generated attack-parameter variant.

    Attributes:
        case_id: Stable identifier, ``"<campaign>-<index:03d>"``.
        campaign: Campaign name from ``config/fuzzing.yaml``.
        strategy: The strategy that produced this case.
        index: Zero-based index within the campaign.
        seed: Simulation seed assigned to this case.
        base_experiment: Experiment whose configuration is used as the baseline.
        assignments: ``{dotted_key: value}`` overrides applied to the baseline.
        parent: ``case_id`` of the parent case for mutation/adaptive strategies.
        generation: Mutation depth (0 for seed cases).
        score: Objective value assigned by an adaptive campaign, when scored.
    """

    case_id: str
    campaign: str
    strategy: str
    index: int
    seed: int
    base_experiment: str
    assignments: dict[str, Any]
    parent: str | None = None
    generation: int = 0
    score: float | None = None

    def overrides(self) -> dict[str, Any]:
        """Return the assignments as a nested override mapping.

        Returns:
            A nested dict suitable for
            :func:`netshield.utils.config.deep_merge`, with the case seed
            included so every case is independently reproducible.
        """
        nested: dict[str, Any] = {}
        for dotted, value in self.assignments.items():
            set_path(nested, dotted, value)
        set_path(nested, "seed", self.seed)
        return nested

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the case."""
        return {
            "case_id": self.case_id,
            "campaign": self.campaign,
            "strategy": self.strategy,
            "index": self.index,
            "seed": self.seed,
            "base_experiment": self.base_experiment,
            "assignments": dict(self.assignments),
            "parent": self.parent,
            "generation": self.generation,
            "score": self.score,
        }


@dataclass(slots=True)
class CampaignSpec:
    """A parsed campaign definition from ``config/fuzzing.yaml``.

    Attributes:
        name: Campaign key.
        description: Free-text purpose statement.
        strategy: One of :data:`STRATEGIES`.
        seed: Master seed - fully determines the generated corpus.
        base: Baseline experiment name.
        space: Parameter-space declaration.
        n_samples: Number of cases for non-grid strategies.
        population: Elite population size for the adaptive strategy.
        mutation_rate: Per-parameter mutation probability.
        scale: Maximum relative perturbation for numeric parameters.
    """

    name: str
    description: str
    strategy: str
    seed: int
    base: str
    space: dict[str, Any]
    n_samples: int = 10
    population: int = 4
    mutation_rate: float = 0.4
    scale: float = 0.5

    @classmethod
    def from_mapping(cls, name: str, data: Mapping[str, Any]) -> "CampaignSpec":
        """Parse one campaign entry.

        Args:
            name: Campaign key.
            data: The YAML mapping for this campaign.

        Returns:
            The parsed :class:`CampaignSpec`.

        Raises:
            FuzzError: If the strategy is unknown or the space is malformed.
        """
        strategy = str(data.get("strategy", "random")).lower()
        if strategy not in STRATEGIES:
            raise FuzzError(
                f"Campaign '{name}': unknown strategy {strategy!r}; "
                f"expected one of {STRATEGIES}."
            )
        space = dict(data.get("space", {}) or {})
        try:
            validate_space(space)
        except SpaceError as exc:
            raise FuzzError(f"Campaign '{name}': {exc}") from exc

        mutation = data.get("mutation", {}) or {}
        return cls(
            name=name,
            description=str(data.get("description", "")).strip(),
            strategy=strategy,
            seed=int(data.get("seed", 0)),
            base=str(data.get("base", "exp2_udp_flood")),
            space=space,
            n_samples=int(data.get("n_samples", 10)),
            population=int(data.get("population", 4)),
            mutation_rate=float(mutation.get("mutation_rate", 0.4)),
            scale=float(mutation.get("scale", 0.5)),
        )


class FuzzEngine:
    """Generates reproducible attack-parameter variants for a campaign.

    Args:
        spec: The parsed campaign definition.

    Example:
        >>> engine = FuzzEngine(CampaignSpec.from_mapping("s", {
        ...     "strategy": "random", "seed": 7, "n_samples": 3,
        ...     "space": {"attack.packets_per_second": {"uniform": [100, 200]}}}))
        >>> a = [c.assignments for c in engine.generate()]
        >>> b = [c.assignments for c in FuzzEngine(engine.spec).generate()]
        >>> a == b
        True
    """

    def __init__(self, spec: CampaignSpec) -> None:
        self.spec = spec
        self._rng: np.random.Generator = rng_for(spec.seed, "fuzz", spec.name)

    # ------------------------------------------------------------------ #
    def reset(self) -> None:
        """Rewind the generator so a campaign can be regenerated identically."""
        self._rng = rng_for(self.spec.seed, "fuzz", self.spec.name)

    def describe(self) -> dict[str, Any]:
        """Return a JSON-serialisable description of the campaign."""
        return {
            "name": self.spec.name,
            "description": self.spec.description,
            "strategy": self.spec.strategy,
            "seed": self.spec.seed,
            "base_experiment": self.spec.base,
            "n_cases": self.planned_case_count(),
            "parameters": describe_space(self.spec.space),
        }

    def planned_case_count(self) -> int:
        """Return how many cases :meth:`generate` will produce."""
        if self.spec.strategy == "grid":
            return min(grid_size(self.spec.space), MAX_CASES_PER_CAMPAIGN)
        return min(max(1, self.spec.n_samples), MAX_CASES_PER_CAMPAIGN)

    def _case_seed(self, index: int) -> int:
        """Derive this case's simulation seed from the campaign seed."""
        return int(self.spec.seed * 1000 + index)

    def _make_case(
        self,
        index: int,
        assignments: Mapping[str, Any],
        parent: str | None = None,
        generation: int = 0,
    ) -> FuzzCase:
        """Wrap an assignment into a :class:`FuzzCase`."""
        return FuzzCase(
            case_id=f"{self.spec.name}-{index:03d}",
            campaign=self.spec.name,
            strategy=self.spec.strategy,
            index=index,
            seed=self._case_seed(index),
            base_experiment=self.spec.base,
            assignments=dict(assignments),
            parent=parent,
            generation=generation,
        )

    # ------------------------------------------------------------------ #
    def generate(self) -> list[FuzzCase]:
        """Generate the campaign's cases (grid / random / mutation).

        For the ``adaptive`` strategy this returns only the initial random
        population; call :meth:`run_adaptive` to drive the full search.

        Returns:
            The generated cases, in deterministic order.
        """
        self.reset()
        strategy = self.spec.strategy

        if strategy == "grid":
            cases = [
                self._make_case(i, point)
                for i, point in enumerate(grid_points(self.spec.space))
                if i < MAX_CASES_PER_CAMPAIGN
            ]
            total = grid_size(self.spec.space)
            if total > MAX_CASES_PER_CAMPAIGN:
                _LOG.warning(
                    "Campaign '%s': grid has %d points, truncated to the cap of %d.",
                    self.spec.name, total, MAX_CASES_PER_CAMPAIGN,
                )
            return cases

        if strategy in ("random", "adaptive"):
            count = self.planned_case_count()
            if strategy == "adaptive":
                count = min(count, max(2, self.spec.population))
            return [
                self._make_case(i, sample_point(self.spec.space, self._rng))
                for i in range(count)
            ]

        # mutation: one random seed point, then a walk.
        count = self.planned_case_count()
        cases: list[FuzzCase] = []
        current = sample_point(self.spec.space, self._rng)
        cases.append(self._make_case(0, current))
        for i in range(1, count):
            current = mutate_point(
                current, self.spec.space, self._rng,
                mutation_rate=self.spec.mutation_rate, scale=self.spec.scale,
            )
            cases.append(self._make_case(i, current, parent=cases[-1].case_id,
                                         generation=i))
        return cases

    # ------------------------------------------------------------------ #
    def run_adaptive(
        self,
        evaluate: Callable[[FuzzCase], float],
        n_samples: int | None = None,
    ) -> list[FuzzCase]:
        """Drive a greedy evasion search using a caller-supplied objective.

        The objective should return **lower values for better evasion** (e.g.
        the detector's recall on the attacker nodes). The engine keeps the
        ``population`` lowest-scoring cases and mutates them to produce the next
        candidate, which is exactly a coverage-guided fuzzer with "detector
        weakness" as the coverage signal.

        Args:
            evaluate: Callable scoring one case; must be deterministic given the
                case, or the search becomes non-reproducible.
            n_samples: Total number of cases to evaluate; defaults to the
                campaign's ``n_samples``.

        Returns:
            Every evaluated case, each with :attr:`FuzzCase.score` populated,
            sorted by score ascending (best evasion first).
        """
        budget = int(n_samples or self.spec.n_samples)
        self.reset()

        population: list[FuzzCase] = []
        evaluated: list[FuzzCase] = []
        seed_count = min(max(2, self.spec.population), budget)

        for index in range(seed_count):
            case = self._make_case(index, sample_point(self.spec.space, self._rng))
            case.score = float(evaluate(case))
            evaluated.append(case)
            population.append(case)
            _LOG.info("  [adaptive] %s seed score=%.4f", case.case_id, case.score)

        for index in range(seed_count, budget):
            population.sort(key=lambda c: (c.score if c.score is not None else 1e9))
            elite = population[: max(1, self.spec.population)]
            parent = elite[int(self._rng.integers(0, len(elite)))]
            child = self._make_case(
                index,
                mutate_point(
                    parent.assignments, self.spec.space, self._rng,
                    mutation_rate=self.spec.mutation_rate, scale=self.spec.scale,
                ),
                parent=parent.case_id,
                generation=parent.generation + 1,
            )
            child.score = float(evaluate(child))
            evaluated.append(child)
            population.append(child)
            _LOG.info(
                "  [adaptive] %s (gen %d from %s) score=%.4f",
                child.case_id, child.generation, parent.case_id, child.score,
            )

        evaluated.sort(key=lambda c: (c.score if c.score is not None else 1e9))
        return evaluated


# --------------------------------------------------------------------------- #
# campaign loading / configuration materialisation
# --------------------------------------------------------------------------- #
def load_campaign(name: str, path: str | Path | None = None) -> CampaignSpec:
    """Load one campaign definition from ``config/fuzzing.yaml``.

    Args:
        name: Campaign key.
        path: Optional override path to the fuzzing config.

    Returns:
        The parsed :class:`CampaignSpec`.

    Raises:
        FuzzError: If the campaign does not exist.
    """
    doc = load_fuzzing_config(path) if path else load_fuzzing_config()
    campaigns = doc.get("campaigns", {}) or {}
    if name not in campaigns:
        known = ", ".join(sorted(campaigns)) or "<none>"
        raise FuzzError(f"Unknown fuzzing campaign '{name}'. Available: {known}")
    return CampaignSpec.from_mapping(name, campaigns[name] or {})


def campaign_names(path: str | Path | None = None) -> list[str]:
    """Return every declared campaign name."""
    doc = load_fuzzing_config(path) if path else load_fuzzing_config()
    return sorted((doc.get("campaigns") or {}).keys())


def materialise(case: FuzzCase, base_config: Config) -> Config:
    """Apply a fuzz case's overrides to a baseline configuration.

    Args:
        case: The case to materialise.
        base_config: The baseline experiment configuration.

    Returns:
        A new validated :class:`~netshield.utils.config.Config`.

    Raises:
        netshield.utils.config.ConfigError: If the fuzzed configuration violates
            a structural invariant (e.g. an attack that starts after the run
            ends). Invalid cases are a normal outcome of fuzzing and are meant
            to be caught and skipped by the caller.
    """
    from ..utils.config import Config as _Config, validate

    merged = deep_merge(base_config.data, case.overrides())
    fuzzed = _Config(merged, [*base_config.sources, f"fuzz:{case.case_id}"])
    return validate(fuzzed)


def save_cases(cases: Sequence[FuzzCase], path: str | Path) -> Path:
    """Write a campaign's cases to JSON for reproducibility and reporting."""
    target = ensure_parent(path)
    payload = [case.to_dict() for case in cases]
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _LOG.info("Wrote %d fuzz cases -> %s", len(cases), target)
    return target


def load_cases(path: str | Path) -> list[FuzzCase]:
    """Read cases previously written by :func:`save_cases`."""
    source = resolve(path)
    if not source.exists():
        raise FileNotFoundError(f"Fuzz case file not found: {source}")
    payload = json.loads(source.read_text(encoding="utf-8"))
    return [
        FuzzCase(
            case_id=item["case_id"],
            campaign=item["campaign"],
            strategy=item["strategy"],
            index=int(item["index"]),
            seed=int(item["seed"]),
            base_experiment=item["base_experiment"],
            assignments=dict(item["assignments"]),
            parent=item.get("parent"),
            generation=int(item.get("generation", 0)),
            score=item.get("score"),
        )
        for item in payload
    ]


def cases_to_frame(cases: Iterable[FuzzCase]) -> Any:
    """Return a tidy :class:`pandas.DataFrame` of cases for plotting.

    Args:
        cases: The cases to tabulate.

    Returns:
        One row per case with the assignments flattened into columns.
    """
    import pandas as pd

    rows: list[dict[str, Any]] = []
    for case in cases:
        row: dict[str, Any] = {
            "case_id": case.case_id,
            "campaign": case.campaign,
            "strategy": case.strategy,
            "seed": case.seed,
            "generation": case.generation,
            "parent": case.parent,
            "score": case.score,
        }
        for key, value in case.assignments.items():
            row[key] = json.dumps(value) if isinstance(value, (list, dict)) else value
        rows.append(row)
    return pd.DataFrame(rows)
