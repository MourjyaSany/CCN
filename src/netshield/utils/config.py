"""Layered YAML configuration with deep-merge, dotted access and validation.

The configuration model is deliberately simple and explicit::

    config/default.yaml                      (base)
      -> config/network.yaml                 (merged under the "network" key)
        -> experiment block from config/experiments.yaml
          -> fuzzer-generated override
            -> --set key.path=value CLI overrides

Every layer is a *sparse* mapping deep-merged onto the previous one, so an
experiment only has to state what actually differs.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping

import yaml

from .logging_utils import get_logger
from .paths import repo_root, resolve

_LOG = get_logger(__name__)

DEFAULT_CONFIG_FILE = "config/default.yaml"
NETWORK_CONFIG_FILE = "config/network.yaml"
EXPERIMENTS_FILE = "config/experiments.yaml"
FUZZING_FILE = "config/fuzzing.yaml"


class ConfigError(ValueError):
    """Raised when a configuration is missing, malformed or internally invalid."""


# --------------------------------------------------------------------------- #
# merge / dotted-path helpers
# --------------------------------------------------------------------------- #
def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* onto *base* without mutating either.

    Mappings merge key-by-key; every other type (including lists) is replaced
    wholesale. Lists are intentionally *not* concatenated - an experiment that
    declares ``dst_ports: [80]`` means exactly that.

    Args:
        base: The lower-priority mapping.
        override: The higher-priority mapping.

    Returns:
        A new merged ``dict``.
    """
    result: dict[str, Any] = copy.deepcopy(dict(base))
    for key, value in override.items():
        if key in result and isinstance(result[key], Mapping) and isinstance(value, Mapping):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def get_path(data: Mapping[str, Any], dotted: str, default: Any = None) -> Any:
    """Read a dotted key such as ``a.b.c`` from a nested mapping.

    Args:
        data: Nested mapping to read from.
        dotted: Dot-separated key path.
        default: Value returned when any level of the path is missing.

    Returns:
        The value at *dotted*, or *default*.
    """
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return default
        node = node[part]
    return node


def set_path(data: MutableMapping[str, Any], dotted: str, value: Any) -> None:
    """Write ``a.b.c = value`` into a nested mapping, creating levels as needed.

    Args:
        data: Mutable nested mapping.
        dotted: Dot-separated key path.
        value: Value to store at the leaf.
    """
    parts = dotted.split(".")
    node: MutableMapping[str, Any] = data
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, MutableMapping):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value


def flatten(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten a nested mapping into ``{"a.b.c": value}`` form."""
    flat: dict[str, Any] = {}
    for key, value in data.items():
        path = f"{prefix}{key}"
        if isinstance(value, Mapping):
            flat.update(flatten(value, prefix=f"{path}."))
        else:
            flat[path] = value
    return flat


def parse_scalar(text: str) -> Any:
    """Parse a CLI ``--set`` value using YAML scalar rules.

    ``"3"`` becomes ``int``, ``"3.5"`` becomes ``float``, ``"true"`` becomes
    ``bool``, ``"[1,2]"`` becomes ``list``; anything else stays ``str``.
    """
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return text


# --------------------------------------------------------------------------- #
# Config object
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Config:
    """An immutable-by-convention configuration tree with dotted access.

    Attributes:
        data: The merged configuration mapping.
        sources: Provenance trail of every layer that contributed.
    """

    data: dict[str, Any]
    sources: list[str]

    # -- access ------------------------------------------------------------- #
    def get(self, dotted: str, default: Any = None) -> Any:
        """Return the value at *dotted*, or *default* when absent."""
        return get_path(self.data, dotted, default)

    def require(self, dotted: str) -> Any:
        """Return the value at *dotted* or raise :class:`ConfigError`."""
        sentinel = object()
        value = get_path(self.data, dotted, sentinel)
        if value is sentinel:
            raise ConfigError(f"Required configuration key '{dotted}' is missing.")
        return value

    def __getitem__(self, dotted: str) -> Any:
        return self.require(dotted)

    def __contains__(self, dotted: str) -> bool:
        sentinel = object()
        return get_path(self.data, dotted, sentinel) is not sentinel

    def section(self, name: str) -> dict[str, Any]:
        """Return a deep copy of a top-level (or dotted) section mapping."""
        value = self.get(name, {})
        if not isinstance(value, Mapping):
            raise ConfigError(f"Configuration section '{name}' is not a mapping.")
        return copy.deepcopy(dict(value))

    # -- derivation --------------------------------------------------------- #
    def merged(self, override: Mapping[str, Any], source: str = "<override>") -> "Config":
        """Return a new :class:`Config` with *override* deep-merged on top."""
        return Config(deep_merge(self.data, override), [*self.sources, source])

    def with_set(self, assignments: Iterable[str]) -> "Config":
        """Apply ``key.path=value`` strings and return a new :class:`Config`.

        Args:
            assignments: Iterable of ``key=value`` strings.

        Returns:
            A new configuration with the assignments applied.

        Raises:
            ConfigError: If an assignment is not of the form ``key=value``.
        """
        data = copy.deepcopy(self.data)
        applied: list[str] = []
        for item in assignments:
            if "=" not in item:
                raise ConfigError(f"--set expects key=value, got: {item!r}")
            key, _, raw = item.partition("=")
            set_path(data, key.strip(), parse_scalar(raw.strip()))
            applied.append(key.strip())
        joined = ",".join(applied)
        return Config(data, [*self.sources, f"--set({joined})"])

    # -- paths -------------------------------------------------------------- #
    def path(self, key: str) -> Path:
        """Resolve a ``paths.*`` entry to an absolute :class:`~pathlib.Path`."""
        raw = self.get(f"paths.{key}")
        if raw is None:
            raise ConfigError(f"Unknown path key 'paths.{key}'.")
        return resolve(str(raw))

    # -- serialisation ------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        """Return a deep copy of the underlying mapping."""
        return copy.deepcopy(self.data)

    def to_yaml(self) -> str:
        """Serialise to YAML (used to snapshot a run's exact configuration)."""
        return yaml.safe_dump(self.data, sort_keys=False, default_flow_style=False)

    def save(self, path: str | Path) -> Path:
        """Write the configuration snapshot next to a run's artefacts."""
        target = resolve(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_yaml(), encoding="utf-8")
        return target

    def fingerprint(self) -> str:
        """Return a stable short hash of the configuration (run identity)."""
        import hashlib

        blob = json.dumps(self.data, sort_keys=True, default=str).encode("utf-8")
        return hashlib.blake2b(blob, digest_size=6).hexdigest()


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #
def _read_yaml(path: Path) -> dict[str, Any]:
    """Read a YAML file that must contain a top-level mapping."""
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if loaded is None:
        return {}
    if not isinstance(loaded, Mapping):
        raise ConfigError(f"Configuration file {path} must contain a mapping at top level.")
    return dict(loaded)


def _relative_label(path: Path) -> str:
    """Return a repo-relative label for provenance, falling back to the name."""
    try:
        return str(path.relative_to(repo_root()))
    except ValueError:
        return path.name


def load_config(
    default_file: str | Path = DEFAULT_CONFIG_FILE,
    network_file: str | Path | None = NETWORK_CONFIG_FILE,
    overrides: Mapping[str, Any] | None = None,
    set_args: Iterable[str] | None = None,
    validate_config: bool = True,
) -> Config:
    """Load the layered configuration.

    Args:
        default_file: Base YAML file.
        network_file: Topology YAML, merged under the top-level ``network`` key.
        overrides: Sparse mapping merged after the files (experiment/fuzzer).
        set_args: Iterable of ``key.path=value`` CLI assignments (highest prio).
        validate_config: Run :func:`validate` before returning.

    Returns:
        The fully merged :class:`Config`.

    Raises:
        ConfigError: If a file is missing or the merged tree is invalid.
    """
    base_path = resolve(default_file)
    data = _read_yaml(base_path)
    sources = [_relative_label(base_path)]

    if network_file is not None:
        net_path = resolve(network_file)
        data = deep_merge(data, {"network": _read_yaml(net_path)})
        sources.append(_relative_label(net_path))

    if overrides:
        data = deep_merge(data, overrides)
        sources.append("<overrides>")

    cfg = Config(data, sources)
    if set_args:
        cfg = cfg.with_set(set_args)
    if validate_config:
        validate(cfg)
    return cfg


def load_experiments(path: str | Path = EXPERIMENTS_FILE) -> dict[str, Any]:
    """Load and return ``config/experiments.yaml``."""
    return _read_yaml(resolve(path))


def load_fuzzing_config(path: str | Path = FUZZING_FILE) -> dict[str, Any]:
    """Load and return ``config/fuzzing.yaml``."""
    return _read_yaml(resolve(path))


def experiment_names(experiments: Mapping[str, Any] | None = None) -> list[str]:
    """Return the ordered list of declared experiment names."""
    doc = dict(experiments) if experiments is not None else load_experiments()
    return list((doc.get("experiments") or {}).keys())


def experiment_config(
    name: str,
    experiments: Mapping[str, Any] | None = None,
    set_args: Iterable[str] | None = None,
) -> tuple[Config, dict[str, Any]]:
    """Build the :class:`Config` for a named experiment.

    Args:
        name: Experiment key inside ``config/experiments.yaml``.
        experiments: Pre-loaded experiments mapping (loaded from disk if None).
        set_args: Extra ``key=value`` CLI overrides applied last.

    Returns:
        A ``(config, metadata)`` tuple; metadata carries description and tags.

    Raises:
        ConfigError: If the experiment name is unknown.
    """
    doc = dict(experiments) if experiments is not None else load_experiments()
    table = doc.get("experiments") or {}
    if name not in table:
        known = ", ".join(sorted(table)) or "<none>"
        raise ConfigError(f"Unknown experiment '{name}'. Available: {known}")

    entry = table[name] or {}
    override = deep_merge(doc.get("defaults") or {}, entry.get("config") or {})
    cfg = load_config(overrides=override, set_args=set_args)
    meta = {
        "experiment": name,
        "description": str(entry.get("description", "")).strip(),
        "tags": list(entry.get("tags", [])),
        "holdout": bool(entry.get("holdout", False)),
    }
    return cfg, meta


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #
_POSITIVE_KEYS: tuple[str, ...] = (
    "simulation.duration_s",
    "features.window_s",
    "features.flow_timeout_s",
    "network.topology.access_link.bandwidth_bps",
    "network.topology.gateway.uplink.bandwidth_bps",
    "network.topology.routers.uplink.bandwidth_bps",
)

_NON_NEGATIVE_INT_KEYS: tuple[str, ...] = (
    "simulation.n_iot_devices",
    "simulation.n_attackers",
    "network.topology.routers.count",
)

VALID_ATTACK_TYPES: frozenset[str] = frozenset(
    {
        "udp_flood",
        "syn_flood",
        "http_flood",
        "icmp_flood",
        "ack_flood",
        "slowloris",
        "mixed",
    }
)
VALID_ENGINES: frozenset[str] = frozenset({"auto", "ns3", "python"})
VALID_RATE_PROFILES: frozenset[str] = frozenset(
    {"constant", "ramp", "sine", "step"}
)
VALID_TOPOLOGY_FAMILIES: frozenset[str] = frozenset(
    {"tree", "star", "multi_gateway", "dumbbell", "fat_tree", "mesh", "ring"}
)


def validate(cfg: Config) -> Config:
    """Validate structural invariants of a merged configuration.

    Args:
        cfg: The configuration to check.

    Returns:
        The same configuration object (for call chaining).

    Raises:
        ConfigError: On the first invariant violation, with a precise message.
    """
    for key in _POSITIVE_KEYS:
        value = cfg.get(key)
        if value is None:
            raise ConfigError(f"Missing required numeric key '{key}'.")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ConfigError(f"'{key}' must be a positive number, got {value!r}.")

    for key in _NON_NEGATIVE_INT_KEYS:
        value = cfg.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ConfigError(f"'{key}' must be a non-negative integer, got {value!r}.")

    if int(cfg.get("simulation.n_iot_devices", 0)) < 1:
        raise ConfigError("simulation.n_iot_devices must be >= 1.")
    if int(cfg.get("network.topology.routers.count", 0)) < 1:
        raise ConfigError("network.topology.routers.count must be >= 1.")

    engine = str(cfg.get("simulation.engine", "auto")).lower()
    if engine not in VALID_ENGINES:
        raise ConfigError(f"simulation.engine must be auto|ns3|python, got {engine!r}.")

    window = float(cfg.require("features.window_s"))
    duration = float(cfg.require("simulation.duration_s"))
    if window > duration:
        raise ConfigError(
            f"features.window_s ({window}) exceeds simulation.duration_s ({duration}); "
            "no feature window could be produced."
        )

    family = str(cfg.get("network.topology.family", "tree")).lower()
    if family not in VALID_TOPOLOGY_FAMILIES:
        raise ConfigError(
            "network.topology.family must be one of "
            f"{sorted(VALID_TOPOLOGY_FAMILIES)}, got {family!r}."
        )

    if bool(cfg.get("attack.enabled", False)):
        start = float(cfg.get("attack.start_s", 0.0))
        attack_duration = float(cfg.get("attack.duration_s", 0.0))
        if start < 0:
            raise ConfigError("attack.start_s must be >= 0.")
        if attack_duration <= 0:
            raise ConfigError("attack.duration_s must be > 0 when the attack is enabled.")
        if start >= duration:
            raise ConfigError(
                f"attack.start_s ({start}) is at or beyond simulation.duration_s "
                f"({duration}); the attack would never fire."
            )
        if int(cfg.get("simulation.n_attackers", 0)) < 1:
            raise ConfigError("attack.enabled is true but simulation.n_attackers is 0.")

        atype = str(cfg.get("attack.type", "")).lower()
        if atype not in VALID_ATTACK_TYPES:
            raise ConfigError(
                "attack.type must be one of "
                f"{sorted(VALID_ATTACK_TYPES)}, got {atype!r}."
            )

        pps = cfg.get("attack.packets_per_second", 0.0)
        if not isinstance(pps, (int, float)) or float(pps) <= 0:
            raise ConfigError(f"attack.packets_per_second must be > 0, got {pps!r}.")

        sizes = cfg.get("attack.packet_bytes", None)
        if not isinstance(sizes, (list, tuple)) or len(sizes) != 2:
            raise ConfigError(f"attack.packet_bytes must be a [lo, hi] pair, got {sizes!r}.")
        lo, hi = int(sizes[0]), int(sizes[1])
        if not 0 < lo <= hi <= 1500:
            raise ConfigError(
                f"attack.packet_bytes must satisfy 0 < lo <= hi <= 1500, got [{lo}, {hi}]."
            )

        shape = str(cfg.get("attack.shape.profile", "constant")).lower()
        if shape not in VALID_RATE_PROFILES:
            raise ConfigError(
                "attack.shape.profile must be one of "
                f"{sorted(VALID_RATE_PROFILES)}, got {shape!r}."
            )

        jitter = cfg.get("attack.rate_jitter", [1.0, 1.0])
        if not isinstance(jitter, (list, tuple)) or len(jitter) != 2:
            raise ConfigError(
                f"attack.rate_jitter must be a [lo, hi] pair, got {jitter!r}."
            )
        if not (0 < float(jitter[0]) <= float(jitter[1])):
            raise ConfigError(
                "attack.rate_jitter must satisfy 0 < lo <= hi, got "
                f"[{jitter[0]}, {jitter[1]}]."
            )

        if float(cfg.get("attack.stagger_s", 0.0)) < 0:
            raise ConfigError("attack.stagger_s must be >= 0.")

        ports = cfg.get("attack.dst_ports", [])
        if not isinstance(ports, (list, tuple)) or not ports:
            raise ConfigError("attack.dst_ports must be a non-empty list.")
        # ICMP has no port field at all, so port 0 is the correct - and only
        # meaningful - value for an ICMP flood. It stays invalid for every
        # port-bearing protocol.
        lowest = 0 if atype == "icmp_flood" else 1
        for port in ports:
            valid = (
                not isinstance(port, bool)
                and isinstance(port, int)
                and lowest <= port < 65536
            )
            if not valid:
                raise ConfigError(f"Invalid destination port {port!r} in attack.dst_ports.")

    malicious = float(cfg.get("features.label_malicious_threshold", 0.5))
    suspicious = float(cfg.get("features.label_suspicious_threshold", 0.1))
    if not 0.0 < suspicious < malicious <= 1.0:
        raise ConfigError(
            "features label thresholds must satisfy 0 < suspicious < malicious <= 1, "
            f"got suspicious={suspicious}, malicious={malicious}."
        )

    trigger = float(cfg.get("detection.mitigation_trigger_probability", 0.8))
    if not 0.0 < trigger <= 1.0:
        raise ConfigError(
            f"detection.mitigation_trigger_probability must be in (0, 1], got {trigger}."
        )

    return cfg
