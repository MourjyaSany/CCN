"""Shared pytest fixtures.

The fixtures here deliberately run *real* simulations rather than using mocks.
The point of the test suite is to prove that the network model behaves like a
network - that queues fill, that SYN floods exhaust a backlog, that mitigation
actually drops packets - and a mock cannot show any of that. Every fixture is
sized so the whole suite finishes in well under a minute.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from netshield.utils.config import Config, experiment_config, load_config  # noqa: E402
from netshield.utils.logging_utils import setup_logging  # noqa: E402

setup_logging(level="WARNING", force=True)

#: Short duration used by every simulation-backed test.
TEST_DURATION_S = 25.0
#: Attack timing that fits inside TEST_DURATION_S with clean window alignment.
TEST_ATTACK_START_S = 10.0
TEST_ATTACK_DURATION_S = 10.0


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """The repository root directory."""
    return REPO_ROOT


@pytest.fixture(scope="session")
def base_config() -> Config:
    """The default merged configuration."""
    return load_config()


@pytest.fixture(scope="session")
def benign_config() -> Config:
    """A short benign scenario."""
    cfg, _ = experiment_config("exp1_normal")
    return cfg.with_set([
        f"simulation.duration_s={TEST_DURATION_S}",
        "simulation.n_iot_devices=10",
        "network.topology.routers.count=2",
    ])


@pytest.fixture(scope="session")
def attack_config() -> Config:
    """A short volumetric UDP-flood scenario that genuinely congests the uplink.

    The rate is chosen from the link budget, not picked by feel. A 512-byte
    payload becomes a 558-byte frame (512 + 8 UDP + 20 IPv4 + 18 Ethernet), so
    three attackers at 2000 packets/second offer

        3 x 2000 x 558 x 8  =  26.8 Mbit/s

    against a 20 Mbit/s gateway uplink. That is ~1.34x capacity, which is enough
    to fill the drop-tail buffer and produce measurable loss and queueing delay
    within the short test duration. A rate that merely approaches capacity would
    leave the congestion assertions testing nothing.
    """
    cfg, _ = experiment_config("exp2_udp_flood")
    return cfg.with_set([
        f"simulation.duration_s={TEST_DURATION_S}",
        "simulation.n_iot_devices=10",
        "simulation.n_attackers=3",
        "network.topology.routers.count=2",
        f"attack.start_s={TEST_ATTACK_START_S}",
        f"attack.duration_s={TEST_ATTACK_DURATION_S}",
        "attack.packets_per_second=2000",
    ])


@pytest.fixture(scope="session")
def syn_flood_config() -> Config:
    """A short SYN-flood scenario with spoofed sources."""
    cfg, _ = experiment_config("exp3_syn_flood")
    return cfg.with_set([
        f"simulation.duration_s={TEST_DURATION_S}",
        "simulation.n_iot_devices=8",
        "simulation.n_attackers=2",
        "network.topology.routers.count=2",
        f"attack.start_s={TEST_ATTACK_START_S}",
        f"attack.duration_s={TEST_ATTACK_DURATION_S}",
        "attack.packets_per_second=700",
    ])


@pytest.fixture(scope="session")
def benign_result(benign_config: Config) -> Any:
    """A completed benign simulation run."""
    from netshield.simulation.runner import run_simulation

    return run_simulation(benign_config, {"experiment": "test_benign"})


@pytest.fixture(scope="session")
def attack_result(attack_config: Config) -> Any:
    """A completed UDP-flood simulation run."""
    from netshield.simulation.runner import run_simulation

    return run_simulation(attack_config, {"experiment": "test_attack"})


@pytest.fixture(scope="session")
def syn_flood_result(syn_flood_config: Config) -> Any:
    """A completed SYN-flood simulation run."""
    from netshield.simulation.runner import run_simulation

    return run_simulation(syn_flood_config, {"experiment": "test_syn"})


@pytest.fixture(scope="session")
def corpus(benign_result: Any, attack_result: Any, syn_flood_result: Any,
           base_config: Config) -> Any:
    """A small labelled corpus built from the three fixture runs."""
    from netshield.features.dataset import build_dataset

    return build_dataset([benign_result, attack_result, syn_flood_result], base_config)


@pytest.fixture(scope="session")
def corpus_edges(benign_result: Any, attack_result: Any, syn_flood_result: Any) -> Any:
    """The edge table matching :func:`corpus`."""
    from netshield.graph.builder import edge_table_from_results

    return edge_table_from_results([benign_result, attack_result, syn_flood_result])


@pytest.fixture(scope="session")
def detection_input(corpus: Any, corpus_edges: Any) -> Any:
    """A :class:`DetectionInput` over the whole fixture corpus."""
    from netshield.models.base import DetectionInput

    return DetectionInput(corpus, corpus_edges)
