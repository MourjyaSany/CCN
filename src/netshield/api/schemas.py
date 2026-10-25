"""Pydantic request/response models.

These types are what FastAPI turns into the OpenAPI document served at
``/docs``, so the field descriptions here are the API documentation.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Liveness and capability report."""

    status: str = Field(description="Always 'ok' when the API is serving.")
    version: str = Field(description="Project version.")
    engine: str = Field(description="Simulation engine that will be used.")
    ns3_available: bool = Field(description="Whether a usable NS-3 was detected.")
    gnn_backend: str = Field(description="GraphSAGE backend actually in use.")
    detectors_loaded: list[str] = Field(description="Trained detectors available.")
    database: str = Field(description="Path to the SQLite database.")
    dataset_available: bool = Field(description="Whether a generated corpus exists.")


class ScenarioInfo(BaseModel):
    """One runnable scenario from ``config/experiments.yaml``."""

    name: str
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    n_iot_devices: int = 0
    n_attackers: int = 0
    duration_s: float = 0.0
    attack_type: str = ""
    attack_start_s: float | None = None
    attack_duration_s: float | None = None
    mitigation_enabled: bool = False
    holdout: bool = False


class StartSimulationRequest(BaseModel):
    """Body of ``POST /api/simulation/start``."""

    scenario: str = Field(
        default="exp8_mitigation",
        description="Experiment name from config/experiments.yaml.",
    )
    speed: float = Field(
        default=5.0, ge=0.0, le=100.0,
        description="Simulated seconds per wall-clock second; 0 runs as fast as "
                    "possible (no live pacing).",
    )
    mitigation: bool | None = Field(
        default=None,
        description="Force the closed mitigation loop on or off. Null uses the "
                    "scenario's own setting.",
    )
    detector: str = Field(
        default="graphsage",
        description="Detector driving detection and mitigation.",
    )
    duration_s: float | None = Field(
        default=None, gt=0.0,
        description="Override the simulated duration.",
    )
    overrides: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Sparse dotted-key configuration overrides, e.g. "
            "{'attack.type': 'slowloris', 'attack.packets_per_second': 800}. "
            "Only keys under the allowlisted prefixes are accepted "
            "(attack.*, network.topology.*, simulation.n_iot_devices, "
            "simulation.n_attackers, mitigation.*, detection.*, features.*): "
            "the API deliberately exposes no host, port, interface or "
            "real-world target parameter, so it cannot be repurposed to "
            "generate traffic outside the simulator."
        ),
    )


class CustomAttackRequest(BaseModel):
    """Body of ``POST /api/attack/preview``: validate a builder configuration."""

    overrides: dict[str, Any] = Field(
        default_factory=dict,
        description="Dotted-key overrides to validate, same allowlist as start.",
    )
    scenario: str = Field(
        default="exp2_udp_flood",
        description="Base scenario the overrides are merged onto.",
    )


class TopologyFamilyInfo(BaseModel):
    """One entry of ``GET /api/topologies``."""

    name: str = Field(description="Family identifier used in configuration.")
    description: str = Field(description="What structural assumption it changes.")
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Family-specific tunables and their configured defaults.",
    )


class AttackFamilyInfo(BaseModel):
    """One entry of ``GET /api/attacks``."""

    name: str = Field(description="Attack family identifier.")
    description: str = Field(description="What the family exhausts, and how.")
    layer: str = Field(description="volumetric | protocol | application | mixed.")


class FigureInfo(BaseModel):
    """One entry of ``GET /api/figures``."""

    name: str = Field(description="File name within results/figures.")
    url: str = Field(description="Path to fetch the image from.")
    size_bytes: int = Field(description="File size on disk.")
    experiment: str = Field(default="", description="Owning experiment, if any.")


class SimulationStatus(BaseModel):
    """State of the live simulation session."""

    state: str = Field(description="idle | running | stopping | completed | failed")
    scenario: str = ""
    run_id: str = ""
    engine_label: str = ""
    sim_time_s: float = 0.0
    duration_s: float = 0.0
    progress: float = Field(default=0.0, description="Completion fraction in [0, 1].")
    mitigation_enabled: bool = False
    detector: str = ""
    error: str = ""


class NetworkStatus(BaseModel):
    """Aggregate live status of the simulated network."""

    state: str
    scenario: str = ""
    run_id: str = ""
    engine_label: str = ""
    sim_time_s: float = 0.0
    duration_s: float = 0.0
    progress: float = 0.0
    n_devices: int = 0
    n_routers: int = 0
    n_suspicious: int = 0
    n_malicious: int = 0
    n_mitigated: int = 0
    active_attack: bool = False
    attack_type: str = ""
    packets_per_second: float = 0.0
    throughput_mbps: float = 0.0
    latency_ms: float = 0.0
    clean_latency_ms: float = Field(
        default=0.0,
        description="Mean end-to-end delay for devices that were never "
                    "compromised - the service-level number.",
    )
    packet_loss: float = 0.0
    clean_packet_loss: float = Field(
        default=0.0,
        description="Packet loss for never-compromised devices. Isolating a "
                    "bot also severs that bot's own legitimate telemetry, "
                    "which is an intended consequence of the defence rather "
                    "than a failure of it, so the two populations are "
                    "reported separately.",
    )
    uplink_utilisation: float = 0.0
    max_confidence: float = 0.0
    detector: str = ""


class TopologyNode(BaseModel):
    """A node in the topology view."""

    node_id: str
    kind: str
    ip: str = ""
    device_class: str = ""
    tier: int = 3
    parent: str | None = None
    is_attacker: bool = False
    probability: float = 0.0
    predicted: str = "BENIGN"
    packet_rate: float = 0.0
    mitigation: str = ""


class TopologyLink(BaseModel):
    """A physical link in the topology view."""

    source: str
    target: str
    bandwidth_bps: float = 0.0
    delay_ms: float = 0.0
    queue_packets: int = 0


class TopologyResponse(BaseModel):
    """The full topology plus live per-node status."""

    name: str = ""
    run_id: str = ""
    n_nodes: int = 0
    n_links: int = 0
    nodes: list[TopologyNode] = Field(default_factory=list)
    links: list[TopologyLink] = Field(default_factory=list)


class TrafficSnapshot(BaseModel):
    """Current traffic conditions and the top talkers."""

    window: int = 0
    t_start: float = 0.0
    t_end: float = 0.0
    packets_per_second: float = 0.0
    throughput_mbps: float = 0.0
    offered_mbps: float = 0.0
    delivered_packets: int = 0
    dropped_packets: int = 0
    loss_ratio: float = 0.0
    mean_latency_ms: float = 0.0
    uplink_utilisation: float = 0.0
    top_talkers: list[dict[str, Any]] = Field(default_factory=list)


class Alert(BaseModel):
    """An operator-facing alert."""

    timestamp: float
    window: int
    node_id: str
    ip: str = ""
    severity: str
    confidence: float
    detector: str = ""
    packet_rate: float = 0.0
    message: str = ""


class MitigationRecord(BaseModel):
    """One mitigation action."""

    timestamp: float
    window: int
    node: str
    ip: str = ""
    action: str
    confidence: float
    detector: str = ""
    reason: str = ""
    result: dict[str, Any] = Field(default_factory=dict)


class MetricsResponse(BaseModel):
    """Per-window QoS metric series."""

    run_id: str = ""
    engine_label: str = ""
    window_s: float = 5.0
    attack: dict[str, Any] = Field(default_factory=dict)
    first_mitigation_s: float | None = None
    windows: list[dict[str, Any]] = Field(default_factory=list)


class ExperimentRequest(BaseModel):
    """Body of ``POST /api/experiment/run``."""

    experiment: str = Field(description="Experiment name to run to completion.")
    detector: str = Field(default="graphsage")
    duration_s: float | None = Field(default=None, gt=0.0)


class ResultsResponse(BaseModel):
    """Stored evaluation results and generated artefacts."""

    detectors: list[dict[str, Any]] = Field(default_factory=list)
    per_experiment: list[dict[str, Any]] = Field(default_factory=list)
    figures: list[str] = Field(default_factory=list)
    reports: list[str] = Field(default_factory=list)
    dataset: dict[str, Any] = Field(default_factory=dict)
    available: bool = Field(
        default=False,
        description="False when evaluation has not been run yet; the caller "
                    "should tell the user to run scripts/evaluate.py.",
    )
    message: str = ""
