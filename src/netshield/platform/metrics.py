"""Prometheus metrics for detection, mitigation, the pipeline and the API.

Scraped at ``/metrics``. A private :class:`CollectorRegistry` is used so tests
and multiple app instances never collide on the global registry.

Metric names follow Prometheus conventions (``_total`` counters,
``_seconds`` histograms, base units).
"""

from __future__ import annotations

from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST

INFERENCE_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)


class NetShieldMetrics:
    """Bundle of every metric the platform exports."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        r = self.registry
        self.windows_scored = Counter("netshield_windows_scored_total",
                                      "Feature windows scored by the detector",
                                      ["detector"], registry=r)
        self.nodes_flagged = Counter("netshield_nodes_flagged_total",
                                     "Node-windows at or above the trigger probability",
                                     ["detector"], registry=r)
        self.inference_seconds = Histogram("netshield_inference_seconds",
                                           "Detector wall-clock time per window",
                                           ["detector"], buckets=INFERENCE_BUCKETS, registry=r)
        self.mitigation_actions = Counter("netshield_mitigation_actions_total",
                                          "Mitigation actions taken", ["action", "origin"],
                                          registry=r)
        self.active_rules = Gauge("netshield_active_rules", "Rules currently installed",
                                  registry=r)
        self.pending_approvals = Gauge("netshield_pending_approvals",
                                       "Mitigation actions awaiting an operator", registry=r)
        self.clean_availability = Gauge("netshield_clean_availability_ratio",
                                        "Clean-device availability in the last window",
                                        registry=r)
        self.clean_p99_latency = Gauge("netshield_clean_p99_latency_seconds",
                                       "Clean-device p99 one-way latency, last window",
                                       registry=r)
        self.sim_time = Gauge("netshield_simulation_time_seconds",
                              "Simulated time of the running session", registry=r)
        self.http_requests = Counter("netshield_http_requests_total", "API requests",
                                     ["method", "route", "status"], registry=r)
        self.http_seconds = Histogram("netshield_http_request_seconds", "API latency",
                                      ["method", "route"], registry=r)
        self.auth_failures = Counter("netshield_auth_failures_total",
                                     "Rejected authentication or authorisation attempts",
                                     ["reason"], registry=r)
        self.bus_messages = Counter("netshield_bus_messages_total", "Messages published",
                                    ["topic"], registry=r)

    def observe_snapshot(self, snapshot: Any) -> None:
        """Refresh gauges from a live session snapshot."""
        self.sim_time.set(float(getattr(snapshot, "sim_time_s", 0.0) or 0.0))
        windows = getattr(snapshot, "windows", None) or []
        if windows:
            last = windows[-1]
            if "clean_availability" in last:
                self.clean_availability.set(float(last["clean_availability"]))
            if "clean_p99_latency_ms" in last:
                self.clean_p99_latency.set(float(last["clean_p99_latency_ms"]) / 1000.0)

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST
