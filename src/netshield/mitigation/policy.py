"""Mitigation policy: turning a detection probability into a network action.

The policy is a graduated response ladder rather than a single on/off switch,
because the cost of a wrong decision is not symmetric. Blocking a legitimate
temperature sensor is a silent outage that nobody notices until the data is
missing; letting a bot through costs a fraction of one link. So the response
escalates with confidence and with *persistence*:

=========================  ==========================  ===========================
Confidence                 Action                      Reversibility
=========================  ==========================  ===========================
``p >= 0.60``              Token-bucket rate limit     Fully reversible, graceful
``p >= 0.85``              Simulated source block      Reversible after N clean
``p >= 0.95`` for N        Gateway port isolation      Requires clean windows
                           consecutive windows
=========================  ==========================  ===========================

Enforcement keys on the **ingress node identity**, not on the source IP address.
That distinction matters: a SYN flood spoofs its source address, so an
IP-keyed ACL would be useless (and would blackhole innocent third parties). The
gateway knows which physical port a frame arrived on, which is exactly the
information a real switch-level mitigation uses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)


class ActionType(str, Enum):
    """The mitigation actions this engine can install."""

    NONE = "none"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    BLOCK = "block"
    ISOLATE = "isolate"
    RELEASE = "release"

    @property
    def severity(self) -> int:
        """Ordering used to decide whether an action is an escalation."""
        return {
            ActionType.NONE: 0,
            ActionType.RELEASE: 0,
            ActionType.MONITOR: 1,
            ActionType.RATE_LIMIT: 2,
            ActionType.BLOCK: 3,
            ActionType.ISOLATE: 4,
        }[self]


#: Drop reason recorded in the telemetry for each enforcement action.
DROP_REASON: dict[ActionType, str] = {
    ActionType.RATE_LIMIT: "mitigation_ratelimit",
    ActionType.BLOCK: "mitigation_block",
    ActionType.ISOLATE: "mitigation_isolate",
}


@dataclass(slots=True)
class MitigationAction:
    """One decision taken by the mitigation engine.

    Attributes:
        timestamp: Simulated time the action was installed.
        window: Feature window that triggered it.
        node: Target node id (the ingress identity, never a spoofable address).
        ip: The node's address, recorded for the operator-facing log.
        action: The :class:`ActionType` applied.
        confidence: Detector probability that drove the decision.
        attack_type: Predicted class name.
        reason: Human-readable justification.
        detector: Which detector produced the score.
        consecutive_hits: How many consecutive windows this node has been flagged.
        result: Outcome recorded after the fact (packets dropped, released, ...).
    """

    timestamp: float
    window: int
    node: str
    ip: str
    action: ActionType
    confidence: float
    attack_type: str = ""
    reason: str = ""
    detector: str = ""
    consecutive_hits: int = 0
    result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON/CSV row written to the mitigation log."""
        return {
            "timestamp": round(self.timestamp, 4),
            "window": self.window,
            "node": self.node,
            "ip": self.ip,
            "action": self.action.value,
            "confidence": round(self.confidence, 5),
            "attack_type": self.attack_type,
            "reason": self.reason,
            "detector": self.detector,
            "consecutive_hits": self.consecutive_hits,
            "result": dict(self.result),
        }


@dataclass(slots=True)
class NodeState:
    """Per-source enforcement state tracked across windows.

    Attributes:
        node: Node id.
        action: Currently installed action.
        consecutive_hits: Consecutive flagged windows.
        clean_windows: Consecutive windows scored below the trigger.
        installed_at: Time the current action was installed.
        last_confidence: Most recent detector confidence.
        dropped_packets: Packets discarded by this rule so far.
        dropped_bytes: Bytes discarded by this rule so far.
        tokens: Remaining token-bucket allowance.
        last_refill: Time the bucket was last refilled.
    """

    node: str
    action: ActionType = ActionType.NONE
    consecutive_hits: int = 0
    clean_windows: int = 0
    installed_at: float = 0.0
    last_confidence: float = 0.0
    dropped_packets: int = 0
    dropped_bytes: int = 0
    tokens: float = 0.0
    last_refill: float = 0.0

    @property
    def active(self) -> bool:
        """True when a restrictive rule is currently installed."""
        return self.action in (
            ActionType.RATE_LIMIT, ActionType.BLOCK, ActionType.ISOLATE
        )


@dataclass(slots=True)
class PolicyConfig:
    """Thresholds and timing constants of the response ladder.

    Attributes:
        rate_limit_probability: Confidence at which throttling begins.
        block_probability: Confidence at which the source is blocked.
        isolate_probability: Confidence at which isolation becomes possible.
        escalation_windows: Consecutive flagged windows required to isolate.
        release_after_clean_windows: Clean windows required before release.
        rate_limit_pps: Token-bucket refill rate for throttled sources.
        rate_limit_burst: Token-bucket depth.
        trigger_probability: Global floor below which nothing is done.
    """

    rate_limit_probability: float = 0.60
    block_probability: float = 0.85
    isolate_probability: float = 0.95
    escalation_windows: int = 2
    release_after_clean_windows: int = 3
    rate_limit_pps: float = 60.0
    rate_limit_burst: int = 30
    trigger_probability: float = 0.80

    @classmethod
    def from_config(cls, config: Any) -> "PolicyConfig":
        """Build a policy from the ``mitigation`` and ``detection`` sections."""
        section = config.get("mitigation", {}) or {}
        policy = section.get("policy", {}) or {}
        return cls(
            rate_limit_probability=float(policy.get("rate_limit_probability", 0.60)),
            block_probability=float(policy.get("block_probability", 0.85)),
            isolate_probability=float(policy.get("isolate_probability", 0.95)),
            escalation_windows=int(section.get("escalation_windows", 2)),
            release_after_clean_windows=int(
                section.get("release_after_clean_windows", 3)
            ),
            rate_limit_pps=float(section.get("rate_limit_pps", 60.0)),
            rate_limit_burst=int(section.get("rate_limit_burst", 30)),
            trigger_probability=float(
                config.get("detection.mitigation_trigger_probability", 0.80)
            ),
        )

    def validate(self) -> "PolicyConfig":
        """Check the ladder is monotone.

        Returns:
            The same policy.

        Raises:
            ValueError: If the confidence bands are not increasing, which would
                make the escalation ladder incoherent.
        """
        if not (0.0 < self.rate_limit_probability <= self.block_probability
                <= self.isolate_probability <= 1.0):
            raise ValueError(
                "Mitigation policy thresholds must satisfy "
                "0 < rate_limit <= block <= isolate <= 1, got "
                f"{self.rate_limit_probability}, {self.block_probability}, "
                f"{self.isolate_probability}."
            )
        if self.escalation_windows < 1:
            raise ValueError("mitigation.escalation_windows must be >= 1.")
        if self.release_after_clean_windows < 1:
            raise ValueError("mitigation.release_after_clean_windows must be >= 1.")
        if self.rate_limit_pps <= 0:
            raise ValueError("mitigation.rate_limit_pps must be > 0.")
        return self


def decide(
    confidence: float,
    state: NodeState,
    policy: PolicyConfig,
) -> tuple[ActionType, str]:
    """Choose the action for one node given its score and history.

    Args:
        confidence: ``P(SUSPICIOUS) + P(MALICIOUS)`` from the detector.
        state: The node's current enforcement state.
        policy: The response ladder.

    Returns:
        ``(action, reason)``. ``ActionType.NONE`` means "leave as-is";
        ``ActionType.RELEASE`` means "remove the installed rule".
    """
    if confidence < policy.trigger_probability:
        if state.active and state.clean_windows >= policy.release_after_clean_windows:
            return (
                ActionType.RELEASE,
                f"{state.clean_windows} consecutive clean windows "
                f"(p={confidence:.2f} < {policy.trigger_probability:.2f})",
            )
        return ActionType.NONE, "below trigger probability"

    # Escalate to isolation only for a persistently, highly confident detection.
    if (
        confidence >= policy.isolate_probability
        and state.consecutive_hits >= policy.escalation_windows
    ):
        return (
            ActionType.ISOLATE,
            f"p={confidence:.2f} >= {policy.isolate_probability:.2f} for "
            f"{state.consecutive_hits} consecutive windows",
        )

    if confidence >= policy.block_probability:
        return ActionType.BLOCK, f"p={confidence:.2f} >= {policy.block_probability:.2f}"

    if confidence >= policy.rate_limit_probability:
        return (
            ActionType.RATE_LIMIT,
            f"p={confidence:.2f} >= {policy.rate_limit_probability:.2f}; "
            f"throttling to {policy.rate_limit_pps:.0f} pps",
        )

    return ActionType.MONITOR, f"p={confidence:.2f}; observing"


def summarise_actions(actions: Mapping[str, NodeState]) -> dict[str, int]:
    """Return a histogram of currently installed actions."""
    counts: dict[str, int] = {}
    for state in actions.values():
        counts[state.action.value] = counts.get(state.action.value, 0) + 1
    return counts
