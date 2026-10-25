"""In-band mitigation enforcement at the edge gateway.

This module is the *data-plane* half of the mitigation subsystem: it implements
the :class:`~netshield.simulation.engine.PacketFilter` interface, so the
simulator calls :meth:`MitigationEnforcer.inspect` for every packet arriving at
the gateway. A rule installed at simulated time *t* therefore changes what
physically happens to packets from *t* onwards, inside the same run. Recovery is
consequently *measured* - throughput climbing back and latency falling are
emergent consequences of packets being dropped earlier in the path - and never
asserted.

Everything is simulated. There is no firewall call, no ``iptables`` invocation,
no socket. The "block" is a Python set lookup inside the event loop.
"""

from __future__ import annotations

import threading

import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..simulation.packet import Packet
from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_parent
from .policy import (
    DROP_REASON,
    ActionType,
    MitigationAction,
    NodeState,
    PolicyConfig,
    decide,
)

_LOG = get_logger(__name__)

#: Columns of the persisted mitigation log.
MITIGATION_LOG_COLUMNS: tuple[str, ...] = (
    "timestamp", "window", "node", "ip", "action", "confidence", "attack_type",
    "detector", "consecutive_hits", "reason", "result",
)


class MitigationEnforcer:
    """Token-bucket / blocklist enforcement point installed at the gateway.

    Args:
        policy: The response ladder.
        node_ips: ``{node_id: ip}`` used only to enrich the operator log.
    """

    def __init__(self, policy: PolicyConfig, node_ips: Mapping[str, str] | None = None) -> None:
        self.policy = policy.validate()
        self.node_ips = dict(node_ips or {})
        self.states: dict[str, NodeState] = {}
        #: Total packets dropped by mitigation, by action type.
        self.drops: dict[str, int] = {}
        self.dropped_bytes: int = 0
        self.inspected: int = 0

    # ------------------------------------------------------------------ #
    def state_for(self, node: str) -> NodeState:
        """Return (creating if needed) the enforcement state for *node*."""
        state = self.states.get(node)
        if state is None:
            state = NodeState(node=node)
            self.states[node] = state
        return state

    def active_sources(self) -> list[str]:
        """Return every node with a restrictive rule currently installed."""
        return sorted(n for n, s in self.states.items() if s.active)

    # ------------------------------------------------------------------ #
    def install(
        self, node: str, action: ActionType, t: float, confidence: float
    ) -> None:
        """Install (or replace) the rule for *node*.

        Args:
            node: Target node id.
            action: Action to install.
            t: Simulated time.
            confidence: Detector confidence that motivated the rule.
        """
        state = self.state_for(node)
        state.action = action
        state.installed_at = t
        state.last_confidence = confidence
        if action is ActionType.RATE_LIMIT:
            state.tokens = float(self.policy.rate_limit_burst)
            state.last_refill = t

    def release(self, node: str, t: float) -> None:
        """Remove any rule installed for *node*."""
        state = self.state_for(node)
        state.action = ActionType.NONE
        state.installed_at = t
        state.consecutive_hits = 0

    # ------------------------------------------------------------------ #
    def inspect(self, packet: Packet, t: float) -> str | None:
        """Decide the fate of one packet at the gateway ingress.

        Args:
            packet: The arriving packet.
            t: Simulated arrival time.

        Returns:
            ``None`` to forward the packet, or the drop reason string.
        """
        self.inspected += 1
        # Key on the ingress node identity, which spoofing cannot forge.
        state = self.states.get(packet.src)
        if state is None or not state.active:
            return None

        if state.action in (ActionType.BLOCK, ActionType.ISOLATE):
            return self._record_drop(state, packet, state.action)

        if state.action is ActionType.RATE_LIMIT:
            elapsed = max(0.0, t - state.last_refill)
            state.last_refill = t
            state.tokens = min(
                float(self.policy.rate_limit_burst),
                state.tokens + elapsed * self.policy.rate_limit_pps,
            )
            if state.tokens >= 1.0:
                state.tokens -= 1.0
                return None
            return self._record_drop(state, packet, ActionType.RATE_LIMIT)

        return None

    def _record_drop(
        self, state: NodeState, packet: Packet, action: ActionType
    ) -> str:
        """Update counters and return the drop reason for *action*."""
        reason = DROP_REASON[action]
        state.dropped_packets += 1
        state.dropped_bytes += packet.size
        self.drops[reason] = self.drops.get(reason, 0) + 1
        self.dropped_bytes += packet.size
        return reason

    # ------------------------------------------------------------------ #
    def report(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of enforcement activity."""
        return {
            "packets_inspected": self.inspected,
            "packets_dropped": sum(self.drops.values()),
            "bytes_dropped": self.dropped_bytes,
            "drops_by_reason": dict(self.drops),
            "active_rules": {
                node: {
                    "action": state.action.value,
                    "installed_at": round(state.installed_at, 3),
                    "confidence": round(state.last_confidence, 4),
                    "dropped_packets": state.dropped_packets,
                    "dropped_bytes": state.dropped_bytes,
                }
                for node, state in sorted(self.states.items())
                if state.active
            },
        }


class MitigationEngine:
    """Control-plane half: consumes detections and drives the enforcer.

    Args:
        policy: The response ladder.
        enforcer: The data-plane enforcement point.
        detector_name: Recorded in every log entry for provenance.
    """

    def __init__(
        self,
        policy: PolicyConfig,
        enforcer: MitigationEnforcer,
        detector_name: str = "unknown",
    ) -> None:
        self.policy = policy
        self.enforcer = enforcer
        self.detector_name = detector_name
        self.log: list[MitigationAction] = []
        self.first_action_time: float | None = None
        #: ``auto`` installs every rule; ``hybrid`` auto-installs rate limits
        #: but queues blocks and isolations for a human; ``manual`` queues all.
        self.approval_mode: str = "auto"
        self.pending: list[dict[str, Any]] = []
        self._pending_seq = 0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    def needs_approval(self, action: ActionType) -> bool:
        """Whether *action* must wait for an operator under the current mode."""
        if self.approval_mode == "manual":
            return action in (ActionType.RATE_LIMIT, ActionType.BLOCK, ActionType.ISOLATE)
        if self.approval_mode == "hybrid":
            return action in (ActionType.BLOCK, ActionType.ISOLATE)
        return False

    def _queue(self, node: str, action: ActionType, t: float, window: int,
               confidence: float, reason: str, attack_type: str) -> None:
        for item in self.pending:
            if item["node"] == node and item["status"] == "pending":
                if ActionType(item["action"]).severity >= action.severity:
                    return
                item.update(action=action.value, confidence=round(confidence, 5),
                            reason=reason, window=window, timestamp=t)
                return
        self._pending_seq += 1
        self.pending.append({"id": self._pending_seq, "node": node, "action": action.value,
                             "confidence": round(float(confidence), 5), "window": window,
                             "timestamp": t, "reason": reason, "attack_type": attack_type,
                             "status": "pending", "decided_by": None, "decided_at": None})

    def approve(self, approval_id: int, t: float, user: str = "operator") -> MitigationAction:
        """Install a queued action now, on an operator's authority."""
        with self._lock:
            item = self._pending_item(approval_id)
            action = ActionType(item["action"])
            node = item["node"]
            self.enforcer.install(node, action, t, float(item["confidence"]))
            if self.first_action_time is None:
                self.first_action_time = t
            entry = MitigationAction(
                timestamp=t, window=int(item["window"]), node=node,
                ip=self.enforcer.node_ips.get(node, ""), action=action,
                confidence=float(item["confidence"]), attack_type=item["attack_type"],
                reason=f"approved by {user}: {item['reason']}", detector=self.detector_name,
                consecutive_hits=self.enforcer.state_for(node).consecutive_hits,
                result={"enforcement_point": "gateway-ingress", "approved_by": user,
                        "queued_at": item["timestamp"]})
            self.log.append(entry)
            item.update(status="approved", decided_by=user, decided_at=t)
            return entry

    def reject(self, approval_id: int, t: float, user: str = "operator") -> dict[str, Any]:
        """Discard a queued action."""
        with self._lock:
            item = self._pending_item(approval_id)
            item.update(status="rejected", decided_by=user, decided_at=t)
            return dict(item)

    def rollback(self, node: str, t: float, user: str = "operator") -> MitigationAction:
        """Release whatever rule is installed on *node* (operator override)."""
        with self._lock:
            state = self.enforcer.state_for(node)
            if not state.active:
                raise KeyError(f"No active rule on {node!r}")
            previous = state.action
            self.enforcer.release(node, t)
            entry = MitigationAction(
                timestamp=t, window=-1, node=node, ip=self.enforcer.node_ips.get(node, ""),
                action=ActionType.RELEASE, confidence=float(state.last_confidence),
                reason=f"rolled back by {user}", detector=self.detector_name,
                result={"released_from": previous.value, "rolled_back_by": user})
            self.log.append(entry)
            return entry

    def _pending_item(self, approval_id: int) -> dict[str, Any]:
        for item in self.pending:
            if item["id"] == int(approval_id):
                if item["status"] != "pending":
                    raise ValueError(f"Approval {approval_id} is already {item['status']}")
                return item
        raise KeyError(f"No approval {approval_id}")

    # ------------------------------------------------------------------ #
    def apply_window(
        self,
        window: int,
        t: float,
        scores: Mapping[str, float],
        predicted: Mapping[str, str] | None = None,
    ) -> list[MitigationAction]:
        """Process one window of detector output and update enforcement.

        Args:
            window: Window index that produced the scores.
            t: Simulated time at which the decision is taken (window boundary).
            scores: ``{node_id: P(hostile)}`` for every scored node.
            predicted: Optional ``{node_id: predicted_class_name}``.

        Returns:
            The actions installed or released during this window.
        """
        predicted = dict(predicted or {})
        taken: list[MitigationAction] = []
        with self._lock:
            return self._apply_window_locked(window, t, scores, predicted, taken)

    def _apply_window_locked(self, window: int, t: float, scores: Mapping[str, float],
                             predicted: dict[str, str], taken: list[MitigationAction]
                             ) -> list[MitigationAction]:
        for node, confidence in sorted(scores.items()):
            state = self.enforcer.state_for(node)

            if confidence >= self.policy.trigger_probability:
                state.consecutive_hits += 1
                state.clean_windows = 0
            else:
                state.clean_windows += 1
                state.consecutive_hits = 0

            action, reason = decide(confidence, state, self.policy)
            if action in (ActionType.NONE, ActionType.MONITOR):
                continue

            if action is ActionType.RELEASE:
                if not state.active:
                    continue
                previous = state.action
                self.enforcer.release(node, t)
                entry = MitigationAction(
                    timestamp=t, window=window, node=node,
                    ip=self.enforcer.node_ips.get(node, ""),
                    action=ActionType.RELEASE, confidence=float(confidence),
                    attack_type=predicted.get(node, ""), reason=reason,
                    detector=self.detector_name,
                    consecutive_hits=state.consecutive_hits,
                    result={"released_from": previous.value,
                            "dropped_packets": state.dropped_packets},
                )
                self.log.append(entry)
                taken.append(entry)
                _LOG.info("  [mitigation] t=%.1fs RELEASE %s (%s)", t, node, reason)
                continue

            # Never de-escalate an installed rule inside the same incident.
            if state.active and action.severity <= state.action.severity:
                continue

            if self.needs_approval(action):
                self._queue(node, action, t, window, float(confidence), reason,
                            predicted.get(node, ""))
                continue

            self.enforcer.install(node, action, t, float(confidence))
            if self.first_action_time is None:
                self.first_action_time = t
            entry = MitigationAction(
                timestamp=t, window=window, node=node,
                ip=self.enforcer.node_ips.get(node, ""),
                action=action, confidence=float(confidence),
                attack_type=predicted.get(node, ""), reason=reason,
                detector=self.detector_name,
                consecutive_hits=state.consecutive_hits,
                result={"enforcement_point": "gateway-ingress"},
            )
            self.log.append(entry)
            taken.append(entry)
            _LOG.info(
                "  [mitigation] t=%.1fs %s %s p=%.3f (%s)",
                t, action.value.upper(), node, confidence, reason,
            )

        return taken

    # ------------------------------------------------------------------ #
    def finalise(self) -> None:
        """Attach per-rule drop counts to each installed action in the log."""
        for entry in self.log:
            state = self.enforcer.states.get(entry.node)
            if state is not None and entry.action is not ActionType.RELEASE:
                entry.result.setdefault("dropped_packets", state.dropped_packets)
                entry.result.setdefault("dropped_bytes", state.dropped_bytes)

    def log_rows(self) -> list[dict[str, Any]]:
        """Return the mitigation log as CSV/JSON rows."""
        self.finalise()
        return [entry.to_dict() for entry in self.log]

    def save_log(self, path: str | Path) -> Path:
        """Write the mitigation log to a CSV file.

        Args:
            path: Destination CSV path.

        Returns:
            The absolute path written.
        """
        target = ensure_parent(path)
        rows = self.log_rows()
        with target.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=list(MITIGATION_LOG_COLUMNS), extrasaction="ignore"
            )
            writer.writeheader()
            for row in rows:
                writer.writerow({**row, "result": json.dumps(row.get("result", {}))})
        _LOG.info("Mitigation log written: %s (%d entries)", target, len(rows))
        return target

    def summary(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of the mitigation campaign."""
        by_action: dict[str, int] = {}
        for entry in self.log:
            by_action[entry.action.value] = by_action.get(entry.action.value, 0) + 1
        return {
            "detector": self.detector_name,
            "n_actions": len(self.log),
            "actions_by_type": by_action,
            "first_action_s": (
                round(self.first_action_time, 4)
                if self.first_action_time is not None else None
            ),
            "nodes_affected": sorted({entry.node for entry in self.log}),
            "enforcement": self.enforcer.report(),
            "policy": {
                "trigger_probability": self.policy.trigger_probability,
                "rate_limit_probability": self.policy.rate_limit_probability,
                "block_probability": self.policy.block_probability,
                "isolate_probability": self.policy.isolate_probability,
                "rate_limit_pps": self.policy.rate_limit_pps,
                "escalation_windows": self.policy.escalation_windows,
                "release_after_clean_windows": self.policy.release_after_clean_windows,
            },
        }


def evaluate_mitigation_accuracy(
    actions: Iterable[MitigationAction], attacker_nodes: Iterable[str]
) -> dict[str, Any]:
    """Score the mitigation decisions against ground truth.

    A mitigation decision is a *second* classification problem with a much
    higher cost of error than detection, so it is scored separately: how many
    blocked nodes were genuinely compromised, and how many bots were missed.

    Args:
        actions: The mitigation log.
        attacker_nodes: Ground-truth compromised node ids.

    Returns:
        Counts and precision/recall over the set of nodes acted upon.
    """
    truth = set(attacker_nodes)
    acted = {
        entry.node for entry in actions
        if entry.action in (ActionType.RATE_LIMIT, ActionType.BLOCK, ActionType.ISOLATE)
    }
    correct = acted & truth
    wrong = acted - truth
    missed = truth - acted
    precision = len(correct) / len(acted) if acted else 0.0
    recall = len(correct) / len(truth) if truth else 0.0
    denominator = precision + recall
    return {
        "nodes_mitigated": len(acted),
        "attackers_total": len(truth),
        "correctly_mitigated": sorted(correct),
        "wrongly_mitigated": sorted(wrong),
        "missed_attackers": sorted(missed),
        "precision": round(precision, 5),
        "recall": round(recall, 5),
        "f1": round(2 * precision * recall / denominator, 5) if denominator else 0.0,
        "collateral_damage": len(wrong),
    }
