"""Legitimate traffic surges that a production detector must *not* flag.

A detector evaluated only on "quiet fleet vs. flood" can score a near-zero
false-positive rate simply by learning "lots of traffic means attack". Real
networks routinely produce legitimate surges, and an operator will switch off
a detector that blocks the fleet every time it receives a firmware update.
These events reproduce three such surges inside the simulator:

``flash_crowd``
    A fraction of devices of one class (by default ``http_client``) raise
    their request rate by ``rate_multiplier`` for ``duration_s`` seconds - a
    dashboard everyone opens at once, a scheduled report, a news event.
``firmware_storm``
    Every ``tcp_uploader`` (or a fraction) starts a large transfer at the same
    instant - a fleet-wide OTA update or log flush.
``reboot_storm``
    Every ``mqtt_sensor`` drops its session at once and reconnects within
    ``spread_s`` seconds - a power blip or broker fail-over. It produces a SYN
    burst that superficially resembles a SYN flood.

All events are labelled BENIGN (no packet is marked ``is_attack``), so any
detector output above the trigger on these windows is a false alarm.

Configuration (``traffic.benign_events``)::

    - {type: flash_crowd, start_s: 40, duration_s: 20, rate_multiplier: 8,
       device_class: http_client, fraction: 1.0}
    - {type: firmware_storm, start_s: 40, upload_bytes: [200000, 400000]}
    - {type: reboot_storm, start_s: 40, spread_s: 1.0}
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from ..utils.logging_utils import get_logger
from ..utils.seeding import rng_for

_LOG = get_logger(__name__)

EVENT_TYPES: tuple[str, ...] = ("flash_crowd", "firmware_storm", "reboot_storm")
_DEFAULT_CLASS = {"flash_crowd": "http_client", "firmware_storm": "tcp_uploader",
                  "reboot_storm": "mqtt_sensor"}


def schedule_benign_events(
    engine: Any,
    applications: Sequence[Any],
    events: Iterable[Mapping[str, Any]] | None,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Schedule every configured benign surge on the simulation engine.

    Args:
        engine: The simulation engine.
        applications: Every endpoint application (attackers' benign apps too).
        events: Event specs from ``traffic.benign_events``.
        seed: Master seed; each event derives an independent stream.

    Returns:
        A list describing each scheduled event (stored in the run summary).

    Raises:
        ValueError: On an unknown event type.
    """
    described: list[dict[str, Any]] = []
    for i, spec in enumerate(events or []):
        kind = str(spec.get("type", ""))
        if kind not in EVENT_TYPES:
            raise ValueError(f"Unknown benign event type {kind!r}; known: {EVENT_TYPES}")
        rng = rng_for(seed, "benign_event", str(i), kind)
        device_class = str(spec.get("device_class", _DEFAULT_CLASS[kind]))
        pool = [a for a in applications if getattr(a, "kind", "") == device_class]
        fraction = float(spec.get("fraction", 1.0))
        count = max(0, min(len(pool), int(round(fraction * len(pool)))))
        chosen = [pool[j] for j in sorted(rng.choice(len(pool), count, replace=False))] \
            if count else []
        start = float(spec.get("start_s", 40.0))

        if kind == "flash_crowd":
            multiplier = float(spec.get("rate_multiplier", 8.0))
            end = start + float(spec.get("duration_s", 20.0))

            def boost(t: float, apps: list[Any], m: float = multiplier) -> None:
                # The boost takes effect from each device's next scheduled
                # request; no extra request chain is spawned, so the rate
                # returns exactly to baseline when the surge ends.
                for app in apps:
                    app.rate_boost = m

            def calm(t: float, apps: list[Any]) -> None:
                for app in apps:
                    app.rate_boost = 1.0

            engine.schedule_at(start, boost, chosen)
            engine.schedule_at(end, calm, chosen)
            described.append({"type": kind, "start_s": start, "end_s": end,
                              "devices": len(chosen), "rate_multiplier": multiplier})

        elif kind == "firmware_storm":
            lo, hi = (int(v) for v in spec.get("upload_bytes", [200000, 400000]))
            spread = float(spec.get("spread_s", 2.0))
            for app in chosen:
                size = int(rng.integers(lo, hi + 1))
                engine.schedule_at(start + float(rng.uniform(0.0, spread)),
                                   app.upload_now, size)
            described.append({"type": kind, "start_s": start, "end_s": start + spread,
                              "devices": len(chosen), "upload_bytes": [lo, hi]})

        elif kind == "reboot_storm":
            spread = float(spec.get("spread_s", 1.0))
            down = float(spec.get("down_s", 0.5))
            for app in chosen:
                engine.schedule_at(start, app.reboot,
                                   down + float(rng.uniform(0.0, spread)))
            described.append({"type": kind, "start_s": start, "end_s": start + down + spread,
                              "devices": len(chosen)})
        _LOG.info("Benign event scheduled: %s", described[-1])
    return described
