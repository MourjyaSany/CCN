"""Real-time per-source flow features over a sliding time window.

Unlike the simulator, this observes *real* requests arriving at a *real* socket.
For every source identity it keeps a bounded, thread-safe sliding window of
recent arrivals and computes the same *kinds* of features the offline detector
uses - rates, counts, timing regularity, path/endpoint spread, error rate - so a
detector trained on the sim's feature philosophy has a compatible view of live
traffic.

Source identity
---------------
On the loopback interface every connection's peer address is ``127.0.0.1``, so a
raw source IP cannot separate one client from another. The gateway therefore
keys on a **client identity**: an ``X-Device-Id`` header when present (the
loopback analogue of a device certificate, API key or switch ingress port),
falling back to ``ip:port``. This mirrors the project's core stance that
mitigation must key on an identity the attacker cannot forge, not on a spoofable
source address.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Arrival:
    """A single observed request arrival."""

    t: float
    bytes_in: int
    path: str
    status: int = 0  # filled in after the request is served; 0 = pending


@dataclass(slots=True)
class SourceWindow:
    """Sliding-window statistics for one source identity.

    Attributes:
        device: The source identity string.
        arrivals: Recent arrivals within the window.
        total_seen: Lifetime request count (never pruned).
        first_seen: Wall-clock time of the first ever arrival.
    """

    device: str
    arrivals: deque[Arrival] = field(default_factory=deque)
    total_seen: int = 0
    first_seen: float = 0.0

    def prune(self, now: float, window_s: float) -> None:
        """Drop arrivals older than *window_s* seconds."""
        cutoff = now - window_s
        arrivals = self.arrivals
        while arrivals and arrivals[0].t < cutoff:
            arrivals.popleft()

    def features(self, now: float, window_s: float) -> dict[str, float]:
        """Compute the current window feature vector for this source.

        Args:
            now: Current wall-clock time.
            window_s: Window length in seconds.

        Returns:
            A mapping of feature name to value. The keys are a real-traffic
            analogue of the simulator's egress features.
        """
        self.prune(now, window_s)
        arrivals = self.arrivals
        n = len(arrivals)
        if n == 0:
            return {
                "req_rate": 0.0, "byte_rate": 0.0, "req_count": 0.0,
                "unique_paths": 0.0, "mean_iat": 0.0, "iat_cv": 0.0,
                "burstiness": 0.0, "error_rate": 0.0, "mean_bytes": 0.0,
            }

        total_bytes = sum(a.bytes_in for a in arrivals)
        paths = {a.path for a in arrivals}
        errors = sum(1 for a in arrivals if a.status >= 400)

        # Inter-arrival timing.
        iats = [arrivals[i].t - arrivals[i - 1].t for i in range(1, n)]
        mean_iat = sum(iats) / len(iats) if iats else 0.0
        if len(iats) >= 2 and mean_iat > 0:
            var = sum((x - mean_iat) ** 2 for x in iats) / len(iats)
            iat_cv = math.sqrt(max(0.0, var)) / mean_iat
        else:
            iat_cv = 0.0

        return {
            "req_rate": n / window_s,
            "byte_rate": total_bytes / window_s,
            "req_count": float(n),
            "unique_paths": float(len(paths)),
            "mean_iat": mean_iat,
            "iat_cv": iat_cv,
            # Low CV = machine-regular timing; high = human-irregular. Report the
            # inverse regularity so a steady flood scores high.
            "burstiness": iat_cv,
            "error_rate": errors / n,
            "mean_bytes": total_bytes / n,
        }


class FlowTracker:
    """Thread-safe registry of per-source sliding windows.

    Args:
        window_s: Sliding-window length in seconds.
        max_sources: Cap on tracked identities (LRU-evicted) to bound memory
            under a spoofed-identity flood.
    """

    def __init__(self, window_s: float = 2.0, max_sources: int = 20000) -> None:
        self.window_s = float(window_s)
        self.max_sources = int(max_sources)
        self._sources: dict[str, SourceWindow] = {}
        self._lock = threading.Lock()
        self.total_arrivals = 0

    def record(self, device: str, bytes_in: int, path: str) -> Arrival:
        """Record a request arrival and return its :class:`Arrival` handle.

        Args:
            device: Source identity.
            bytes_in: Request size in bytes.
            path: Requested path (for endpoint-spread features).

        Returns:
            The arrival object, so the caller can back-fill the status code
            once the request has been served.
        """
        now = time.perf_counter()
        arrival = Arrival(t=now, bytes_in=int(bytes_in), path=path)
        with self._lock:
            window = self._sources.get(device)
            if window is None:
                if len(self._sources) >= self.max_sources:
                    # Evict the least-recently-active source.
                    oldest = min(
                        self._sources.values(),
                        key=lambda w: w.arrivals[-1].t if w.arrivals else 0.0,
                    )
                    self._sources.pop(oldest.device, None)
                window = SourceWindow(device=device, first_seen=now)
                self._sources[device] = window
            window.arrivals.append(arrival)
            window.total_seen += 1
            self.total_arrivals += 1
        return arrival

    def snapshot(self) -> dict[str, dict[str, float]]:
        """Return the current feature vector for every tracked source."""
        now = time.perf_counter()
        with self._lock:
            return {
                device: window.features(now, self.window_s)
                for device, window in self._sources.items()
            }

    def active_sources(self) -> int:
        """Number of sources with at least one arrival in the window."""
        now = time.perf_counter()
        with self._lock:
            return sum(
                1 for w in self._sources.values()
                if w.arrivals and w.arrivals[-1].t >= now - self.window_s
            )

    def stats(self) -> dict[str, Any]:
        """Return coarse tracker statistics."""
        with self._lock:
            return {
                "tracked_sources": len(self._sources),
                "total_arrivals": self.total_arrivals,
                "window_s": self.window_s,
            }
