"""Message bus abstraction for the streaming pipeline.

Two backends with the same interface:

``InMemoryBus``      thread-safe queues; the default, used by tests and the
                     single-process demo.
``RedisStreamBus``   Redis Streams (``XADD`` / ``XREADGROUP``) with consumer
                     groups, so each service can be scaled horizontally and
                     a crashed consumer's pending messages can be reclaimed.

Messages are JSON-serialisable dicts. Topics used by the pipeline:
``flows`` -> ``features`` -> ``scores`` -> ``actions`` (+ ``alerts``).
"""

from __future__ import annotations

import json
import queue
import threading
from collections import defaultdict
from typing import Any, Callable, Iterator


class Bus:
    """Publish/subscribe interface."""

    def publish(self, topic: str, message: dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError

    def consume(self, topic: str, group: str, timeout_s: float = 1.0
                ) -> Iterator[dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:
        return None


class InMemoryBus(Bus):
    """Fan-out per consumer group, like Kafka/Redis consumer groups."""

    def __init__(self, on_publish: Callable[[str], None] | None = None) -> None:
        self._groups: dict[str, dict[str, queue.Queue]] = defaultdict(dict)
        self._lock = threading.Lock()
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.on_publish = on_publish

    def _queue(self, topic: str, group: str) -> queue.Queue:
        with self._lock:
            if group not in self._groups[topic]:
                q: queue.Queue = queue.Queue()
                for msg in self._history[topic]:
                    q.put(msg)
                self._groups[topic][group] = q
            return self._groups[topic][group]

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        payload = json.loads(json.dumps(message, default=str))   # enforce serialisability
        with self._lock:
            self._history[topic].append(payload)
            targets = list(self._groups[topic].values())
        for q in targets:
            q.put(payload)
        if self.on_publish:
            self.on_publish(topic)

    def consume(self, topic: str, group: str, timeout_s: float = 1.0
                ) -> Iterator[dict[str, Any]]:
        q = self._queue(topic, group)
        while True:
            try:
                yield q.get(timeout=timeout_s)
            except queue.Empty:
                return

    def drain(self, topic: str, group: str) -> list[dict[str, Any]]:
        """Return every message currently queued for *group* without blocking."""
        return list(self.consume(topic, group, timeout_s=0.0))


class RedisStreamBus(Bus):
    """Redis Streams backend (requires a reachable Redis >= 5)."""

    def __init__(self, url: str = "redis://localhost:6379/0", prefix: str = "netshield:",
                 maxlen: int = 100_000, consumer: str = "c1") -> None:
        import redis  # noqa: PLC0415

        self.r = redis.Redis.from_url(url, decode_responses=True)
        self.prefix, self.maxlen, self.consumer = prefix, maxlen, consumer

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        self.r.xadd(self.prefix + topic, {"m": json.dumps(message, default=str)},
                    maxlen=self.maxlen, approximate=True)

    def consume(self, topic: str, group: str, timeout_s: float = 1.0
                ) -> Iterator[dict[str, Any]]:
        stream = self.prefix + topic
        try:
            self.r.xgroup_create(stream, group, id="0", mkstream=True)
        except Exception:  # noqa: BLE001 - group exists
            pass
        while True:
            resp = self.r.xreadgroup(group, self.consumer, {stream: ">"}, count=100,
                                     block=int(timeout_s * 1000))
            if not resp:
                return
            for _, entries in resp:
                for msg_id, fields in entries:
                    yield json.loads(fields["m"])
                    self.r.xack(stream, group, msg_id)

    def close(self) -> None:
        self.r.close()


def make_bus(url: str | None = None) -> Bus:
    """``None``/``memory://`` -> in-memory; ``redis://...`` -> Redis Streams."""
    if not url or url.startswith("memory"):
        return InMemoryBus()
    if url.startswith("redis"):
        return RedisStreamBus(url)
    raise ValueError(f"Unsupported bus URL {url!r}")
