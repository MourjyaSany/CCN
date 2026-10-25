"""SQLite data-access layer.

A thin, explicit repository over :mod:`netshield.database.schema`. No ORM: the
queries are few, fixed and easier to audit as SQL. Every write path is
idempotent per ``run_id`` - persisting a run twice replaces it rather than
duplicating it - which matters because ``./run.sh all`` is expected to be re-run
freely.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_parent, resolve
from .schema import SCHEMA_SQL, SCHEMA_VERSION, TABLES

_LOG = get_logger(__name__)

#: Maximum flow rows persisted per run. A single SYN-flood run can export well
#: over 100 000 flow records; the dashboard only ever shows the top talkers, so
#: the largest flows are kept and the long tail is summarised out.
MAX_FLOW_ROWS_PER_RUN: int = 20000


class DatabaseError(RuntimeError):
    """Raised when a database operation cannot be completed."""


class NetShieldDB:
    """Repository over the NetShield-GNN SQLite database.

    Args:
        path: Database file path (repo-relative paths are resolved).
        create: Create and initialise the schema if the file does not exist.
    """

    def __init__(self, path: str | Path, create: bool = True) -> None:
        self.path = ensure_parent(path) if create else resolve(path)
        if not create and not self.path.exists():
            raise DatabaseError(
                f"Database not found: {self.path}. "
                "Run 'python scripts/init_db.py' to create it."
            )
        if create:
            self.initialise()

    # ------------------------------------------------------------------ #
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a configured connection, committing on success.

        Yields:
            An open :class:`sqlite3.Connection` with row access by name and
            foreign-key enforcement enabled.
        """
        conn = sqlite3.connect(str(self.path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialise(self) -> Path:
        """Create the schema if needed and stamp the schema version."""
        with self.connect() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.execute(
                "INSERT INTO schema_info (key, value) VALUES ('version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )
        return self.path

    def reset(self) -> None:
        """Delete every row from every table (schema is preserved)."""
        with self.connect() as conn:
            for table in reversed(TABLES):
                conn.execute(f"DELETE FROM {table}")
        _LOG.warning("Database reset: all rows deleted from %s", self.path)

    def table_counts(self) -> dict[str, int]:
        """Return ``{table: row_count}`` for every table."""
        counts: dict[str, int] = {}
        with self.connect() as conn:
            for table in TABLES:
                row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
                counts[table] = int(row["n"])
        return counts

    # ------------------------------------------------------------------ #
    def delete_run(self, run_id: str) -> None:
        """Remove a run and every row that cascades from it."""
        with self.connect() as conn:
            conn.execute("DELETE FROM experiments WHERE run_id = ?", (run_id,))
            # evaluations has no FK cascade (it may reference an absent run).
            conn.execute("DELETE FROM evaluations WHERE run_id = ?", (run_id,))

    def store_run(
        self,
        result: Any,
        detections: Sequence[Mapping[str, Any]] | None = None,
        mitigations: Sequence[Mapping[str, Any]] | None = None,
        trigger: float = 0.80,
        max_flows: int = MAX_FLOW_ROWS_PER_RUN,
    ) -> str:
        """Persist a complete simulation run.

        Args:
            result: A :class:`~netshield.simulation.runner.SimulationResult`.
            detections: Optional detection rows to store.
            mitigations: Optional mitigation-action rows to store.
            trigger: Probability at or above which a detection becomes an alert.
            max_flows: Cap on flow rows retained for this run.

        Returns:
            The stored ``run_id``.
        """
        self.delete_run(result.run_id)
        summary = dict(result.summary)
        attack = dict(summary.get("attack", {}) or {})
        meta = dict(result.meta)

        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO experiments (
                    run_id, experiment, description, tags, engine, engine_label,
                    engine_reason, seed, duration_s, window_s, n_iot_devices,
                    n_attackers, attack_type, attack_start_s, attack_duration_s,
                    packets_generated, packets_dropped, wall_seconds,
                    config_json, summary_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    result.run_id,
                    str(meta.get("experiment", result.run_id)),
                    str(meta.get("description", "")),
                    json.dumps(meta.get("tags", [])),
                    result.engine,
                    result.engine_label,
                    result.engine_reason,
                    int(summary.get("seed", 0)),
                    float(summary.get("duration_s", 0.0)),
                    float(summary.get("window_s", 5.0)),
                    int(summary.get("n_iot_devices", 0)),
                    int(summary.get("n_attackers", 0)),
                    str(attack.get("type", "")) if attack.get("enabled") else "",
                    float(attack.get("start_s", 0.0)) if attack.get("enabled") else None,
                    float(attack.get("duration_s", 0.0)) if attack.get("enabled") else None,
                    int(summary.get("packets_generated", 0)),
                    int(summary.get("packets_dropped", 0)),
                    float(summary.get("wall_seconds", 0.0)),
                    json.dumps(result.config, default=str),
                    json.dumps(summary, default=str),
                ),
            )

            node_stats = {row["node_id"]: row for row in result.nodes}
            conn.executemany(
                """
                INSERT INTO devices (
                    run_id, node_id, kind, ip, device_class, parent, tier,
                    is_attacker, tx_packets, tx_bytes, rx_packets, rx_bytes
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        result.run_id, node["node_id"], node["kind"], node["ip"],
                        node.get("device_class", ""), node.get("parent"),
                        int(node.get("tier", 3)), int(bool(node.get("is_attacker"))),
                        int(node_stats.get(node["node_id"], {}).get("tx_packets", 0)),
                        int(node_stats.get(node["node_id"], {}).get("tx_bytes", 0)),
                        int(node_stats.get(node["node_id"], {}).get("rx_packets", 0)),
                        int(node_stats.get(node["node_id"], {}).get("rx_bytes", 0)),
                    )
                    for node in result.topology["nodes"]
                ],
            )

            flows = sorted(result.flows, key=lambda r: -int(r.get("packets", 0)))[:max_flows]
            conn.executemany(
                """
                INSERT INTO traffic_flows (
                    run_id, window, t_start, src_node, dst_node, src_ip, dst_ip,
                    src_port, dst_port, protocol, packets, bytes, packet_rate,
                    byte_rate, mean_packet_size, syn_count, attack_packets
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        result.run_id, int(f["window"]), float(f["t_start"]),
                        f["src_node"], f["dst_node"], f["src_ip"], f["dst_ip"],
                        int(f["src_port"]), int(f["dst_port"]), int(f["protocol"]),
                        int(f["packets"]), int(f["bytes"]), float(f["packet_rate"]),
                        float(f["byte_rate"]), float(f["mean_packet_size"]),
                        int(f["syn_count"]), int(f["attack_packets"]),
                    )
                    for f in flows
                ],
            )

            conn.executemany(
                """
                INSERT INTO metrics (
                    run_id, window, t_start, t_end, offered_packets,
                    delivered_packets, dropped_packets, pps, throughput_mbps,
                    loss_ratio, legit_loss_ratio, mean_latency_ms,
                    legit_mean_latency_ms, p95_latency_ms, uplink_utilisation,
                    mitigation_drops
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        result.run_id, int(w["window"]), float(w["t_start"]),
                        float(w["t_end"]), int(w["offered_packets"]),
                        int(w["delivered_packets"]), int(w["dropped_packets"]),
                        float(w["pps"]), float(w["throughput_mbps"]),
                        float(w["loss_ratio"]), float(w["legit_loss_ratio"]),
                        float(w["mean_latency_ms"]),
                        float(w.get("legit_mean_latency_ms", 0.0)),
                        float(w["p95_latency_ms"]), float(w["uplink_utilisation"]),
                        int(w.get("mitigation_drops", 0)),
                    )
                    for w in result.windows
                ],
            )

            if detections:
                self._insert_detections(conn, result.run_id, detections, trigger)
            if mitigations:
                self._insert_mitigations(conn, result.run_id, mitigations)

        _LOG.info("Run '%s' persisted to %s", result.run_id, self.path)
        return result.run_id

    # ------------------------------------------------------------------ #
    @staticmethod
    def _insert_detections(
        conn: sqlite3.Connection,
        run_id: str,
        rows: Sequence[Mapping[str, Any]],
        trigger: float,
    ) -> None:
        """Insert detection rows and derive alerts from the ones above *trigger*."""
        conn.executemany(
            """
            INSERT INTO detections (
                run_id, detector, window, timestamp, node_id, ip, kind,
                probability, predicted, p_benign, p_suspicious, p_malicious,
                packet_rate, is_attacker
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            [
                (
                    run_id, str(r.get("detector", "")), int(r.get("window", 0)),
                    float(r.get("timestamp", 0.0)), str(r.get("node", r.get("node_id", ""))),
                    str(r.get("ip", "")), str(r.get("kind", "")),
                    float(r.get("probability", 0.0)), str(r.get("predicted", "")),
                    float(r.get("p_benign", 0.0)), float(r.get("p_suspicious", 0.0)),
                    float(r.get("p_malicious", 0.0)), float(r.get("packet_rate", 0.0)),
                    int(bool(r.get("is_attacker", False))),
                )
                for r in rows
            ],
        )

        alerts = [r for r in rows if float(r.get("probability", 0.0)) >= trigger]
        conn.executemany(
            """
            INSERT INTO alerts (
                run_id, timestamp, window, node_id, ip, severity, confidence,
                detector, attack_type, message
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            [
                (
                    run_id, float(r.get("timestamp", 0.0)), int(r.get("window", 0)),
                    str(r.get("node", r.get("node_id", ""))), str(r.get("ip", "")),
                    str(r.get("predicted", "SUSPICIOUS")),
                    float(r.get("probability", 0.0)), str(r.get("detector", "")),
                    str(r.get("predicted", "")),
                    (
                        f"{r.get('node', r.get('node_id', ''))} classified "
                        f"{r.get('predicted', '?')} with confidence "
                        f"{float(r.get('probability', 0.0)):.2f} "
                        f"at {float(r.get('timestamp', 0.0)):.1f}s "
                        f"({float(r.get('packet_rate', 0.0)):.0f} pps)"
                    ),
                )
                for r in alerts
            ],
        )

    @staticmethod
    def _insert_mitigations(
        conn: sqlite3.Connection, run_id: str, rows: Sequence[Mapping[str, Any]]
    ) -> None:
        """Insert mitigation-action rows."""
        conn.executemany(
            """
            INSERT INTO mitigation_actions (
                run_id, timestamp, window, node_id, ip, action, confidence,
                attack_type, detector, reason, result_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            [
                (
                    run_id, float(r.get("timestamp", 0.0)), int(r.get("window", 0)),
                    str(r.get("node", "")), str(r.get("ip", "")),
                    str(r.get("action", "")), float(r.get("confidence", 0.0)),
                    str(r.get("attack_type", "")), str(r.get("detector", "")),
                    str(r.get("reason", "")),
                    json.dumps(r.get("result", {}), default=str),
                )
                for r in rows
            ],
        )

    def store_evaluation(
        self,
        detector: str,
        split: str,
        metrics: Mapping[str, Any],
        run_id: str | None = None,
    ) -> None:
        """Persist one evaluation result."""
        binary = dict(metrics.get("binary", {}) or {})
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO evaluations (
                    run_id, detector, split, accuracy, macro_f1, precision_,
                    recall, fpr, roc_auc, metrics_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id, detector, split,
                    float(metrics.get("accuracy", 0.0)),
                    float(metrics.get("macro_f1", 0.0)),
                    float(binary.get("precision", 0.0)),
                    float(binary.get("recall", 0.0)),
                    float(binary.get("false_positive_rate", 0.0)),
                    float(binary.get("roc_auc") or 0.0),
                    json.dumps(dict(metrics), default=str),
                ),
            )

    # ------------------------------------------------------------------ #
    # read paths used by the API
    # ------------------------------------------------------------------ #
    def _rows(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        """Execute *sql* and return the result as a list of dicts."""
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(sql, tuple(params)).fetchall()]

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent runs, newest first."""
        return self._rows(
            """
            SELECT run_id, experiment, description, engine, engine_label, seed,
                   duration_s, n_iot_devices, n_attackers, attack_type,
                   packets_generated, packets_dropped, wall_seconds, created_at
            FROM experiments ORDER BY created_at DESC, rowid DESC LIMIT ?
            """,
            (int(limit),),
        )

    def latest_run_id(self) -> str | None:
        """Return the id of the most recently stored run, if any."""
        rows = self._rows(
            "SELECT run_id FROM experiments ORDER BY created_at DESC, rowid DESC LIMIT 1"
        )
        return rows[0]["run_id"] if rows else None

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Return the full record for one run."""
        rows = self._rows("SELECT * FROM experiments WHERE run_id = ?", (run_id,))
        return rows[0] if rows else None

    def devices(self, run_id: str) -> list[dict[str, Any]]:
        """Return every device in a run's topology."""
        return self._rows(
            "SELECT * FROM devices WHERE run_id = ? ORDER BY tier, node_id", (run_id,)
        )

    def metrics(self, run_id: str, limit: int = 500) -> list[dict[str, Any]]:
        """Return per-window QoS metrics for a run."""
        return self._rows(
            "SELECT * FROM metrics WHERE run_id = ? ORDER BY window LIMIT ?",
            (run_id, int(limit)),
        )

    def alerts(self, run_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        """Return alerts, newest first, optionally scoped to one run."""
        if run_id:
            return self._rows(
                "SELECT * FROM alerts WHERE run_id = ? "
                "ORDER BY timestamp DESC, id DESC LIMIT ?",
                (run_id, int(limit)),
            )
        return self._rows(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (int(limit),)
        )

    def mitigations(
        self, run_id: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        """Return mitigation actions, newest first."""
        if run_id:
            return self._rows(
                "SELECT * FROM mitigation_actions WHERE run_id = ? "
                "ORDER BY timestamp DESC, id DESC LIMIT ?",
                (run_id, int(limit)),
            )
        return self._rows(
            "SELECT * FROM mitigation_actions ORDER BY id DESC LIMIT ?", (int(limit),)
        )

    def detections(
        self, run_id: str, window: int | None = None, limit: int = 2000
    ) -> list[dict[str, Any]]:
        """Return detection rows for a run, optionally for a single window."""
        if window is None:
            return self._rows(
                "SELECT * FROM detections WHERE run_id = ? "
                "ORDER BY window, node_id LIMIT ?",
                (run_id, int(limit)),
            )
        return self._rows(
            "SELECT * FROM detections WHERE run_id = ? AND window = ? "
            "ORDER BY probability DESC LIMIT ?",
            (run_id, int(window), int(limit)),
        )

    def top_talkers(self, run_id: str, limit: int = 15) -> list[dict[str, Any]]:
        """Return the highest-volume sources in a run."""
        return self._rows(
            """
            SELECT src_node AS node_id,
                   SUM(packets) AS packets,
                   SUM(bytes)   AS bytes,
                   COUNT(*)     AS flows
            FROM traffic_flows WHERE run_id = ?
            GROUP BY src_node ORDER BY bytes DESC LIMIT ?
            """,
            (run_id, int(limit)),
        )

    def evaluations(self, split: str | None = None) -> list[dict[str, Any]]:
        """Return stored evaluation results, newest first."""
        if split:
            return self._rows(
                "SELECT * FROM evaluations WHERE split = ? ORDER BY id DESC",
                (split,),
            )
        return self._rows("SELECT * FROM evaluations ORDER BY id DESC")


def init_database(path: str | Path) -> NetShieldDB:
    """Create (or open) the database and ensure the schema exists."""
    db = NetShieldDB(path, create=True)
    _LOG.info("Database ready at %s (schema v%d)", db.path, SCHEMA_VERSION)
    return db
