"""TimescaleDB storage for window metrics, detections and mitigation actions.

SQLite stays the zero-setup default for a laptop. For a deployment the time
series go to TimescaleDB (PostgreSQL + hypertables), configuration and the
audit trail to plain PostgreSQL tables, and Grafana reads both.

``SCHEMA_SQL`` creates the hypertables with compression and retention
policies. :class:`TimescaleWriter` batches inserts with ``executemany`` and
works with any DB-API driver that uses the ``%s`` paramstyle (psycopg 3).
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS window_metrics (
    time                 TIMESTAMPTZ      NOT NULL,
    run_id               TEXT             NOT NULL,
    window_index         INTEGER          NOT NULL,
    clean_availability   DOUBLE PRECISION,
    clean_loss_ratio     DOUBLE PRECISION,
    clean_p50_latency_ms DOUBLE PRECISION,
    clean_p99_latency_ms DOUBLE PRECISION,
    clean_jitter_ms      DOUBLE PRECISION,
    clean_fairness       DOUBLE PRECISION,
    throughput_mbps      DOUBLE PRECISION,
    uplink_utilisation   DOUBLE PRECISION,
    attack_offered       BIGINT,
    mitigation_drops     BIGINT,
    collateral_byte_ratio DOUBLE PRECISION,
    extra                JSONB
);
SELECT create_hypertable('window_metrics', 'time', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS ix_wm_run ON window_metrics (run_id, time DESC);

CREATE TABLE IF NOT EXISTS detections (
    time        TIMESTAMPTZ NOT NULL,
    run_id      TEXT        NOT NULL,
    window_index INTEGER    NOT NULL,
    node        TEXT        NOT NULL,
    detector    TEXT        NOT NULL,
    p_hostile   REAL        NOT NULL,
    predicted   TEXT
);
SELECT create_hypertable('detections', 'time', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS ix_det_node ON detections (node, time DESC);

CREATE TABLE IF NOT EXISTS mitigation_actions (
    time       TIMESTAMPTZ NOT NULL,
    run_id     TEXT        NOT NULL,
    node       TEXT        NOT NULL,
    action     TEXT        NOT NULL,
    confidence REAL,
    reason     TEXT,
    actor      TEXT        NOT NULL DEFAULT 'system'
);
SELECT create_hypertable('mitigation_actions', 'time', if_not_exists => TRUE);

ALTER TABLE detections SET (timescaledb.compress, timescaledb.compress_segmentby = 'node');
SELECT add_compression_policy('detections', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_retention_policy('detections', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('window_metrics', INTERVAL '365 days', if_not_exists => TRUE);
"""

_WM_COLUMNS = ("clean_availability", "clean_loss_ratio", "clean_p50_latency_ms",
               "clean_p99_latency_ms", "clean_jitter_ms", "clean_fairness", "throughput_mbps",
               "uplink_utilisation", "attack_offered", "mitigation_drops",
               "collateral_byte_ratio")


def window_rows(run_id: str, windows: Iterable[Mapping[str, Any]], t0_epoch: float
                ) -> list[tuple]:
    """Rows for ``window_metrics`` (simulated time anchored at *t0_epoch*)."""
    from datetime import datetime, timezone  # noqa: PLC0415

    out = []
    for w in windows:
        ts = datetime.fromtimestamp(t0_epoch + float(w["t_start"]), tz=timezone.utc)
        extra = {k: v for k, v in w.items() if k not in _WM_COLUMNS and k != "drop_reasons"}
        out.append((ts, run_id, int(w["window"]), *[w.get(c) for c in _WM_COLUMNS],
                    json.dumps(extra, default=str)))
    return out


class TimescaleWriter:
    """Batch writer over a DB-API connection (psycopg 3 recommended)."""

    def __init__(self, connection: Any) -> None:
        self.conn = connection

    @classmethod
    def connect(cls, dsn: str) -> "TimescaleWriter":
        import psycopg  # noqa: PLC0415 - optional dependency

        return cls(psycopg.connect(dsn, autocommit=False))

    def init_schema(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        self.conn.commit()

    def write_windows(self, run_id: str, windows: Iterable[Mapping[str, Any]],
                      t0_epoch: float) -> int:
        rows = window_rows(run_id, windows, t0_epoch)
        placeholders = ", ".join(["%s"] * (4 + len(_WM_COLUMNS)))
        sql = (f"INSERT INTO window_metrics (time, run_id, window_index, "
               f"{', '.join(_WM_COLUMNS)}, extra) VALUES ({placeholders})")
        with self.conn.cursor() as cur:
            cur.executemany(sql, rows)
        self.conn.commit()
        return len(rows)
