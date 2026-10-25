"""SQLite schema for NetShield-GNN.

The database is the system of record for everything the dashboard and the
reporting scripts read back: which experiments ran, what the network looked
like, what the detectors said and what the mitigation engine did.

Design notes
------------
* ``PRAGMA foreign_keys = ON`` is enabled on every connection, and every child
  table cascades from ``experiments(run_id)`` so re-running an experiment
  cleanly replaces its rows instead of accumulating duplicates.
* ``traffic_flows`` stores *aggregated* flow records, not packets. A single
  volumetric run generates over a million packets; storing them would make the
  database useless. This mirrors what a real IPFIX collector retains.
* Indices are declared on the access paths the dashboard actually uses
  (``run_id``, ``window``, ``node_id``), because the alerts and metrics
  endpoints are polled once a second while a simulation is running.
"""

from __future__ import annotations

from typing import Final

SCHEMA_VERSION: Final[int] = 1

#: Executed as a script on database creation.
SCHEMA_SQL: Final[str] = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS schema_info (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- One row per simulation run.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS experiments (
    run_id           TEXT PRIMARY KEY,
    experiment       TEXT NOT NULL,
    description      TEXT DEFAULT '',
    tags             TEXT DEFAULT '[]',
    engine           TEXT NOT NULL,
    engine_label     TEXT NOT NULL,
    engine_reason    TEXT DEFAULT '',
    seed             INTEGER NOT NULL,
    duration_s       REAL NOT NULL,
    window_s         REAL NOT NULL,
    n_iot_devices    INTEGER NOT NULL DEFAULT 0,
    n_attackers      INTEGER NOT NULL DEFAULT 0,
    attack_type      TEXT DEFAULT '',
    attack_start_s   REAL,
    attack_duration_s REAL,
    packets_generated INTEGER DEFAULT 0,
    packets_dropped  INTEGER DEFAULT 0,
    wall_seconds     REAL DEFAULT 0,
    config_json      TEXT DEFAULT '{}',
    summary_json     TEXT DEFAULT '{}',
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------------------
-- Static description of every node in a run's topology.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    node_id      TEXT NOT NULL,
    kind         TEXT NOT NULL,
    ip           TEXT NOT NULL,
    device_class TEXT DEFAULT '',
    parent       TEXT,
    tier         INTEGER NOT NULL DEFAULT 3,
    is_attacker  INTEGER NOT NULL DEFAULT 0,
    tx_packets   INTEGER DEFAULT 0,
    tx_bytes     INTEGER DEFAULT 0,
    rx_packets   INTEGER DEFAULT 0,
    rx_bytes     INTEGER DEFAULT 0,
    UNIQUE (run_id, node_id),
    FOREIGN KEY (run_id) REFERENCES experiments (run_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Aggregated IPFIX-style flow records (one row per window per 5-tuple).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS traffic_flows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    window       INTEGER NOT NULL,
    t_start      REAL NOT NULL,
    src_node     TEXT NOT NULL,
    dst_node     TEXT NOT NULL,
    src_ip       TEXT NOT NULL,
    dst_ip       TEXT NOT NULL,
    src_port     INTEGER NOT NULL,
    dst_port     INTEGER NOT NULL,
    protocol     INTEGER NOT NULL,
    packets      INTEGER NOT NULL,
    bytes        INTEGER NOT NULL,
    packet_rate  REAL DEFAULT 0,
    byte_rate    REAL DEFAULT 0,
    mean_packet_size REAL DEFAULT 0,
    syn_count    INTEGER DEFAULT 0,
    attack_packets INTEGER DEFAULT 0,
    FOREIGN KEY (run_id) REFERENCES experiments (run_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Per-window network QoS measurements.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS metrics (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            TEXT NOT NULL,
    window            INTEGER NOT NULL,
    t_start           REAL NOT NULL,
    t_end             REAL NOT NULL,
    offered_packets   INTEGER DEFAULT 0,
    delivered_packets INTEGER DEFAULT 0,
    dropped_packets   INTEGER DEFAULT 0,
    pps               REAL DEFAULT 0,
    throughput_mbps   REAL DEFAULT 0,
    loss_ratio        REAL DEFAULT 0,
    legit_loss_ratio  REAL DEFAULT 0,
    mean_latency_ms   REAL DEFAULT 0,
    legit_mean_latency_ms REAL DEFAULT 0,
    p95_latency_ms    REAL DEFAULT 0,
    uplink_utilisation REAL DEFAULT 0,
    mitigation_drops  INTEGER DEFAULT 0,
    UNIQUE (run_id, window),
    FOREIGN KEY (run_id) REFERENCES experiments (run_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Every node scored in every window by every detector.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL,
    detector      TEXT NOT NULL,
    window        INTEGER NOT NULL,
    timestamp     REAL NOT NULL,
    node_id       TEXT NOT NULL,
    ip            TEXT DEFAULT '',
    kind          TEXT DEFAULT '',
    probability   REAL NOT NULL,
    predicted     TEXT NOT NULL,
    p_benign      REAL DEFAULT 0,
    p_suspicious  REAL DEFAULT 0,
    p_malicious   REAL DEFAULT 0,
    packet_rate   REAL DEFAULT 0,
    is_attacker   INTEGER DEFAULT 0,
    FOREIGN KEY (run_id) REFERENCES experiments (run_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Detections that crossed the trigger probability (operator-facing).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    timestamp    REAL NOT NULL,
    window       INTEGER NOT NULL,
    node_id      TEXT NOT NULL,
    ip           TEXT DEFAULT '',
    severity     TEXT NOT NULL,
    confidence   REAL NOT NULL,
    detector     TEXT NOT NULL,
    attack_type  TEXT DEFAULT '',
    message      TEXT DEFAULT '',
    acknowledged INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (run_id) REFERENCES experiments (run_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Mitigation decisions and their outcomes.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mitigation_actions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         TEXT NOT NULL,
    timestamp      REAL NOT NULL,
    window         INTEGER NOT NULL,
    node_id        TEXT NOT NULL,
    ip             TEXT DEFAULT '',
    action         TEXT NOT NULL,
    confidence     REAL NOT NULL,
    attack_type    TEXT DEFAULT '',
    detector       TEXT DEFAULT '',
    reason         TEXT DEFAULT '',
    result_json    TEXT DEFAULT '{}',
    FOREIGN KEY (run_id) REFERENCES experiments (run_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Evaluation results, one row per (run, detector, split).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evaluations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT,
    detector     TEXT NOT NULL,
    split        TEXT NOT NULL,
    accuracy     REAL,
    macro_f1     REAL,
    precision_   REAL,
    recall       REAL,
    fpr          REAL,
    roc_auc      REAL,
    metrics_json TEXT DEFAULT '{}',
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_flows_run_window   ON traffic_flows (run_id, window);
CREATE INDEX IF NOT EXISTS idx_flows_src          ON traffic_flows (run_id, src_node);
CREATE INDEX IF NOT EXISTS idx_metrics_run        ON metrics (run_id, window);
CREATE INDEX IF NOT EXISTS idx_detections_run     ON detections (run_id, window);
CREATE INDEX IF NOT EXISTS idx_detections_node    ON detections (run_id, node_id);
CREATE INDEX IF NOT EXISTS idx_alerts_run         ON alerts (run_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_mitigation_run     ON mitigation_actions (run_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_devices_run        ON devices (run_id);
CREATE INDEX IF NOT EXISTS idx_eval_detector      ON evaluations (detector, split);
"""

#: Table names in dependency order (parents first).
TABLES: Final[tuple[str, ...]] = (
    "experiments",
    "devices",
    "traffic_flows",
    "metrics",
    "detections",
    "alerts",
    "mitigation_actions",
    "evaluations",
)
