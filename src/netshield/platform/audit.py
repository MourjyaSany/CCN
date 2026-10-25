"""Append-only audit trail of operator and system actions.

Every state-changing API call and every mitigation decision the system takes
on its own is recorded with who, what, when and why. Rows are never updated
or deleted through this module; each row carries a SHA-256 hash chained to
the previous row, so tampering with history is detectable with
:meth:`AuditLog.verify_chain`.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    actor     TEXT NOT NULL,
    role      TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    outcome   TEXT NOT NULL,
    detail    TEXT,
    prev_hash TEXT NOT NULL,
    row_hash  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


class AuditLog:
    """SQLite-backed, hash-chained audit log (thread-safe)."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._lock = threading.Lock()

    @staticmethod
    def _hash(prev: str, fields: list[Any]) -> str:
        payload = json.dumps([prev, *fields], sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def record(self, actor: str, role: str, action: str, target: str = "",
               outcome: str = "ok", detail: dict[str, Any] | None = None) -> int:
        """Append one entry and return its id."""
        with self._lock:
            row = self._conn.execute(
                "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else "genesis"
            ts = time.time()
            detail_json = json.dumps(detail or {}, sort_keys=True, default=str)
            fields = [ts, actor, role, action, target, outcome, detail_json]
            digest = self._hash(prev, fields)
            cur = self._conn.execute(
                "INSERT INTO audit_log (ts, actor, role, action, target, outcome, detail, "
                "prev_hash, row_hash) VALUES (?,?,?,?,?,?,?,?,?)", (*fields, prev, digest))
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def entries(self, limit: int = 200, actor: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT id, ts, actor, role, action, target, outcome, detail FROM audit_log"
        args: list[Any] = []
        if actor:
            query += " WHERE actor = ?"
            args.append(actor)
        query += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            rows = self._conn.execute(query, args).fetchall()
        keys = ("id", "ts", "actor", "role", "action", "target", "outcome", "detail")
        return [{**dict(zip(keys, r)), "detail": json.loads(r[7] or "{}")} for r in rows]

    def verify_chain(self) -> bool:
        """Recompute every hash; False if any row was altered or removed."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, actor, role, action, target, outcome, detail, prev_hash, row_hash "
                "FROM audit_log ORDER BY id").fetchall()
        prev = "genesis"
        for r in rows:
            if r[7] != prev or self._hash(prev, list(r[:7])) != r[8]:
                return False
            prev = r[8]
        return True
