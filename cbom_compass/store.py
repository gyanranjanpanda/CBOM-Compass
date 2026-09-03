"""Persistence and audit log.

PRD section 10 names Postgres + JSONB. This MVP uses SQLite with the same
JSON-document shape so the move is a connection-string change rather than a
rewrite; nothing here depends on SQLite-specific behaviour.

The audit log is not optional decoration: exports are the primary exfiltration
path for a document that is, by construction, a ranked list of an
organisation's weakest cryptography.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path("cbom-compass.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    initiated_by TEXT,
    sources     TEXT,
    targets     TEXT,
    asset_count INTEGER,
    document    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    ts        TEXT NOT NULL,
    principal TEXT NOT NULL,
    action    TEXT NOT NULL,
    detail    TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
"""


class Store:
    """Scan snapshots and the audit log.

    Ordering note: two scans in one demo land in the same second, so
    `started_at` alone is an ambiguous sort key and the dashboard would show
    whichever row SQLite happened to return first. Every ordering here breaks
    ties on `rowid`, which is monotonic per insert.
    """

    def __init__(self, path: str | Path = DEFAULT_DB) -> None:
        self.path = Path(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---------------------------------------------------------------- scans
    def save(self, report_dict: dict) -> str:
        run = report_dict["run"]
        self.conn.execute(
            "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?)",
            (run["scan_id"], run["started_at"], run["finished_at"], run["initiated_by"],
             json.dumps(run["sources_covered"]), json.dumps(run["target_scope"]),
             run["asset_count"], json.dumps(report_dict)),
        )
        self.conn.commit()
        self.audit(run["initiated_by"], "scan.completed",
                   f"{run['scan_id']}: {run['asset_count']} assets over "
                   f"{','.join(run['sources_covered'])}")
        return run["scan_id"]

    def get(self, scan_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT document FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return json.loads(row["document"]) if row else None

    def latest(self) -> dict | None:
        row = self.conn.execute(
            "SELECT document FROM scans ORDER BY started_at DESC, rowid DESC LIMIT 1").fetchone()
        return json.loads(row["document"]) if row else None

    def previous(self, scan_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT document FROM scans WHERE rowid < "
            "(SELECT rowid FROM scans WHERE scan_id=?) ORDER BY rowid DESC LIMIT 1",
            (scan_id,)).fetchone()
        return json.loads(row["document"]) if row else None

    def list_scans(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT scan_id, started_at, finished_at, initiated_by, sources, targets, "
            "asset_count FROM scans ORDER BY started_at DESC, rowid DESC LIMIT ?",
            (limit,)).fetchall()
        return [
            {**dict(r), "sources": json.loads(r["sources"]), "targets": json.loads(r["targets"])}
            for r in rows
        ]

    # ---------------------------------------------------------------- audit
    def audit(self, principal: str, action: str, detail: str = "") -> None:
        self.conn.execute(
            "INSERT INTO audit VALUES (?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             principal, action, detail),
        )
        self.conn.commit()

    def audit_log(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
