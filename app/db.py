"""Persistencia de scans en SQLite (modulo estandar, sin ORM)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent / "app.db"


def get_conn(path: Path | None = None) -> sqlite3.Connection:
    db = path or DB_PATH
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = get_conn(path)
    try:
        create_schema(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


def create_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            framework TEXT,
            score REAL NOT NULL,
            scanned_files INTEGER NOT NULL DEFAULT 0,
            rules_loaded INTEGER NOT NULL DEFAULT 0,
            duration_ms INTEGER NOT NULL DEFAULT 0,
            findings_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )


def insert_scan(conn: sqlite3.Connection, record: dict[str, Any]) -> int:
    cur = conn.execute(
        """
        INSERT INTO scans (project, framework, score, scanned_files, rules_loaded,
                           duration_ms, findings_json)
        VALUES (:project, :framework, :score, :scanned_files, :rules_loaded,
                :duration_ms, :findings_json)
        """,
        record,
    )
    rowid = cur.lastrowid
    return int(rowid) if rowid is not None else 0


def list_scans(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [norm(r) for r in rows]


def get_scan(conn: sqlite3.Connection, scan_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return norm(row) if row else None


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    avg = conn.execute("SELECT AVG(score) FROM scans").fetchone()[0]
    max_findings = conn.execute(
        "SELECT MAX(json_array_length(json_extract(findings_json, '$.findings'))) FROM scans"
    ).fetchone()[0]
    last = conn.execute("SELECT created_at FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return {
        "total_scans": total,
        "avg_score": round(avg, 2) if avg is not None else None,
        "max_findings": max_findings or 0,
        "last_scan": last[0] if last else None,
    }


def norm(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["findings"] = json.loads(data.pop("findings_json") or "[]")
    return data
