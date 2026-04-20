from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class ScanStateStore:
    """Persist scan summaries and event streams in SQLite."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_events (
                    scan_id TEXT NOT NULL,
                    event_id INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, event_id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scans_updated_at
                    ON scans(updated_at DESC);

                CREATE INDEX IF NOT EXISTS idx_scan_events_scan_timestamp
                    ON scan_events(scan_id, timestamp ASC);
                """
            )
            self._connection.commit()

    def save_scan_summary(self, summary: dict[str, Any]) -> None:
        payload = json.dumps(summary, ensure_ascii=True)
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO scans (scan_id, created_at, updated_at, status, payload_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    created_at = excluded.created_at,
                    updated_at = excluded.updated_at,
                    status = excluded.status,
                    payload_json = excluded.payload_json
                """,
                (
                    summary["scan_id"],
                    float(summary.get("created_at") or 0.0),
                    float(summary.get("updated_at") or 0.0),
                    str(summary.get("status") or "unknown"),
                    payload,
                ),
            )
            self._connection.commit()

    def append_event(self, scan_id: str, event: dict[str, Any]) -> None:
        payload = json.dumps(event, ensure_ascii=True)
        with self._lock:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO scan_events (scan_id, event_id, timestamp, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    scan_id,
                    int(event["event_id"]),
                    float(event.get("timestamp") or 0.0),
                    payload,
                ),
            )
            self._connection.commit()

    def load_scan_summaries(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload_json FROM scans ORDER BY created_at ASC"
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def load_events(self, scan_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload_json
                FROM scan_events
                WHERE scan_id = ?
                ORDER BY event_id ASC
                """,
                (scan_id,),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def delete_scan(self, scan_id: str) -> None:
        with self._lock:
            self._connection.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            self._connection.commit()

    def delete_scans(self, scan_ids: list[str]) -> None:
        if not scan_ids:
            return
        placeholders = ", ".join("?" for _ in scan_ids)
        with self._lock:
            self._connection.execute(f"DELETE FROM scans WHERE scan_id IN ({placeholders})", tuple(scan_ids))
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()
