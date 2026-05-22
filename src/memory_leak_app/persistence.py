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

                CREATE TABLE IF NOT EXISTS scan_reports (
                    scan_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS scan_findings (
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    bundle_id TEXT,
                    candidate_id TEXT,
                    verdict TEXT,
                    file TEXT,
                    line INTEGER,
                    summary TEXT,
                    sort_key TEXT,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, finding_id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS finding_evidence (
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    evidence_index INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, finding_id, evidence_index),
                    FOREIGN KEY (scan_id, finding_id) REFERENCES scan_findings(scan_id, finding_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS finding_suggestions (
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    suggestion_index INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, finding_id, suggestion_index),
                    FOREIGN KEY (scan_id, finding_id) REFERENCES scan_findings(scan_id, finding_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scans_updated_at
                    ON scans(updated_at DESC);

                CREATE INDEX IF NOT EXISTS idx_scan_events_scan_timestamp
                    ON scan_events(scan_id, timestamp ASC);

                CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_sort
                    ON scan_findings(scan_id, sort_key ASC, file ASC, line ASC);
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

    def save_report(self, scan_id: str, report: dict[str, Any]) -> None:
        findings = list(report.get("findings") or [])
        report_metadata = dict(report)
        report_metadata.pop("findings", None)
        report_metadata.pop("bundles", None)
        payload = json.dumps(report_metadata, ensure_ascii=True)
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO scan_reports (scan_id, payload_json)
                VALUES (?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    payload_json = excluded.payload_json
                """,
                (scan_id, payload),
            )
            self._connection.execute("DELETE FROM finding_evidence WHERE scan_id = ?", (scan_id,))
            self._connection.execute("DELETE FROM finding_suggestions WHERE scan_id = ?", (scan_id,))
            self._connection.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))

            for finding in findings:
                candidate = finding.get("candidate") or {}
                verdict = finding.get("verdict") or {}
                sort_key = self._finding_sort_key(finding)
                self._connection.execute(
                    """
                    INSERT INTO scan_findings (
                        scan_id,
                        finding_id,
                        bundle_id,
                        candidate_id,
                        verdict,
                        file,
                        line,
                        summary,
                        sort_key,
                        payload_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        str(finding.get("finding_id") or ""),
                        finding.get("bundle_id"),
                        finding.get("candidate_id") or candidate.get("candidate_id"),
                        verdict.get("verdict"),
                        candidate.get("file"),
                        candidate.get("line"),
                        candidate.get("summary"),
                        sort_key,
                        json.dumps(finding, ensure_ascii=True),
                    ),
                )

                for index, evidence in enumerate(candidate.get("evidence") or []):
                    self._connection.execute(
                        """
                        INSERT INTO finding_evidence (scan_id, finding_id, evidence_index, payload_json)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            str(finding.get("finding_id") or ""),
                            index,
                            json.dumps(evidence, ensure_ascii=True),
                        ),
                    )

                for index, suggestion in enumerate(verdict.get("fix_suggestions") or []):
                    self._connection.execute(
                        """
                        INSERT INTO finding_suggestions (scan_id, finding_id, suggestion_index, payload_json)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            str(finding.get("finding_id") or ""),
                            index,
                            json.dumps(suggestion, ensure_ascii=True),
                        ),
                    )

            self._connection.commit()

    def load_report(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            metadata_row = self._connection.execute(
                "SELECT payload_json FROM scan_reports WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            if metadata_row is None:
                return None

            metadata = json.loads(metadata_row["payload_json"])
            finding_rows = self._connection.execute(
                """
                SELECT finding_id, payload_json
                FROM scan_findings
                WHERE scan_id = ?
                ORDER BY sort_key ASC, file ASC, line ASC, finding_id ASC
                """,
                (scan_id,),
            ).fetchall()

            findings: list[dict[str, Any]] = []
            for row in finding_rows:
                finding = json.loads(row["payload_json"])
                finding_id = row["finding_id"]
                evidence_rows = self._connection.execute(
                    """
                    SELECT payload_json
                    FROM finding_evidence
                    WHERE scan_id = ? AND finding_id = ?
                    ORDER BY evidence_index ASC
                    """,
                    (scan_id, finding_id),
                ).fetchall()
                suggestion_rows = self._connection.execute(
                    """
                    SELECT payload_json
                    FROM finding_suggestions
                    WHERE scan_id = ? AND finding_id = ?
                    ORDER BY suggestion_index ASC
                    """,
                    (scan_id, finding_id),
                ).fetchall()
                candidate = dict(finding.get("candidate") or {})
                verdict = dict(finding.get("verdict") or {})
                candidate["evidence"] = [json.loads(item["payload_json"]) for item in evidence_rows]
                verdict["fix_suggestions"] = [json.loads(item["payload_json"]) for item in suggestion_rows]
                finding["candidate"] = candidate
                finding["verdict"] = verdict if verdict else finding.get("verdict")
                findings.append(finding)

        metadata["findings"] = findings
        metadata["bundles"] = findings
        if "finding_count" not in metadata:
            metadata["finding_count"] = len(findings)
        if "bundle_count" not in metadata:
            metadata["bundle_count"] = len(findings)
        if "candidate_count" not in metadata:
            metadata["candidate_count"] = len(findings)
        return metadata

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

    def _finding_sort_key(self, finding: dict[str, Any]) -> str:
        candidate = finding.get("candidate") or {}
        file_name = str(candidate.get("file") or "")
        line = int(candidate.get("line") or 0)
        summary = str(candidate.get("summary") or "")
        return f"{file_name}:{line:08d}:{summary}"
