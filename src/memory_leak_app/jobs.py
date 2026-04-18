from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from src.memory_leak.control_plane import MemoryLeakControlPlane
from src.memory_leak.reporting import build_result_snapshot, render_html_report, render_markdown_report


TERMINAL_STATES = {"completed", "failed", "cancelled"}


@dataclass
class ScanJob:
    scan_id: str
    workspace_path: str
    file_limit: int
    build_command: str | None = None
    dynamic_run_ids: list[str] = field(default_factory=list)
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None
    report: dict[str, Any] | None = None
    artifacts: dict[str, str] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    cancel_requested: bool = False

    def to_summary(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "workspace_path": self.workspace_path,
            "file_limit": self.file_limit,
            "build_command": self.build_command,
            "dynamic_run_ids": self.dynamic_run_ids,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "bundle_count": (self.report or {}).get("bundle_count"),
            "candidate_count": (self.report or {}).get("candidate_count"),
            "evidence_count": (self.report or {}).get("evidence_count"),
            "artifacts": self.artifacts,
            "cancel_requested": self.cancel_requested,
        }


class ScanJobManager:
    def __init__(
        self,
        artifact_root: str | None = None,
        control_plane_factory: Callable[[], MemoryLeakControlPlane] | None = None,
    ):
        self.artifact_root = Path(
            artifact_root
            or os.getenv("MEMORY_LEAK_APP_ARTIFACT_DIR", "")
            or Path(__file__).resolve().parents[2] / "results" / "app_scans"
        ).expanduser().resolve()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.control_plane_factory = control_plane_factory or MemoryLeakControlPlane
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)

    def create_scan(
        self,
        workspace_path: str,
        file_limit: int = 500,
        build_command: str | None = None,
        dynamic_run_ids: list[str] | None = None,
    ) -> ScanJob:
        scan_id = uuid.uuid4().hex[:12]
        job = ScanJob(
            scan_id=scan_id,
            workspace_path=workspace_path,
            file_limit=file_limit,
            build_command=build_command,
            dynamic_run_ids=dynamic_run_ids or [],
        )
        with self._condition:
            self._jobs[scan_id] = job
            self._append_event_locked(job, "queued", message="Scan queued")
            self._write_status_locked(job)
            self._condition.notify_all()

        thread = threading.Thread(target=self._run_job, args=(scan_id,), daemon=True)
        thread.start()
        return job

    def get_job(self, scan_id: str) -> ScanJob:
        with self._lock:
            if scan_id not in self._jobs:
                raise KeyError(scan_id)
            return self._jobs[scan_id]

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [job.to_summary() for job in sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)]

    def cancel_job(self, scan_id: str) -> ScanJob:
        with self._condition:
            job = self.get_job(scan_id)
            job.cancel_requested = True
            if job.status == "queued":
                job.status = "cancelled"
                job.finished_at = time.time()
            self._append_event_locked(job, "cancel_requested", message="Cancellation requested")
            self._write_status_locked(job)
            self._condition.notify_all()
            return job

    def get_events_since(self, scan_id: str, last_event_id: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            job = self.get_job(scan_id)
            return [event for event in job.events if event["event_id"] > last_event_id]

    def wait_for_events(self, scan_id: str, last_event_id: int, timeout: float = 15.0) -> list[dict[str, Any]]:
        deadline = time.time() + timeout
        with self._condition:
            while True:
                job = self.get_job(scan_id)
                events = [event for event in job.events if event["event_id"] > last_event_id]
                if events or job.status in TERMINAL_STATES:
                    return events
                remaining = deadline - time.time()
                if remaining <= 0:
                    return []
                self._condition.wait(timeout=remaining)

    def _run_job(self, scan_id: str) -> None:
        control_plane = self.control_plane_factory()
        job = self.get_job(scan_id)
        try:
            with self._condition:
                if job.cancel_requested:
                    job.status = "cancelled"
                    job.finished_at = time.time()
                    self._append_event_locked(job, "cancelled", message="Scan cancelled before start")
                    self._write_status_locked(job)
                    self._condition.notify_all()
                    return
                job.status = "starting"
                job.started_at = time.time()
                job.updated_at = job.started_at
                self._append_event_locked(job, "starting", message="Scan starting")
                self._write_status_locked(job)
                self._condition.notify_all()

            report = control_plane.scan_repo(
                job.workspace_path,
                file_limit=job.file_limit,
                dynamic_run_ids=job.dynamic_run_ids,
                build_command=job.build_command,
                progress_callback=lambda event: self._record_control_plane_event(scan_id, event),
            )
            artifacts = self._write_report_artifacts(job, report)
            with self._condition:
                job.status = "completed"
                job.finished_at = time.time()
                job.updated_at = job.finished_at
                job.report = report
                job.artifacts = artifacts
                self._append_event_locked(job, "completed", message="Scan completed", artifacts=artifacts)
                self._write_status_locked(job)
                self._condition.notify_all()
        except Exception as exc:
            with self._condition:
                job.status = "failed"
                job.error = str(exc)
                job.finished_at = time.time()
                job.updated_at = job.finished_at
                self._append_event_locked(job, "failed", message=str(exc))
                self._write_status_locked(job)
                self._condition.notify_all()
        finally:
            close = getattr(control_plane, "close", None)
            if callable(close):
                close()

    def _record_control_plane_event(self, scan_id: str, event: dict[str, Any]) -> None:
        with self._condition:
            job = self.get_job(scan_id)
            phase = event.get("phase")
            if phase and phase not in {"completed"}:
                job.status = self._phase_to_status(phase)
            job.updated_at = time.time()
            self._append_event_locked(job, event.get("type", "progress"), **event)
            self._write_status_locked(job)
            self._condition.notify_all()

    def _append_event_locked(self, job: ScanJob, event_type: str, **payload: Any) -> None:
        event = {
            "event_id": len(job.events) + 1,
            "scan_id": job.scan_id,
            "type": event_type,
            "timestamp": time.time(),
            **payload,
        }
        job.events.append(event)
        job_dir = self._job_dir(job.scan_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        with (job_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=True) + "\n")

    def _write_status_locked(self, job: ScanJob) -> None:
        job_dir = self._job_dir(job.scan_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        (job_dir / "status.json").write_text(json.dumps(job.to_summary(), indent=2), encoding="utf-8")
        (job_dir / "request.json").write_text(
            json.dumps(
                {
                    "scan_id": job.scan_id,
                    "workspace_path": job.workspace_path,
                    "file_limit": job.file_limit,
                    "build_command": job.build_command,
                    "dynamic_run_ids": job.dynamic_run_ids,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def _write_report_artifacts(self, job: ScanJob, report: dict[str, Any]) -> dict[str, str]:
        job_dir = self._job_dir(job.scan_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        snapshot = build_result_snapshot(report)
        artifacts = {
            "json": str(job_dir / "report.json"),
            "markdown": str(job_dir / "report.md"),
            "html": str(job_dir / "report.html"),
            "snapshot": str(job_dir / "snapshot.json"),
        }
        Path(artifacts["json"]).write_text(json.dumps(report, indent=2), encoding="utf-8")
        Path(artifacts["markdown"]).write_text(render_markdown_report(report), encoding="utf-8")
        Path(artifacts["html"]).write_text(render_html_report(report), encoding="utf-8")
        Path(artifacts["snapshot"]).write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        return artifacts

    def _job_dir(self, scan_id: str) -> Path:
        return self.artifact_root / scan_id

    def _phase_to_status(self, phase: str) -> str:
        mapping = {
            "startup": "starting",
            "candidate_discovery": "indexing",
            "static_analysis": "static_analysis",
            "leakguard_analysis": "leakguard_analysis",
            "dynamic_merge": "dynamic_merge",
            "judging": "judging",
            "reporting": "reporting",
        }
        return mapping.get(phase, "starting")
