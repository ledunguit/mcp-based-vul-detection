from __future__ import annotations

import json
import inspect
import multiprocessing
import os
import queue
import shlex
import shutil
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from src.memory_leak.control_plane import MemoryLeakControlPlane
from src.memory_leak.judge import MemoryLeakJudge
from src.memory_leak.reporting import build_result_snapshot, render_html_report, render_markdown_report
from src.memory_leak_app.persistence import ScanStateStore


TERMINAL_STATES = {"completed", "failed", "cancelled"}
ACTIVE_STATES = {
    "queued",
    "starting",
    "indexing",
    "static_analysis",
    "leakguard_analysis",
    "dynamic_build",
    "dynamic_planning",
    "dynamic_execution",
    "dynamic_merge",
    "judging",
    "reporting",
}
ANALYSIS_MODES = {"no_llm", "llm_assisted"}
DYNAMIC_MODES = {"off", "selective", "aggressive"}


@dataclass(frozen=True)
class ScanFailure:
    code: str
    category: str
    message: str
    remediation: str
    detail: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "error_code": self.code,
            "error_category": self.category,
            "error": self.message,
            "remediation": self.remediation,
            "detail": self.detail,
        }


class DuplicateScanError(ValueError):
    def __init__(self, existing_job: "ScanJob"):
        self.existing_job = existing_job
        super().__init__(f"Workspace already has an active scan: {existing_job.scan_id}")


class ScanDeletionError(ValueError):
    def __init__(self, message: str, remediation: str):
        self.remediation = remediation
        super().__init__(message)


class ScanCancelled(RuntimeError):
    pass


def classify_scan_failure(error: BaseException | str, detail: str | None = None) -> ScanFailure:
    message = str(error).strip() if isinstance(error, BaseException) else str(error).strip()
    if not message:
        message = "Unknown scan failure"
    lowered = message.lower()

    if isinstance(error, ScanCancelled) or "scan cancelled" in lowered:
        return ScanFailure(
            code="scan_cancelled",
            category="cancellation",
            message="Scan was cancelled.",
            remediation="Start a new scan when you are ready to resume investigation.",
            detail=detail,
        )
    if (
        isinstance(error, FileNotFoundError)
        or "workspace is not allowed" in lowered
        or "repository path does not exist" in lowered
        or "project directory does not exist" in lowered
    ):
        return ScanFailure(
            code="invalid_workspace",
            category="input_validation",
            message=message,
            remediation="Choose a mounted repository path under the configured allowed roots.",
            detail=detail,
        )
    if "no c/c++ files" in lowered:
        return ScanFailure(
            code="no_source_files",
            category="input_validation",
            message=message,
            remediation="Select a repository that contains .c, .cc, .cpp, .cxx, .h, or .hpp files.",
            detail=detail,
        )
    if "build_command is required" in lowered:
        return ScanFailure(
            code="build_command_required",
            category="input_validation",
            message=message,
            remediation="Provide a build command so LeakGuard can generate compilation metadata for the target project.",
            detail=detail,
        )
    if "required mcp tool not available" in lowered:
        return ScanFailure(
            code="missing_mcp_tool",
            category="configuration",
            message=message,
            remediation="Check the analyzer server version and ensure the required MCP tools are exposed.",
            detail=detail,
        )
    if "failed to reach http mcp server" in lowered:
        return ScanFailure(
            code="mcp_server_unreachable",
            category="dependency_unavailable",
            message=message,
            remediation="Start the MCP server container and verify MCP_STATIC_SERVER_URL / MCP_DYNAMIC_SERVER_URL.",
            detail=detail,
        )
    if "http mcp request failed" in lowered:
        return ScanFailure(
            code="mcp_server_error",
            category="tool_execution",
            message=message,
            remediation="Inspect the target MCP server logs to see why the tool request failed.",
            detail=detail,
        )
    if "http mcp request timed out" in lowered:
        return ScanFailure(
            code="mcp_server_timeout",
            category="tool_execution",
            message=message,
            remediation="Increase the MCP HTTP timeout for long-running tools such as LeakGuard, or reduce the target scope/build complexity.",
            detail=detail,
        )
    if "leakguard repo root not found" in lowered:
        return ScanFailure(
            code="leakguard_repo_missing",
            category="configuration",
            message=message,
            remediation="Mount leak_guard_tool into the static-analysis container and set LEAKGUARD_REPO_ROOT correctly.",
            detail=detail,
        )
    if ("docker" in lowered and "not found" in lowered) or "cannot connect to the docker daemon" in lowered:
        return ScanFailure(
            code="docker_unavailable",
            category="dependency_unavailable",
            message=message,
            remediation="Make sure Docker is available to the static-analysis service and that the docker socket mount is valid.",
            detail=detail,
        )
    if "does not match the specified platform" in lowered and "leakguard-tool:dev" in lowered:
        return ScanFailure(
            code="docker_platform_mismatch",
            category="configuration",
            message=message,
            remediation="Rebuild the LeakGuard image with the same platform configured by LEAKGUARD_DOCKER_PLATFORM, preferably through docker-compose.thesis-demo.yml so build and runtime stay aligned.",
            detail=detail,
        )
    if "build command failed" in lowered or "codechecker log" in lowered or "compilation.json" in lowered:
        return ScanFailure(
            code="build_command_failed",
            category="tool_execution",
            message=message,
            remediation="Review the build command and confirm the project can generate compilation.json or compile_commands.json.",
            detail=detail,
        )
    if "unsupported executable format" in lowered or "exec format error" in lowered:
        return ScanFailure(
            code="dynamic_binary_incompatible",
            category="input_validation",
            message=message,
            remediation=(
                "Rebuild the target binary inside the dynamic-analysis environment, or provide a Linux-compatible "
                "ELF executable (or a shebang script) under the mounted workspace."
            ),
            detail=detail,
        )
    if "openai" in lowered or "anthropic" in lowered or "judge" in lowered:
        return ScanFailure(
            code="judge_failure",
            category="llm_judge",
            message=message,
            remediation="Check judge configuration and provider credentials. The heuristic fallback should remain available for local runs.",
            detail=detail,
        )
    return ScanFailure(
        code="scan_failed",
        category="unknown",
        message=message,
        remediation="Inspect the app logs and the relevant analyzer container logs for the failing step.",
        detail=detail,
    )


def _scan_worker_main(
    request: dict[str, Any],
    event_queue: Any,
    control_plane_factory: Callable[..., MemoryLeakControlPlane] | None = None,
) -> None:
    control_plane = _build_control_plane(request, control_plane_factory)
    try:
        event_queue.put({"kind": "worker_started", "pid": os.getpid()})
        report = control_plane.scan_repo(
            request["workspace_path"],
            file_limit=request["file_limit"],
            dynamic_run_ids=request["dynamic_run_ids"],
            build_command=request.get("build_command"),
            dynamic_mode=request.get("dynamic_mode"),
            dynamic_binary_path=request.get("dynamic_binary_path"),
            dynamic_args=request.get("dynamic_args") or [],
            dynamic_timeout_sec=request.get("dynamic_timeout_sec"),
            dynamic_tool_preference=request.get("dynamic_tool_preference"),
            progress_callback=lambda event: event_queue.put({"kind": "progress", "event": event}),
        )
        report.update(_report_mode_metadata(request["analysis_mode"]))
        event_queue.put({"kind": "report", "report": report})
    except BaseException as exc:
        failure = classify_scan_failure(exc, detail=traceback.format_exc())
        event_queue.put({"kind": "error", "failure": failure.to_dict()})
    finally:
        close = getattr(control_plane, "close", None)
        if callable(close):
            close()
        try:
            event_queue.put({"kind": "worker_finished"})
        except Exception:
            pass


def normalize_analysis_mode(value: str | None) -> str:
    mode = (value or "no_llm").strip().lower()
    if mode not in ANALYSIS_MODES:
        raise ValueError(f"analysis_mode must be one of: {', '.join(sorted(ANALYSIS_MODES))}")
    return mode


def normalize_dynamic_mode(value: str | None) -> str:
    mode = (value or "selective").strip().lower()
    if mode not in DYNAMIC_MODES:
        raise ValueError(f"dynamic_mode must be one of: {', '.join(sorted(DYNAMIC_MODES))}")
    return mode


def normalize_dynamic_args(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return shlex.split(text) if text else []
    return [str(item) for item in value]


def _build_control_plane(
    request: dict[str, Any],
    control_plane_factory: Callable[..., MemoryLeakControlPlane] | None = None,
) -> MemoryLeakControlPlane:
    if control_plane_factory is not None:
        if inspect.isclass(control_plane_factory):
            return control_plane_factory()
        try:
            signature = inspect.signature(control_plane_factory)
        except (TypeError, ValueError):
            signature = None
        if signature is not None:
            supported_params = [
                parameter
                for parameter in signature.parameters.values()
                if parameter.kind in {
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                }
            ]
            if supported_params:
                return control_plane_factory(request)
        return control_plane_factory()

    analysis_mode = normalize_analysis_mode(request.get("analysis_mode"))
    judge = MemoryLeakJudge(use_llm=analysis_mode == "llm_assisted")
    return MemoryLeakControlPlane(judge=judge)


def _report_mode_metadata(analysis_mode: str) -> dict[str, Any]:
    return {
        "analysis_mode": analysis_mode,
        "orchestration_mode": "deterministic_policy",
        "judge_strategy_requested": "llm" if analysis_mode == "llm_assisted" else "heuristic",
    }


@dataclass
class ScanJob:
    scan_id: str
    workspace_path: str
    file_limit: int
    analysis_mode: str = "no_llm"
    build_command: str | None = None
    dynamic_run_ids: list[str] = field(default_factory=list)
    dynamic_mode: str = "selective"
    dynamic_binary_path: str | None = None
    dynamic_args: list[str] = field(default_factory=list)
    dynamic_timeout_sec: int | None = None
    dynamic_tool_preference: str | None = None
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None
    error_code: str | None = None
    error_category: str | None = None
    remediation: str | None = None
    error_detail: str | None = None
    report: dict[str, Any] | None = None
    artifacts: dict[str, str] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    cancel_requested: bool = False
    worker_mode: str = "thread"
    worker_pid: int | None = None

    def to_summary(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "workspace_path": self.workspace_path,
            "file_limit": self.file_limit,
            "analysis_mode": self.analysis_mode,
            "build_command": self.build_command,
            "dynamic_run_ids": self.dynamic_run_ids,
            "dynamic_mode": self.dynamic_mode,
            "dynamic_binary_path": self.dynamic_binary_path,
            "dynamic_args": self.dynamic_args,
            "dynamic_timeout_sec": self.dynamic_timeout_sec,
            "dynamic_tool_preference": self.dynamic_tool_preference,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "error_code": self.error_code,
            "error_category": self.error_category,
            "remediation": self.remediation,
            "error_detail": self.error_detail,
            "bundle_count": (self.report or {}).get("bundle_count"),
            "finding_count": (self.report or {}).get("finding_count"),
            "candidate_count": (self.report or {}).get("candidate_count"),
            "evidence_count": (self.report or {}).get("evidence_count"),
            "judge_summary": (self.report or {}).get("judge_summary"),
            "artifacts": self.artifacts,
            "cancel_requested": self.cancel_requested,
            "worker_mode": self.worker_mode,
            "worker_pid": self.worker_pid,
        }


class ScanJobManager:
    def __init__(
        self,
        artifact_root: str | None = None,
        control_plane_factory: Callable[..., MemoryLeakControlPlane] | None = None,
        db_path: str | None = None,
        worker_mode: str = "auto",
    ):
        self.artifact_root = Path(
            artifact_root
            or os.getenv("MEMORY_LEAK_APP_ARTIFACT_DIR", "")
            or Path(__file__).resolve().parents[2] / "results" / "app_scans"
        ).expanduser().resolve()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(
            db_path
            or os.getenv("MEMORY_LEAK_APP_DB_PATH", "")
            or self.artifact_root / "memory_leak_app.sqlite3"
        ).expanduser().resolve()
        self.control_plane_factory = control_plane_factory
        self.worker_mode = worker_mode
        self._custom_control_plane_factory = control_plane_factory is not None
        self._store = ScanStateStore(self.db_path)
        self._jobs: dict[str, ScanJob] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._processes: dict[str, Any] = {}
        self._queues: dict[str, Any] = {}
        self._queue_threads: dict[str, threading.Thread] = {}
        self._active_control_planes: dict[str, MemoryLeakControlPlane] = {}
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._mp_context = multiprocessing.get_context("spawn")
        self._load_persisted_jobs()

    def create_scan(
        self,
        workspace_path: str,
        file_limit: int = 500,
        analysis_mode: str = "no_llm",
        build_command: str | None = None,
        dynamic_run_ids: list[str] | None = None,
        dynamic_mode: str = "selective",
        dynamic_binary_path: str | None = None,
        dynamic_args: list[str] | None = None,
        dynamic_timeout_sec: int | None = None,
        dynamic_tool_preference: str | None = None,
    ) -> ScanJob:
        workspace_path = str(Path(workspace_path).expanduser().resolve())
        analysis_mode = normalize_analysis_mode(analysis_mode)
        dynamic_mode = normalize_dynamic_mode(dynamic_mode)
        scan_id = uuid.uuid4().hex[:12]
        job = ScanJob(
            scan_id=scan_id,
            workspace_path=workspace_path,
            file_limit=file_limit,
            analysis_mode=analysis_mode,
            build_command=build_command,
            dynamic_run_ids=dynamic_run_ids or [],
            dynamic_mode=dynamic_mode,
            dynamic_binary_path=dynamic_binary_path,
            dynamic_args=dynamic_args or [],
            dynamic_timeout_sec=dynamic_timeout_sec,
            dynamic_tool_preference=dynamic_tool_preference,
            worker_mode=self._resolve_worker_mode(),
        )
        with self._condition:
            duplicate = self._find_active_job_for_workspace_locked(workspace_path)
            if duplicate:
                raise DuplicateScanError(duplicate)
            self._jobs[scan_id] = job
            self._append_event_locked(
                job,
                "queued",
                message="Scan queued",
                workspace_path=job.workspace_path,
                analysis_mode=job.analysis_mode,
                build_command=job.build_command,
                dynamic_run_ids=job.dynamic_run_ids,
                dynamic_mode=job.dynamic_mode,
                dynamic_binary_path=job.dynamic_binary_path,
                dynamic_args=job.dynamic_args,
                dynamic_timeout_sec=job.dynamic_timeout_sec,
                dynamic_tool_preference=job.dynamic_tool_preference,
            )
            self._write_status_locked(job)
            self._condition.notify_all()

        self._start_job(job)
        return job

    def get_job(self, scan_id: str) -> ScanJob:
        with self._lock:
            if scan_id not in self._jobs:
                raise KeyError(scan_id)
            job = self._jobs[scan_id]
            self._ensure_report_loaded_locked(job)
            return job

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [job.to_summary() for job in sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)]

    def load_report(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self.get_job(scan_id)
            return job.report

    def close(self) -> None:
        self._store.close()

    def delete_job(self, scan_id: str) -> dict[str, Any]:
        with self._condition:
            if scan_id not in self._jobs:
                raise KeyError(scan_id)
            job = self._jobs[scan_id]
            if job.status in ACTIVE_STATES:
                raise ScanDeletionError(
                    f"Scan {scan_id} is still running and cannot be deleted.",
                    "Cancel the active scan first, then delete it after it reaches a terminal state.",
                )
            artifacts = dict(job.artifacts)
            job_dir = self._job_dir(scan_id)
            summary = job.to_summary()
            self._jobs.pop(scan_id, None)
            self._threads.pop(scan_id, None)
            self._processes.pop(scan_id, None)
            self._queues.pop(scan_id, None)
            self._queue_threads.pop(scan_id, None)
            self._active_control_planes.pop(scan_id, None)
            self._store.delete_scan(scan_id)
            self._condition.notify_all()

        for path in artifacts.values():
            self._unlink_artifact(path)
        self._remove_job_dir(job_dir)
        return {"deleted_scan_id": scan_id, "deleted": True, "scan": summary}

    def delete_terminal_jobs(self) -> dict[str, Any]:
        with self._condition:
            scan_ids = [
                job.scan_id
                for job in self._jobs.values()
                if job.status in TERMINAL_STATES
            ]
        deleted = [self.delete_job(scan_id) for scan_id in scan_ids]
        return {
            "deleted_scan_ids": [item["deleted_scan_id"] for item in deleted],
            "deleted_count": len(deleted),
        }

    def cancel_job(self, scan_id: str) -> ScanJob:
        process = None
        control_plane = None
        with self._condition:
            job = self.get_job(scan_id)
            if job.status in TERMINAL_STATES:
                return job
            job.cancel_requested = True
            self._append_event_locked(job, "cancel_requested", message="Cancellation requested")
            if job.status == "queued":
                self._mark_cancelled_locked(job, "Scan cancelled before start")
                self._condition.notify_all()
                return job
            process = self._processes.get(scan_id)
            control_plane = self._active_control_planes.get(scan_id)
            if process is not None and process.is_alive():
                self._append_event_locked(
                    job,
                    "worker_termination_requested",
                    message="Terminating scan worker process",
                    worker_pid=process.pid,
                )
            self._write_status_locked(job)
            self._condition.notify_all()

        if process is not None and process.is_alive():
            self._terminate_process(process)
        if control_plane is not None:
            close = getattr(control_plane, "close", None)
            if callable(close):
                close()

        with self._condition:
            job = self.get_job(scan_id)
            if job.status not in TERMINAL_STATES:
                self._mark_cancelled_locked(job, "Scan cancelled")
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

    def _start_job(self, job: ScanJob) -> None:
        if job.worker_mode == "process":
            self._start_process_job(job)
            return
        thread = threading.Thread(target=self._run_job_thread, args=(job.scan_id,), daemon=True)
        with self._lock:
            self._threads[job.scan_id] = thread
        thread.start()

    def _start_process_job(self, job: ScanJob) -> None:
        request = {
            "scan_id": job.scan_id,
            "workspace_path": job.workspace_path,
            "file_limit": job.file_limit,
            "analysis_mode": job.analysis_mode,
            "build_command": job.build_command,
            "dynamic_run_ids": job.dynamic_run_ids,
            "dynamic_mode": job.dynamic_mode,
            "dynamic_binary_path": job.dynamic_binary_path,
            "dynamic_args": job.dynamic_args,
            "dynamic_timeout_sec": job.dynamic_timeout_sec,
            "dynamic_tool_preference": job.dynamic_tool_preference,
        }
        event_queue = self._mp_context.Queue()
        process = self._mp_context.Process(
            target=_scan_worker_main,
            args=(request, event_queue, self.control_plane_factory),
            daemon=True,
        )
        process.start()
        monitor = threading.Thread(
            target=self._monitor_process_job,
            args=(job.scan_id, process, event_queue),
            daemon=True,
        )
        with self._condition:
            self._processes[job.scan_id] = process
            self._queues[job.scan_id] = event_queue
            self._queue_threads[job.scan_id] = monitor
            self._mark_job_starting_locked(job, "Scan worker started")
            self._condition.notify_all()
        monitor.start()

    def _run_job_thread(self, scan_id: str) -> None:
        job = self.get_job(scan_id)
        request = {
            "scan_id": job.scan_id,
            "workspace_path": job.workspace_path,
            "file_limit": job.file_limit,
            "analysis_mode": job.analysis_mode,
            "build_command": job.build_command,
            "dynamic_run_ids": job.dynamic_run_ids,
            "dynamic_mode": job.dynamic_mode,
            "dynamic_binary_path": job.dynamic_binary_path,
            "dynamic_args": job.dynamic_args,
            "dynamic_timeout_sec": job.dynamic_timeout_sec,
            "dynamic_tool_preference": job.dynamic_tool_preference,
        }
        control_plane = _build_control_plane(request, self.control_plane_factory)
        with self._condition:
            self._active_control_planes[scan_id] = control_plane
        try:
            with self._condition:
                if job.cancel_requested:
                    self._mark_cancelled_locked(job, "Scan cancelled before start")
                    self._condition.notify_all()
                    return
                self._mark_job_starting_locked(job, "Scan starting")
                self._condition.notify_all()

            report = control_plane.scan_repo(
                job.workspace_path,
                file_limit=job.file_limit,
                dynamic_run_ids=job.dynamic_run_ids,
                build_command=job.build_command,
                progress_callback=lambda event: self._record_control_plane_event(scan_id, event, raise_on_cancel=True),
            )
            report.update(_report_mode_metadata(job.analysis_mode))
            self._raise_if_cancelled(scan_id)
            with self._condition:
                self._complete_job_locked(job, report)
                self._condition.notify_all()
        except ScanCancelled:
            with self._condition:
                self._mark_cancelled_locked(job, "Scan cancelled")
                self._condition.notify_all()
        except Exception as exc:
            with self._condition:
                if job.cancel_requested:
                    self._mark_cancelled_locked(job, "Scan cancelled")
                else:
                    self._fail_job_locked(job, classify_scan_failure(exc))
                self._condition.notify_all()
        finally:
            close = getattr(control_plane, "close", None)
            if callable(close):
                close()
            with self._condition:
                self._active_control_planes.pop(scan_id, None)
                self._threads.pop(scan_id, None)

    def _monitor_process_job(self, scan_id: str, process: Any, event_queue: Any) -> None:
        saw_terminal_message = False
        try:
            while True:
                try:
                    message = event_queue.get(timeout=0.2)
                except queue.Empty:
                    if not process.is_alive():
                        break
                    continue

                kind = message.get("kind")
                if kind == "worker_started":
                    with self._condition:
                        job = self.get_job(scan_id)
                        job.worker_pid = message.get("pid")
                        self._write_status_locked(job)
                        self._condition.notify_all()
                    continue

                if kind == "progress":
                    self._record_control_plane_event(scan_id, message["event"], raise_on_cancel=False)
                    continue

                if kind == "report":
                    saw_terminal_message = True
                    with self._condition:
                        job = self.get_job(scan_id)
                        if job.status not in TERMINAL_STATES:
                            self._complete_job_locked(job, message["report"])
                            self._condition.notify_all()
                    break

                if kind == "error":
                    saw_terminal_message = True
                    with self._condition:
                        job = self.get_job(scan_id)
                        if job.status not in TERMINAL_STATES:
                            failure = ScanFailure(
                                code=message["failure"]["error_code"] or "scan_failed",
                                category=message["failure"]["error_category"] or "unknown",
                                message=message["failure"]["error"] or "Scan failed",
                                remediation=message["failure"]["remediation"] or "Inspect app logs for details.",
                                detail=message["failure"].get("detail"),
                            )
                            if job.cancel_requested and failure.category == "cancellation":
                                self._mark_cancelled_locked(job, failure.message)
                            elif job.cancel_requested and process.exitcode not in (0, None):
                                self._mark_cancelled_locked(job, "Scan cancelled")
                            else:
                                self._fail_job_locked(job, failure)
                            self._condition.notify_all()
                    break

                if kind == "worker_finished" and not process.is_alive():
                    break

            process.join(timeout=0.2)
            with self._condition:
                job = self.get_job(scan_id)
                if job.status not in TERMINAL_STATES:
                    if job.cancel_requested:
                        self._mark_cancelled_locked(job, "Scan cancelled")
                    elif saw_terminal_message and process.exitcode == 0:
                        self._fail_job_locked(
                            job,
                            classify_scan_failure("Scan worker exited before publishing a final report."),
                        )
                    elif process.exitcode == 0:
                        self._fail_job_locked(
                            job,
                            classify_scan_failure("Scan worker exited without producing a report."),
                        )
                    else:
                        self._fail_job_locked(
                            job,
                            classify_scan_failure(
                                f"Scan worker terminated unexpectedly with exit code {process.exitcode}."
                            ),
                        )
                    self._condition.notify_all()
        finally:
            with self._condition:
                self._processes.pop(scan_id, None)
                self._queues.pop(scan_id, None)
                self._queue_threads.pop(scan_id, None)
                self._write_status_locked(self.get_job(scan_id))

    def _record_control_plane_event(
        self,
        scan_id: str,
        event: dict[str, Any],
        raise_on_cancel: bool,
    ) -> None:
        with self._condition:
            job = self.get_job(scan_id)
            if job.status in TERMINAL_STATES:
                return
            phase = event.get("phase")
            if phase and phase not in {"completed"}:
                job.status = self._phase_to_status(phase)
            job.updated_at = time.time()
            self._append_event_locked(job, event.get("type", "progress"), **event)
            self._write_status_locked(job)
            self._condition.notify_all()
            if raise_on_cancel and job.cancel_requested:
                raise ScanCancelled()

    def _load_persisted_jobs(self) -> None:
        with self._condition:
            for summary in self._store.load_scan_summaries():
                job = self._job_from_summary(summary)
                job.events = self._store.load_events(job.scan_id)
                self._jobs[job.scan_id] = job
            self._recover_interrupted_jobs_locked()

    def _job_from_summary(self, summary: dict[str, Any]) -> ScanJob:
        report_stub = self._summary_report_stub(summary)
        return ScanJob(
            scan_id=summary["scan_id"],
            workspace_path=summary["workspace_path"],
            file_limit=int(summary.get("file_limit") or 500),
            analysis_mode=normalize_analysis_mode(summary.get("analysis_mode")),
            build_command=summary.get("build_command"),
            dynamic_run_ids=list(summary.get("dynamic_run_ids") or []),
            dynamic_mode=normalize_dynamic_mode(summary.get("dynamic_mode")),
            dynamic_binary_path=summary.get("dynamic_binary_path"),
            dynamic_args=normalize_dynamic_args(summary.get("dynamic_args")),
            dynamic_timeout_sec=summary.get("dynamic_timeout_sec"),
            dynamic_tool_preference=summary.get("dynamic_tool_preference"),
            status=summary.get("status") or "queued",
            created_at=float(summary.get("created_at") or time.time()),
            updated_at=float(summary.get("updated_at") or time.time()),
            started_at=summary.get("started_at"),
            finished_at=summary.get("finished_at"),
            error=summary.get("error"),
            error_code=summary.get("error_code"),
            error_category=summary.get("error_category"),
            remediation=summary.get("remediation"),
            error_detail=summary.get("error_detail"),
            report=report_stub,
            artifacts=dict(summary.get("artifacts") or {}),
            cancel_requested=bool(summary.get("cancel_requested")),
            worker_mode=summary.get("worker_mode") or "process",
            worker_pid=summary.get("worker_pid"),
        )

    def _summary_report_stub(self, summary: dict[str, Any]) -> dict[str, Any] | None:
        if all(summary.get(key) is None for key in ("bundle_count", "finding_count", "candidate_count", "evidence_count", "judge_summary")):
            return None
        return {
            "bundle_count": summary.get("bundle_count"),
            "finding_count": summary.get("finding_count"),
            "candidate_count": summary.get("candidate_count"),
            "evidence_count": summary.get("evidence_count"),
            "judge_summary": summary.get("judge_summary"),
            "analysis_mode": summary.get("analysis_mode"),
        }

    def _recover_interrupted_jobs_locked(self) -> None:
        for job in self._jobs.values():
            if job.status not in ACTIVE_STATES:
                continue
            if not job.events or job.events[-1]["type"] != "failed":
                self._append_event_locked(
                    job,
                    "failed",
                    error="Scan interrupted because the app restarted before the worker finished.",
                    error_code="app_restarted",
                    error_category="service_restart",
                    remediation="Start a new scan to resume the investigation.",
                )
            job.status = "failed"
            job.finished_at = time.time()
            job.updated_at = job.finished_at
            job.error = "Scan interrupted because the app restarted before the worker finished."
            job.error_code = "app_restarted"
            job.error_category = "service_restart"
            job.remediation = "Start a new scan to resume the investigation."
            job.error_detail = None
            self._write_status_locked(job)

    def _ensure_report_loaded_locked(self, job: ScanJob) -> None:
        needs_full_report = job.report is None or set(job.report.keys()).issubset(
            {"bundle_count", "finding_count", "candidate_count", "evidence_count", "judge_summary", "analysis_mode"}
        )
        if not needs_full_report:
            return
        stored_report = self._store.load_report(job.scan_id)
        if stored_report is not None:
            job.report = self._normalize_report_payload(stored_report)
            return
        report_path = (job.artifacts or {}).get("json")
        if not report_path:
            return
        report_file = Path(report_path)
        if not report_file.exists():
            return
        try:
            job.report = self._normalize_report_payload(json.loads(report_file.read_text(encoding="utf-8")))
        except Exception:
            return

    def _raise_if_cancelled(self, scan_id: str) -> None:
        with self._lock:
            if self.get_job(scan_id).cancel_requested:
                raise ScanCancelled()

    def _find_active_job_for_workspace_locked(self, workspace_path: str) -> ScanJob | None:
        for job in self._jobs.values():
            if job.workspace_path == workspace_path and job.status in ACTIVE_STATES:
                return job
        return None

    def _resolve_worker_mode(self) -> str:
        if self.worker_mode in {"thread", "process"}:
            return self.worker_mode
        return "thread" if self._custom_control_plane_factory else "process"

    def _terminate_process(self, process: Any) -> None:
        process.terminate()
        process.join(timeout=1.5)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join(timeout=1.0)

    def _mark_job_starting_locked(self, job: ScanJob, message: str) -> None:
        job.status = "starting"
        now = time.time()
        job.started_at = job.started_at or now
        job.updated_at = now
        self._append_event_locked(
            job,
            "starting",
            message=message,
            analysis_mode=job.analysis_mode,
            workspace_path=job.workspace_path,
            build_command=job.build_command,
            dynamic_run_ids=job.dynamic_run_ids,
            dynamic_mode=job.dynamic_mode,
            dynamic_binary_path=job.dynamic_binary_path,
            dynamic_args=job.dynamic_args,
            dynamic_timeout_sec=job.dynamic_timeout_sec,
            dynamic_tool_preference=job.dynamic_tool_preference,
            worker_mode=job.worker_mode,
        )
        self._write_status_locked(job)

    def _mark_cancelled_locked(self, job: ScanJob, message: str) -> None:
        if job.status == "cancelled":
            return
        job.status = "cancelled"
        job.finished_at = time.time()
        job.updated_at = job.finished_at
        job.error = "Scan cancelled."
        job.error_code = "scan_cancelled"
        job.error_category = "cancellation"
        job.remediation = "Start a new scan when you are ready to resume investigation."
        self._append_event_locked(job, "cancelled", message=message)
        self._write_status_locked(job)

    def _complete_job_locked(self, job: ScanJob, report: dict[str, Any]) -> None:
        artifacts = self._write_report_artifacts(job, report)
        self._store.save_report(job.scan_id, report)
        job.status = "completed"
        job.finished_at = time.time()
        job.updated_at = job.finished_at
        job.report = report
        job.artifacts = artifacts
        job.error = None
        job.error_code = None
        job.error_category = None
        job.remediation = None
        job.error_detail = None
        self._append_event_locked(
            job,
            "completed",
            message="Scan completed",
            artifacts=artifacts,
            bundle_count=report.get("bundle_count"),
            finding_count=report.get("finding_count"),
            candidate_count=report.get("candidate_count"),
            evidence_count=report.get("evidence_count"),
        )
        self._write_status_locked(job)

    def _fail_job_locked(self, job: ScanJob, failure: ScanFailure) -> None:
        job.status = "failed"
        job.error = failure.message
        job.error_code = failure.code
        job.error_category = failure.category
        job.remediation = failure.remediation
        job.error_detail = failure.detail
        job.finished_at = time.time()
        job.updated_at = job.finished_at
        self._append_event_locked(job, "failed", **failure.to_dict())
        self._write_status_locked(job)

    def _append_event_locked(self, job: ScanJob, event_type: str, **payload: Any) -> None:
        event = {
            "event_id": len(job.events) + 1,
            "scan_id": job.scan_id,
            "type": event_type,
            "timestamp": time.time(),
            **payload,
        }
        job.events.append(event)
        self._store.save_scan_summary(job.to_summary())
        self._store.append_event(job.scan_id, event)
        job_dir = self._job_dir(job.scan_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        with (job_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=True) + "\n")

    def _write_status_locked(self, job: ScanJob) -> None:
        self._store.save_scan_summary(job.to_summary())
        job_dir = self._job_dir(job.scan_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        (job_dir / "status.json").write_text(json.dumps(job.to_summary(), indent=2), encoding="utf-8")
        (job_dir / "request.json").write_text(
            json.dumps(
                {
                    "scan_id": job.scan_id,
                    "workspace_path": job.workspace_path,
                    "file_limit": job.file_limit,
                    "analysis_mode": job.analysis_mode,
                    "build_command": job.build_command,
                    "dynamic_run_ids": job.dynamic_run_ids,
                    "dynamic_mode": job.dynamic_mode,
                    "dynamic_binary_path": job.dynamic_binary_path,
                    "dynamic_args": job.dynamic_args,
                    "dynamic_timeout_sec": job.dynamic_timeout_sec,
                    "dynamic_tool_preference": job.dynamic_tool_preference,
                    "worker_mode": job.worker_mode,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def _write_report_artifacts(self, job: ScanJob, report: dict[str, Any]) -> dict[str, str]:
        job_dir = self._job_dir(job.scan_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        snapshot = build_result_snapshot(report, mode=job.analysis_mode)
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

    def _unlink_artifact(self, path: str | None) -> None:
        if not path:
            return
        artifact = Path(path)
        try:
            if artifact.exists():
                artifact.unlink()
        except IsADirectoryError:
            self._remove_job_dir(artifact)
        except FileNotFoundError:
            return

    def _remove_job_dir(self, path: Path) -> None:
        try:
            if path.exists():
                shutil.rmtree(path)
        except FileNotFoundError:
            return

    def _phase_to_status(self, phase: str) -> str:
        mapping = {
            "startup": "starting",
            "candidate_discovery": "indexing",
            "static_analysis": "static_analysis",
            "leakguard_analysis": "leakguard_analysis",
            "dynamic_build": "dynamic_build",
            "dynamic_planning": "dynamic_planning",
            "dynamic_execution": "dynamic_execution",
            "dynamic_merge": "dynamic_merge",
            "judging": "judging",
            "reporting": "reporting",
        }
        return mapping.get(phase, "starting")

    def _normalize_report_payload(self, report: dict[str, Any]) -> dict[str, Any]:
        findings = report.get("findings")
        if not findings and report.get("bundles"):
            findings = list(report.get("bundles") or [])
            report["findings"] = findings
        if findings and "bundles" not in report:
            report["bundles"] = findings
        if findings is not None and "finding_count" not in report:
            report["finding_count"] = len(findings)
        return report
