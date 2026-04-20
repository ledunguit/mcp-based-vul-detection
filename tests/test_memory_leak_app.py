from __future__ import annotations

import json
import time
from io import BytesIO
from pathlib import Path

import pytest

from src.memory_leak_app.jobs import DuplicateScanError, ScanJobManager, normalize_analysis_mode
from src.memory_leak_app.server import MemoryLeakApp
from src.memory_leak_app.workspaces import WorkspaceService


class FakeControlPlane:
    def scan_repo(self, repo_path: str, **kwargs):
        progress_callback = kwargs.get("progress_callback")
        if progress_callback:
            progress_callback({"type": "phase_started", "phase": "candidate_discovery", "message": "Scanning fake repo"})
            progress_callback({"type": "tool_started", "tool": "memory.candidate_scan", "subject": repo_path})
            progress_callback({"type": "tool_completed", "tool": "memory.candidate_scan", "status": "ok", "duration_ms": 1.0})
        return {
            "repo_path": repo_path,
            "bundle_count": 1,
            "candidate_count": 1,
            "evidence_count": 1,
            "indexed_file_count": 1,
            "scanned_file_count": 1,
            "candidate_source_file_count": 1,
            "dynamic_run_ids": [],
            "leakguard_tool": None,
            "scan_manifest": {},
            "tool_invocations": [
                {
                    "tool": "memory.candidate_scan",
                    "status": "ok",
                    "duration_ms": 1.0,
                    "reason": "test",
                }
            ],
            "investigation_tasks": [],
            "bundles": [
                {
                    "bundle_id": "bundle-1",
                    "candidate": {
                        "candidate_id": "candidate-1",
                        "summary": "Potential leak",
                        "primary_tool": "memory.candidate_scan",
                        "evidence": [
                            {
                                "tool": "memory.candidate_scan",
                                "kind": "candidate_discovery",
                                "confidence": "medium",
                                "message": "Potential leak",
                            }
                        ],
                    },
                    "verdict": {
                        "verdict": "likely_leak",
                        "confidence": "medium",
                        "why": "test",
                        "missing_evidence": [],
                        "fix_suggestions": [],
                    },
                }
            ],
        }

    def close(self) -> None:
        return None


class SlowControlPlane(FakeControlPlane):
    def scan_repo(self, repo_path: str, **kwargs):
        progress_callback = kwargs.get("progress_callback")
        if progress_callback:
            progress_callback({"type": "phase_started", "phase": "candidate_discovery", "message": "Scanning fake repo"})
        time.sleep(0.2)
        return super().scan_repo(repo_path, **kwargs)


class FailingControlPlane:
    def scan_repo(self, repo_path: str, **kwargs):
        raise RuntimeError("Failed to reach HTTP MCP server static: [Errno 61] Connection refused")

    def close(self) -> None:
        return None


class SlowProcessControlPlane(FakeControlPlane):
    def scan_repo(self, repo_path: str, **kwargs):
        progress_callback = kwargs.get("progress_callback")
        if progress_callback:
            progress_callback({"type": "phase_started", "phase": "candidate_discovery", "message": "Scanning fake repo"})
        time.sleep(5)
        return super().scan_repo(repo_path, **kwargs)

    def close(self) -> None:
        return None


def test_workspace_service_lists_allowed_c_projects(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    service = WorkspaceService([str(tmp_path)])

    result = service.list_workspaces()

    paths = {workspace["path"] for workspace in result["workspaces"]}
    assert str(repo.resolve()) in paths
    assert service.inspect_workspace(str(repo))["c_cpp_file_count"] == 1


def test_scan_job_manager_runs_scan_and_writes_artifacts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    manager = ScanJobManager(
        artifact_root=str(tmp_path / "artifacts"),
        control_plane_factory=lambda: FakeControlPlane(),
    )

    job = manager.create_scan(str(repo), file_limit=10, analysis_mode="no_llm")

    deadline = time.time() + 5
    while manager.get_job(job.scan_id).status not in {"completed", "failed"} and time.time() < deadline:
        time.sleep(0.02)

    completed = manager.get_job(job.scan_id)
    assert completed.status == "completed"
    assert completed.analysis_mode == "no_llm"
    assert completed.report["bundle_count"] == 1
    assert completed.report["analysis_mode"] == "no_llm"
    assert completed.report["orchestration_mode"] == "deterministic_policy"
    assert Path(completed.artifacts["json"]).exists()
    assert Path(completed.artifacts["markdown"]).exists()
    assert any(event["type"] == "tool_completed" for event in completed.events)


def test_scan_job_manager_persists_scans_and_events_in_sqlite(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    artifact_root = tmp_path / "artifacts"

    manager = ScanJobManager(
        artifact_root=str(artifact_root),
        control_plane_factory=lambda: FakeControlPlane(),
    )
    job = manager.create_scan(str(repo), file_limit=10, analysis_mode="llm_assisted")

    deadline = time.time() + 5
    while manager.get_job(job.scan_id).status not in {"completed", "failed"} and time.time() < deadline:
        time.sleep(0.02)

    restored_manager = ScanJobManager(
        artifact_root=str(artifact_root),
        control_plane_factory=lambda: FakeControlPlane(),
    )

    restored = restored_manager.get_job(job.scan_id)
    assert restored.status == "completed"
    assert restored.analysis_mode == "llm_assisted"
    assert restored.report is not None
    assert restored.report["bundle_count"] == 1
    assert any(event["type"] == "tool_completed" for event in restored.events)
    assert (artifact_root / "memory_leak_app.sqlite3").exists()


def test_scan_job_manager_deletes_terminal_scan_and_artifacts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    artifact_root = tmp_path / "artifacts"
    manager = ScanJobManager(
        artifact_root=str(artifact_root),
        control_plane_factory=lambda: FakeControlPlane(),
        worker_mode="thread",
    )

    job = manager.create_scan(str(repo), file_limit=10, analysis_mode="no_llm")
    deadline = time.time() + 5
    while manager.get_job(job.scan_id).status not in {"completed", "failed"} and time.time() < deadline:
        time.sleep(0.02)

    job_dir = artifact_root / job.scan_id
    assert job_dir.exists()

    result = manager.delete_job(job.scan_id)

    assert result["deleted"] is True
    assert result["deleted_scan_id"] == job.scan_id
    assert job.scan_id not in {item["scan_id"] for item in manager.list_jobs()}
    assert not job_dir.exists()

    restored = ScanJobManager(
        artifact_root=str(artifact_root),
        control_plane_factory=lambda: FakeControlPlane(),
        worker_mode="thread",
    )
    assert job.scan_id not in {item["scan_id"] for item in restored.list_jobs()}


def test_scan_job_manager_rejects_duplicate_active_scan(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    manager = ScanJobManager(
        artifact_root=str(tmp_path / "artifacts"),
        control_plane_factory=lambda: SlowControlPlane(),
    )

    first = manager.create_scan(str(repo), file_limit=10)

    with pytest.raises(DuplicateScanError) as exc:
        manager.create_scan(str(repo), file_limit=10)

    assert exc.value.existing_job.scan_id == first.scan_id


def test_scan_job_manager_rejects_deleting_active_scan(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    manager = ScanJobManager(
        artifact_root=str(tmp_path / "artifacts"),
        control_plane_factory=lambda: SlowControlPlane(),
    )

    job = manager.create_scan(str(repo), file_limit=10)

    with pytest.raises(Exception) as exc:
        manager.delete_job(job.scan_id)

    assert "cannot be deleted" in str(exc.value)


def test_scan_job_manager_marks_cancelled_when_callback_observes_cancel(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    manager = ScanJobManager(
        artifact_root=str(tmp_path / "artifacts"),
        control_plane_factory=lambda: SlowControlPlane(),
    )

    job = manager.create_scan(str(repo), file_limit=10)
    manager.cancel_job(job.scan_id)

    deadline = time.time() + 5
    status = manager.get_job(job.scan_id).status
    while status not in {"cancelled", "failed"} and time.time() < deadline:
        time.sleep(0.02)
        status = manager.get_job(job.scan_id).status

    assert manager.get_job(job.scan_id).status == "cancelled"


def test_scan_job_manager_classifies_failures(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    manager = ScanJobManager(
        artifact_root=str(tmp_path / "artifacts"),
        control_plane_factory=FailingControlPlane,
        worker_mode="thread",
    )

    job = manager.create_scan(str(repo), file_limit=10)

    deadline = time.time() + 5
    while manager.get_job(job.scan_id).status not in {"completed", "failed"} and time.time() < deadline:
        time.sleep(0.02)

    failed = manager.get_job(job.scan_id)
    assert failed.status == "failed"
    assert failed.error_code == "mcp_server_unreachable"
    assert failed.error_category == "dependency_unavailable"
    assert failed.remediation


def test_scan_job_manager_process_worker_cancels_by_terminating_worker(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    manager = ScanJobManager(
        artifact_root=str(tmp_path / "artifacts"),
        control_plane_factory=SlowProcessControlPlane,
        worker_mode="process",
    )

    job = manager.create_scan(str(repo), file_limit=10)
    time.sleep(0.2)
    manager.cancel_job(job.scan_id)

    deadline = time.time() + 5
    status = manager.get_job(job.scan_id).status
    while status not in {"cancelled", "failed"} and time.time() < deadline:
        time.sleep(0.05)
        status = manager.get_job(job.scan_id).status

    cancelled = manager.get_job(job.scan_id)
    assert cancelled.status == "cancelled"
    assert cancelled.worker_mode == "process"


def test_http_app_scan_lifecycle(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    app = MemoryLeakApp(
        workspace_service=WorkspaceService([str(tmp_path)]),
        job_manager=ScanJobManager(
            artifact_root=str(tmp_path / "artifacts"),
            control_plane_factory=lambda: FakeControlPlane(),
        ),
    )
    workspaces = _call_app_json(app, "GET", "/api/workspaces")
    assert workspaces["workspaces"]

    created = _call_app_json(
        app,
        "POST",
        "/api/scans",
        {
            "workspace_path": str(repo),
            "file_limit": 10,
            "analysis_mode": "llm_assisted",
        },
    )
    scan_id = created["scan_id"]

    deadline = time.time() + 5
    status = created
    while status["status"] not in {"completed", "failed"} and time.time() < deadline:
        time.sleep(0.02)
        status = _call_app_json(app, "GET", f"/api/scans/{scan_id}")

    assert status["status"] == "completed"
    assert status["analysis_mode"] == "llm_assisted"
    report = _call_app_json(app, "GET", f"/api/scans/{scan_id}/report?format=json")
    assert report["bundle_count"] == 1
    assert report["analysis_mode"] == "llm_assisted"
    events = _call_app_json(app, "GET", f"/api/scans/{scan_id}/events?format=json&after=0")
    assert len(events["events"]) >= 3
    assert any(event["type"] == "tool_completed" for event in events["events"])


def test_http_app_deletes_scan_and_purges_terminal_history(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.c").write_text("int main(void) { return 0; }\n")
    app = MemoryLeakApp(
        workspace_service=WorkspaceService([str(tmp_path)]),
        job_manager=ScanJobManager(
            artifact_root=str(tmp_path / "artifacts"),
            control_plane_factory=lambda: FakeControlPlane(),
            worker_mode="thread",
        ),
    )

    created = _call_app_json(
        app,
        "POST",
        "/api/scans",
        {
            "workspace_path": str(repo),
            "file_limit": 10,
            "analysis_mode": "no_llm",
        },
    )
    scan_id = created["scan_id"]
    deadline = time.time() + 5
    status = created
    while status["status"] not in {"completed", "failed"} and time.time() < deadline:
        time.sleep(0.02)
        status = _call_app_json(app, "GET", f"/api/scans/{scan_id}")

    deleted = _call_app_json(app, "DELETE", f"/api/scans/{scan_id}")
    assert deleted["deleted_scan_id"] == scan_id

    missing = _call_app("GET", app, f"/api/scans/{scan_id}")
    assert missing["status"] == 404

    purged = _call_app_json(app, "POST", "/api/scans/purge-terminal", {})
    assert purged["deleted_count"] == 0


def test_normalize_analysis_mode_defaults_and_validates() -> None:
    assert normalize_analysis_mode(None) == "no_llm"
    assert normalize_analysis_mode("LLM_ASSISTED") == "llm_assisted"
    with pytest.raises(ValueError):
        normalize_analysis_mode("agentic")


def test_http_app_returns_structured_validation_failure(tmp_path: Path) -> None:
    app = MemoryLeakApp(
        workspace_service=WorkspaceService([str(tmp_path)]),
        job_manager=ScanJobManager(
            artifact_root=str(tmp_path / "artifacts"),
            control_plane_factory=FakeControlPlane,
            worker_mode="thread",
        ),
    )

    response = _call_app("POST", app, "/api/scans", {"workspace_path": str(tmp_path / "missing"), "file_limit": 10})
    assert response["status"] == 400
    assert response["body"]["error_code"] == "invalid_workspace"
    assert response["body"]["remediation"]


def test_http_app_serves_frontend_bundle(tmp_path: Path) -> None:
    frontend_root = tmp_path / "frontend" / "dist"
    frontend_root.mkdir(parents=True)
    (frontend_root / "index.html").write_text("<!doctype html><html><body>frontend</body></html>", encoding="utf-8")
    (frontend_root / "assets.js").write_text("console.log('bundle');", encoding="utf-8")

    app = MemoryLeakApp(
        workspace_service=WorkspaceService([str(tmp_path)]),
        job_manager=ScanJobManager(
            artifact_root=str(tmp_path / "artifacts"),
            control_plane_factory=FakeControlPlane,
            worker_mode="thread",
        ),
        frontend_root=frontend_root,
    )

    root = _call_text("GET", app, "/")
    asset = _call_text("GET", app, "/assets.js")

    assert root["status"] == 200
    assert "frontend" in root["body"]
    assert asset["status"] == 200
    assert "bundle" in asset["body"]


class FakeHandler:
    def __init__(self, path: str, payload: dict | None = None):
        self.path = path
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        self.rfile = BytesIO(body)
        self.wfile = BytesIO()
        self.headers = {"Content-Length": str(len(body))}
        self.status = None
        self.response_headers = {}

    def send_response(self, status):
        self.status = int(status)

    def send_header(self, name, value):
        self.response_headers[name] = value

    def end_headers(self):
        return None


def _call_app_json(app: MemoryLeakApp, method: str, path: str, payload: dict | None = None) -> dict:
    response = _call_app(method, app, path, payload)
    assert response["status"] < 400, json.dumps(response["body"])
    return response["body"]


def _call_app(method: str, app: MemoryLeakApp, path: str, payload: dict | None = None) -> dict:
    handler = FakeHandler(path, payload=payload)
    if method == "POST":
        try:
            app.handle_post(handler)
        except Exception as exc:  # pragma: no cover - mirrors BaseHTTPRequestHandler wrapper
            if isinstance(exc, KeyError):
                app._send_error(handler, 404, "Scan not found")
            else:
                app._send_failure(handler, exc)
    elif method == "DELETE":
        try:
            app.handle_delete(handler)
        except Exception as exc:  # pragma: no cover - mirrors BaseHTTPRequestHandler wrapper
            if isinstance(exc, KeyError):
                app._send_error(handler, 404, "Scan not found")
            else:
                app._send_failure(handler, exc)
    else:
        try:
            app.handle_get(handler)
        except Exception as exc:  # pragma: no cover - mirrors BaseHTTPRequestHandler wrapper
            if isinstance(exc, KeyError):
                app._send_error(handler, 404, "Scan not found")
            else:
                app._send_failure(handler, exc)
    return {
        "status": handler.status,
        "body": json.loads(handler.wfile.getvalue().decode("utf-8")),
    }


def _call_text(method: str, app: MemoryLeakApp, path: str, payload: dict | None = None) -> dict:
    handler = FakeHandler(path, payload=payload)
    if method == "POST":
        app.handle_post(handler)
    else:
        app.handle_get(handler)
    return {
        "status": handler.status,
        "body": handler.wfile.getvalue().decode("utf-8"),
        "headers": handler.response_headers,
    }
