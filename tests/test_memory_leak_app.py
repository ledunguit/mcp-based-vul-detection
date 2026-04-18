from __future__ import annotations

import json
import time
from io import BytesIO
from pathlib import Path

from src.memory_leak_app.jobs import ScanJobManager
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

    job = manager.create_scan(str(repo), file_limit=10)

    deadline = time.time() + 5
    while manager.get_job(job.scan_id).status not in {"completed", "failed"} and time.time() < deadline:
        time.sleep(0.02)

    completed = manager.get_job(job.scan_id)
    assert completed.status == "completed"
    assert completed.report["bundle_count"] == 1
    assert Path(completed.artifacts["json"]).exists()
    assert Path(completed.artifacts["markdown"]).exists()
    assert any(event["type"] == "tool_completed" for event in completed.events)


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
        },
    )
    scan_id = created["scan_id"]

    deadline = time.time() + 5
    status = created
    while status["status"] not in {"completed", "failed"} and time.time() < deadline:
        time.sleep(0.02)
        status = _call_app_json(app, "GET", f"/api/scans/{scan_id}")

    assert status["status"] == "completed"
    report = _call_app_json(app, "GET", f"/api/scans/{scan_id}/report?format=json")
    assert report["bundle_count"] == 1


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
    handler = FakeHandler(path, payload=payload)
    if method == "POST":
        app.handle_post(handler)
    else:
        app.handle_get(handler)
    assert handler.status < 400, handler.wfile.getvalue().decode("utf-8")
    return json.loads(handler.wfile.getvalue().decode("utf-8"))
