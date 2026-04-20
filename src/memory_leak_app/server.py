from __future__ import annotations

import argparse
import json
import mimetypes
import os
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .jobs import DuplicateScanError, ScanDeletionError, ScanJobManager, classify_scan_failure, normalize_analysis_mode
from .workspaces import WorkspaceService


class MemoryLeakApp:
    def __init__(
        self,
        workspace_service: WorkspaceService | None = None,
        job_manager: ScanJobManager | None = None,
        frontend_root: str | Path | None = None,
    ):
        self.workspace_service = workspace_service or WorkspaceService()
        self.job_manager = job_manager or ScanJobManager()
        self.frontend_root = self._resolve_frontend_root(frontend_root)

    def make_handler(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                try:
                    app.handle_get(self)
                except KeyError:
                    app._send_error(self, HTTPStatus.NOT_FOUND, "Scan not found")
                except Exception as exc:
                    app._send_failure(self, exc)

            def do_POST(self) -> None:  # noqa: N802
                try:
                    app.handle_post(self)
                except KeyError:
                    app._send_error(self, HTTPStatus.NOT_FOUND, "Scan not found")
                except DuplicateScanError as exc:
                    app._send_json(
                        self,
                        {
                            "error": str(exc),
                            "existing_scan": exc.existing_job.to_summary(),
                        },
                        status=HTTPStatus.CONFLICT,
                    )
                except ScanDeletionError as exc:
                    app._send_json(
                        self,
                        {
                            "error": str(exc),
                            "remediation": exc.remediation,
                        },
                        status=HTTPStatus.CONFLICT,
                    )
                except Exception as exc:
                    app._send_failure(self, exc)

            def do_DELETE(self) -> None:  # noqa: N802
                try:
                    app.handle_delete(self)
                except KeyError:
                    app._send_error(self, HTTPStatus.NOT_FOUND, "Scan not found")
                except ScanDeletionError as exc:
                    app._send_json(
                        self,
                        {
                            "error": str(exc),
                            "remediation": exc.remediation,
                        },
                        status=HTTPStatus.CONFLICT,
                    )
                except Exception as exc:
                    app._send_failure(self, exc)

            def log_message(self, format: str, *args: Any) -> None:
                return

        return Handler

    def handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        path = parsed.path
        if path == "/api/workspaces":
            self._send_json(handler, self.workspace_service.list_workspaces())
            return
        if path == "/api/scans":
            self._send_json(handler, {"scans": self.job_manager.list_jobs()})
            return

        parts = [part for part in path.split("/") if part]
        if len(parts) >= 3 and parts[0] == "api" and parts[1] == "scans":
            scan_id = parts[2]
            if len(parts) == 3:
                self._send_json(handler, self.job_manager.get_job(scan_id).to_summary())
                return
            if len(parts) == 4 and parts[3] == "events":
                fmt = parse_qs(parsed.query).get("format", ["sse"])[0]
                if fmt == "json":
                    after = int(parse_qs(parsed.query).get("after", ["0"])[0] or 0)
                    self._send_json(handler, {"events": self.job_manager.get_events_since(scan_id, after)})
                    return
                self._stream_events(handler, scan_id)
                return
            if len(parts) == 4 and parts[3] == "report":
                fmt = parse_qs(parsed.query).get("format", ["json"])[0]
                self._send_report(handler, scan_id, fmt)
                return

        if path == "/api" or path.startswith("/api/"):
            self._send_error(handler, HTTPStatus.NOT_FOUND, "Not found")
            return

        self._send_frontend(handler, path)

    def _resolve_frontend_root(self, frontend_root: str | Path | None) -> Path:
        if frontend_root is not None:
            return Path(frontend_root).expanduser().resolve()
        env_root = os.getenv("MEMORY_LEAK_APP_FRONTEND_DIR")
        if env_root:
            return Path(env_root).expanduser().resolve()
        return (Path(__file__).resolve().parents[2] / "frontend" / "dist").resolve()

    def _send_frontend(self, handler: BaseHTTPRequestHandler, path: str) -> None:
        if not self.frontend_root.exists():
            self._send_text(
                handler,
                "Frontend bundle is missing. Build MCP-Vul/frontend with `npm install && npm run build`.",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            )
            return

        requested = unquote(path.lstrip("/"))
        if requested:
            candidate = (self.frontend_root / requested).resolve()
            if self._is_within_frontend_root(candidate) and candidate.is_file():
                self._send_file(handler, candidate)
                return
            if Path(requested).suffix:
                self._send_error(handler, HTTPStatus.NOT_FOUND, "Static asset not found")
                return

        index_file = (self.frontend_root / "index.html").resolve()
        if not self._is_within_frontend_root(index_file) or not index_file.exists():
            self._send_text(
                handler,
                "Frontend entry point is missing. Build MCP-Vul/frontend before starting the app.",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            )
            return
        self._send_file(handler, index_file)

    def _is_within_frontend_root(self, candidate: Path) -> bool:
        try:
            candidate.relative_to(self.frontend_root)
            return True
        except ValueError:
            return False

    def _send_file(self, handler: BaseHTTPRequestHandler, path: Path) -> None:
        content_type, _ = mimetypes.guess_type(path.name)
        self._send_bytes(
            handler,
            path.read_bytes(),
            content_type=content_type or "application/octet-stream",
        )

    def handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        path = parsed.path
        if path == "/api/workspaces/validate":
            payload = self._read_json(handler)
            self._send_json(handler, self.workspace_service.inspect_workspace(payload.get("path", "")))
            return
        if path == "/api/scans":
            payload = self._read_json(handler)
            workspace = self.workspace_service.inspect_workspace(payload.get("workspace_path", ""))
            if workspace["c_cpp_file_count"] <= 0:
                raise ValueError("Selected workspace has no C/C++ files")
            job = self.job_manager.create_scan(
                workspace_path=workspace["path"],
                file_limit=int(payload.get("file_limit") or 500),
                analysis_mode=normalize_analysis_mode(payload.get("analysis_mode")),
                build_command=payload.get("build_command") or None,
                dynamic_run_ids=payload.get("dynamic_run_ids") or [],
            )
            self._send_json(handler, job.to_summary(), status=HTTPStatus.ACCEPTED)
            return
        if path == "/api/scans/purge-terminal":
            self._send_json(handler, self.job_manager.delete_terminal_jobs())
            return

        parts = [part for part in path.split("/") if part]
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "scans" and parts[3] == "cancel":
            job = self.job_manager.cancel_job(parts[2])
            self._send_json(handler, job.to_summary())
            return

        self._send_error(handler, HTTPStatus.NOT_FOUND, "Not found")

    def handle_delete(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "scans":
            self._send_json(handler, self.job_manager.delete_job(parts[2]))
            return
        self._send_error(handler, HTTPStatus.NOT_FOUND, "Not found")

    def _stream_events(self, handler: BaseHTTPRequestHandler, scan_id: str) -> None:
        handler.send_response(HTTPStatus.OK)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Cache-Control", "no-cache")
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()

        last_event_id = 0
        heartbeat_at = time.time()
        while True:
            events = self.job_manager.wait_for_events(scan_id, last_event_id, timeout=5.0)
            for event in events:
                last_event_id = max(last_event_id, int(event["event_id"]))
                handler.wfile.write(f"id: {event['event_id']}\n".encode("utf-8"))
                handler.wfile.write(f"data: {json.dumps(event, ensure_ascii=True)}\n\n".encode("utf-8"))
                handler.wfile.flush()
            job = self.job_manager.get_job(scan_id)
            if job.status in {"completed", "failed", "cancelled"} and last_event_id >= len(job.events):
                return
            if time.time() - heartbeat_at > 15:
                handler.wfile.write(b": heartbeat\n\n")
                handler.wfile.flush()
                heartbeat_at = time.time()

    def _send_report(self, handler: BaseHTTPRequestHandler, scan_id: str, fmt: str) -> None:
        job = self.job_manager.get_job(scan_id)
        report = self.job_manager.load_report(scan_id)
        if report is None:
            self._send_error(handler, HTTPStatus.CONFLICT, "Report is not ready")
            return
        if fmt == "markdown":
            path = job.artifacts.get("markdown")
            self._send_text(handler, self._read_artifact(path), content_type="text/markdown")
            return
        if fmt == "html":
            path = job.artifacts.get("html")
            self._send_text(handler, self._read_artifact(path), content_type="text/html")
            return
        if fmt == "snapshot":
            path = job.artifacts.get("snapshot")
            self._send_text(handler, self._read_artifact(path), content_type="application/json")
            return
        self._send_json(handler, report)

    def _read_json(self, handler: BaseHTTPRequestHandler) -> dict[str, Any]:
        length = int(handler.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = handler.rfile.read(length).decode("utf-8")
        return json.loads(raw) if raw else {}

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        payload: dict[str, Any],
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self._send_text(handler, json.dumps(payload, indent=2), status=status, content_type="application/json")

    def _send_text(
        self,
        handler: BaseHTTPRequestHandler,
        text: str,
        status: HTTPStatus = HTTPStatus.OK,
        content_type: str = "text/plain",
    ) -> None:
        self._send_bytes(handler, text.encode("utf-8"), status=status, content_type=content_type)

    def _send_bytes(
        self,
        handler: BaseHTTPRequestHandler,
        body: bytes,
        status: HTTPStatus = HTTPStatus.OK,
        content_type: str = "application/octet-stream",
    ) -> None:
        handler.send_response(status)
        if content_type.startswith("text/") or content_type in {
            "application/javascript",
            "application/json",
            "image/svg+xml",
        }:
            handler.send_header("Content-Type", f"{content_type}; charset=utf-8")
        else:
            handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def _send_error(self, handler: BaseHTTPRequestHandler, status: HTTPStatus, message: str) -> None:
        self._send_json(handler, {"error": message}, status=status)

    def _send_failure(self, handler: BaseHTTPRequestHandler, exc: Exception) -> None:
        failure = classify_scan_failure(exc)
        status = self._status_for_failure(failure.category)
        self._send_json(handler, failure.to_dict(), status=status)

    def _status_for_failure(self, category: str) -> HTTPStatus:
        if category == "input_validation":
            return HTTPStatus.BAD_REQUEST
        if category == "dependency_unavailable":
            return HTTPStatus.BAD_GATEWAY
        if category == "configuration":
            return HTTPStatus.PRECONDITION_FAILED
        if category in {"tool_execution", "llm_judge"}:
            return HTTPStatus.BAD_GATEWAY
        if category == "cancellation":
            return HTTPStatus.CONFLICT
        return HTTPStatus.INTERNAL_SERVER_ERROR

    def _read_artifact(self, path: str | None) -> str:
        if not path:
            raise FileNotFoundError("Artifact path is not available")
        with open(path, encoding="utf-8") as handle:
            return handle.read()


def run_server(host: str = "127.0.0.1", port: int = 8090) -> None:
    app = MemoryLeakApp()
    server = ThreadingHTTPServer((host, port), app.make_handler())
    print(f"Memory Leak Investigator UI: http://{host}:{port}")
    try:
        server.serve_forever()
    finally:
        app.job_manager.close()
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Memory Leak Investigator web application")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
