from __future__ import annotations

import argparse
import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .jobs import ScanJobManager
from .ui import APP_HTML
from .workspaces import WorkspaceService


class MemoryLeakApp:
    def __init__(
        self,
        workspace_service: WorkspaceService | None = None,
        job_manager: ScanJobManager | None = None,
    ):
        self.workspace_service = workspace_service or WorkspaceService()
        self.job_manager = job_manager or ScanJobManager()

    def make_handler(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                try:
                    app.handle_get(self)
                except KeyError:
                    app._send_error(self, HTTPStatus.NOT_FOUND, "Scan not found")
                except Exception as exc:
                    app._send_error(self, HTTPStatus.BAD_REQUEST, str(exc))

            def do_POST(self) -> None:  # noqa: N802
                try:
                    app.handle_post(self)
                except KeyError:
                    app._send_error(self, HTTPStatus.NOT_FOUND, "Scan not found")
                except Exception as exc:
                    app._send_error(self, HTTPStatus.BAD_REQUEST, str(exc))

            def log_message(self, format: str, *args: Any) -> None:
                return

        return Handler

    def handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        path = parsed.path
        if path == "/":
            self._send_text(handler, APP_HTML, content_type="text/html")
            return
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
                self._stream_events(handler, scan_id)
                return
            if len(parts) == 4 and parts[3] == "report":
                fmt = parse_qs(parsed.query).get("format", ["json"])[0]
                self._send_report(handler, scan_id, fmt)
                return

        self._send_error(handler, HTTPStatus.NOT_FOUND, "Not found")

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
                build_command=payload.get("build_command") or None,
                dynamic_run_ids=payload.get("dynamic_run_ids") or [],
            )
            self._send_json(handler, job.to_summary(), status=HTTPStatus.ACCEPTED)
            return

        parts = [part for part in path.split("/") if part]
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "scans" and parts[3] == "cancel":
            job = self.job_manager.cancel_job(parts[2])
            self._send_json(handler, job.to_summary())
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
        if job.report is None:
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
        self._send_json(handler, job.report)

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
        body = text.encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", f"{content_type}; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def _send_error(self, handler: BaseHTTPRequestHandler, status: HTTPStatus, message: str) -> None:
        self._send_json(handler, {"error": message}, status=status)

    def _read_artifact(self, path: str | None) -> str:
        if not path:
            raise FileNotFoundError("Artifact path is not available")
        with open(path, encoding="utf-8") as handle:
            return handle.read()


def run_server(host: str = "127.0.0.1", port: int = 8090) -> None:
    app = MemoryLeakApp()
    server = ThreadingHTTPServer((host, port), app.make_handler())
    print(f"Memory Leak Investigator UI: http://{host}:{port}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Memory Leak Investigator web application")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
