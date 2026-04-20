"""Memory leak control plane built around external MCP analyzer servers."""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Iterable

from src.mcp_protocol.remote_bridge import build_remote_client_from_env

from .candidate_manager import CandidateManager
from .investigation_policy import InvestigationPolicy, InvestigationTask, ToolDecision
from .judge import MemoryLeakJudge
from .reporting import build_result_snapshot, render_html_report, render_markdown_report


class MemoryLeakControlPlane:
    """Coordinate repo-level memory leak candidate discovery via MCP servers."""

    def __init__(self, mcp_client: Any | None = None, judge: MemoryLeakJudge | None = None):
        self.mcp_client = mcp_client or build_remote_client_from_env()
        self.judge = judge or MemoryLeakJudge()
        self.file_analysis_concurrency = max(1, int(os.getenv("MEMORY_LEAK_FILE_ANALYSIS_CONCURRENCY", "4")))
        self.static_tool_concurrency = max(1, int(os.getenv("MEMORY_LEAK_STATIC_TOOL_CONCURRENCY", "3")))
        self._tool_invocation_lock = Lock()

    def scan_repo(
        self,
        repo_path: str,
        file_limit: int = 500,
        dynamic_run_ids: Iterable[str] | None = None,
        build_command: str | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        repo_root = Path(repo_path).expanduser().resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            raise FileNotFoundError(f"Repository path does not exist or is not a directory: {repo_root}")

        self._emit(progress_callback, "phase_started", phase="startup", message="Validating MCP tools")
        self._require_tool("repo.index_files")
        self._require_tool("memory.candidate_scan")

        available_tools = [tool["name"] for tool in self.mcp_client.list_tools()]
        policy = InvestigationPolicy(available_tools)
        tool_invocations: list[dict[str, Any]] = []
        investigation_tasks: list[InvestigationTask] = []
        manager = CandidateManager(str(repo_root))
        index_result = self._call_tool_traced(
            tool_invocations,
            "repo.index_files",
            {"root_path": str(repo_root), "limit": file_limit},
            reason="Index repository files before candidate discovery.",
            subject=str(repo_root),
            progress_callback=progress_callback,
        )

        self._emit(
            progress_callback,
            "phase_started",
            phase="candidate_discovery",
            message=f"Scanning {index_result.get('count', 0)} indexed files",
            indexed_file_count=index_result.get("count", 0),
        )
        file_analyses = self._analyze_files(
            files=index_result.get("files", []),
            policy=policy,
            tool_invocations=tool_invocations,
            progress_callback=progress_callback,
        )
        scanned_files = 0
        candidate_source_files = 0
        for analysis in file_analyses:
            scanned_files += 1
            task = analysis["task"]
            investigation_tasks.append(task)
            self._emit(
                progress_callback,
                "task_updated",
                phase="candidate_discovery",
                task=task.to_report(),
                scanned_files=scanned_files,
            )
            if analysis["candidate_source_file"]:
                candidate_source_files += 1

            manager.ingest_static_scan(
                analysis["scan_result"],
                ast_result=analysis["expanded"].get("memory.ast_scan"),
                function_summary_result=analysis["expanded"].get("memory.function_summary"),
                call_graph_result=analysis["expanded"].get("memory.call_graph"),
                path_constraints_result=analysis["expanded"].get("memory.path_constraints"),
                interprocedural_flow_result=analysis["expanded"].get("memory.interprocedural_flow"),
                call_path_summary_result=analysis["expanded"].get("memory.call_path_summary"),
            )

        dynamic_run_ids = list(dynamic_run_ids or [])
        leakguard_result = None
        leakguard_tool = None
        project_static_decision = policy.project_static_decision(build_command=build_command)
        if project_static_decision and project_static_decision.tool == "memory.leakguard_run":
            self._emit(progress_callback, "phase_started", phase="leakguard_analysis", message="Running LeakGuard")
            leakguard_args: dict[str, Any] = {"project_path": str(repo_root)}
            if build_command:
                leakguard_args["build_command"] = build_command
            leakguard_result = self._call_tool_traced(
                tool_invocations,
                "memory.leakguard_run",
                leakguard_args,
                reason=project_static_decision.reason,
                subject=str(repo_root),
                progress_callback=progress_callback,
            )
            leakguard_tool = "memory.leakguard_run"
        elif project_static_decision and project_static_decision.tool == "memory.leakguard_get_report":
            self._emit(progress_callback, "phase_started", phase="leakguard_analysis", message="Importing existing LeakGuard report")
            leakguard_result = self._call_tool_traced(
                tool_invocations,
                "memory.leakguard_get_report",
                {"project_path": str(repo_root)},
                reason=project_static_decision.reason,
                subject=str(repo_root),
                progress_callback=progress_callback,
            )
            leakguard_tool = "memory.leakguard_get_report"

        if leakguard_result is not None:
            manager.ingest_dynamic_bundles(leakguard_result.get("bundles", []))

        for run_id, decision in zip(dynamic_run_ids, policy.dynamic_decisions(dynamic_run_ids), strict=False):
            self._emit(progress_callback, "phase_started", phase="dynamic_merge", message=f"Merging dynamic run {run_id}")
            self._require_tool("memory.get_leak_bundles")
            dynamic_result = self._call_tool_traced(
                tool_invocations,
                "memory.get_leak_bundles",
                {"run_id": run_id},
                reason=decision.reason,
                subject=run_id,
                progress_callback=progress_callback,
            )
            manager.ingest_dynamic_bundles(dynamic_result.get("bundles", []))

        self._emit(progress_callback, "phase_started", phase="judging", message="Judging clustered leak bundles")
        self.judge.judge_bundles(manager.list_bundles())
        self._emit(progress_callback, "phase_started", phase="reporting", message="Building scan report")
        report = manager.build_report()
        report["indexed_file_count"] = index_result.get("count", 0)
        report["scanned_file_count"] = scanned_files
        report["candidate_source_file_count"] = candidate_source_files
        report["dynamic_run_ids"] = dynamic_run_ids
        report["build_command"] = build_command
        report["leakguard_run"] = leakguard_result
        report["leakguard_tool"] = leakguard_tool
        report["static_expansion_mode"] = policy.static_expansion_mode
        report["file_analysis_concurrency"] = self.file_analysis_concurrency
        report["static_tool_concurrency"] = self.static_tool_concurrency
        report["available_tools"] = available_tools
        report["tool_invocations"] = tool_invocations
        report["performance_summary"] = self._build_performance_summary(tool_invocations)
        report["investigation_tasks"] = [task.to_report() for task in investigation_tasks]
        judge_summary = getattr(self.judge, "summary", None)
        if callable(judge_summary):
            report["judge_summary"] = judge_summary()
        report["scan_manifest"] = self._build_scan_manifest(
            repo_root=repo_root,
            file_limit=file_limit,
            index_result=index_result,
            build_command=build_command,
            policy=policy,
        )
        self._emit(
            progress_callback,
            "scan_completed",
            phase="completed",
            message="Memory leak scan completed",
            bundle_count=report["bundle_count"],
            evidence_count=report["evidence_count"],
        )
        return report

    def close(self) -> None:
        close = getattr(self.mcp_client, "close", None)
        if callable(close):
            close()

    def _require_tool(self, tool_name: str) -> None:
        if not self.mcp_client.has_tool(tool_name):
            available = ", ".join(tool["name"] for tool in self.mcp_client.list_tools())
            raise RuntimeError(f"Required MCP tool not available: {tool_name}. Available tools: {available}")

    def _run_static_expansion(
        self,
        tool_invocations: list[dict[str, Any]],
        decisions: list[ToolDecision],
        source_code: str,
        file_path: str,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, dict[str, Any]]:
        if not decisions:
            return {}
        if self.static_tool_concurrency <= 1 or len(decisions) <= 1:
            results = {}
            for decision in decisions:
                results[decision.tool] = self._call_tool_traced(
                    tool_invocations,
                    decision.tool,
                    {"source_code": source_code, "file_path": file_path},
                    reason=decision.reason,
                    subject=file_path,
                    progress_callback=progress_callback,
                )
            return results

        results = {}
        with ThreadPoolExecutor(max_workers=min(self.static_tool_concurrency, len(decisions))) as executor:
            future_map = {
                executor.submit(
                    self._call_tool_traced,
                    tool_invocations,
                    decision.tool,
                    {"source_code": source_code, "file_path": file_path},
                    decision.reason,
                    file_path,
                    progress_callback,
                ): decision.tool
                for decision in decisions
            }
            for future in as_completed(future_map):
                results[future_map[future]] = future.result()
        return results

    def _analyze_files(
        self,
        files: list[str],
        policy: InvestigationPolicy,
        tool_invocations: list[dict[str, Any]],
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> list[dict[str, Any]]:
        if self.file_analysis_concurrency <= 1 or len(files) <= 1:
            return [
                self._analyze_file(index, file_path, policy, tool_invocations, progress_callback)
                for index, file_path in enumerate(files)
            ]

        analyses: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(self.file_analysis_concurrency, len(files))) as executor:
            future_map = {
                executor.submit(
                    self._analyze_file,
                    index,
                    file_path,
                    policy,
                    tool_invocations,
                    progress_callback,
                ): index
                for index, file_path in enumerate(files)
            }
            for future in as_completed(future_map):
                analyses.append(future.result())
        analyses.sort(key=lambda item: item["index"])
        return analyses

    def _analyze_file(
        self,
        index: int,
        file_path: str,
        policy: InvestigationPolicy,
        tool_invocations: list[dict[str, Any]],
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        source_code = Path(file_path).read_text(errors="ignore")
        scan_result = self._call_tool_traced(
            tool_invocations,
            "memory.candidate_scan",
            {"source_code": source_code, "file_path": file_path},
            reason="Discover lexical memory allocation/free imbalance candidates.",
            subject=file_path,
            progress_callback=progress_callback,
        )
        task = policy.file_task(file_path, scan_result)
        expanded: dict[str, dict[str, Any]] = {}
        if task.candidate_count > 0:
            self._emit(
                progress_callback,
                "phase_started",
                phase="static_analysis",
                message=f"Expanding static context for {file_path}",
                file_path=file_path,
            )
            expanded = self._run_static_expansion(
                tool_invocations=tool_invocations,
                decisions=task.decisions,
                source_code=source_code,
                file_path=file_path,
                progress_callback=progress_callback,
            )
        return {
            "index": index,
            "file_path": file_path,
            "scan_result": scan_result,
            "task": task,
            "expanded": expanded,
            "candidate_source_file": task.candidate_count > 0,
        }

    def _call_tool_traced(
        self,
        tool_invocations: list[dict[str, Any]],
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
        subject: str | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        status = "ok"
        error = None
        self._emit(
            progress_callback,
            "tool_started",
            tool=tool_name,
            subject=subject,
            reason=reason,
        )
        try:
            return self.mcp_client.call_tool(tool_name, arguments)
        except Exception as exc:
            status = "error"
            error = str(exc)
            raise
        finally:
            invocation = {
                "tool": tool_name,
                "reason": reason,
                "subject": subject,
                "status": status,
                "error": error,
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            }
            with self._tool_invocation_lock:
                tool_invocations.append(invocation)
            self._emit(progress_callback, "tool_completed", **invocation)

    def _emit(
        self,
        progress_callback: Callable[[dict[str, Any]], None] | None,
        event_type: str,
        **payload: Any,
    ) -> None:
        if progress_callback is None:
            return
        progress_callback({"type": event_type, **payload})

    def _build_performance_summary(self, tool_invocations: list[dict[str, Any]]) -> dict[str, Any]:
        per_tool: dict[str, dict[str, Any]] = {}
        total_duration_ms = 0.0
        for invocation in tool_invocations:
            tool_name = invocation["tool"]
            duration_ms = float(invocation.get("duration_ms") or 0.0)
            total_duration_ms += duration_ms
            stats = per_tool.setdefault(
                tool_name,
                {
                    "calls": 0,
                    "total_duration_ms": 0.0,
                    "max_duration_ms": 0.0,
                    "error_count": 0,
                },
            )
            stats["calls"] += 1
            stats["total_duration_ms"] += duration_ms
            stats["max_duration_ms"] = max(stats["max_duration_ms"], duration_ms)
            if invocation.get("status") != "ok":
                stats["error_count"] += 1

        for stats in per_tool.values():
            calls = stats["calls"] or 1
            stats["avg_duration_ms"] = round(stats["total_duration_ms"] / calls, 3)
            stats["total_duration_ms"] = round(stats["total_duration_ms"], 3)
            stats["max_duration_ms"] = round(stats["max_duration_ms"], 3)

        return {
            "total_tool_duration_ms": round(total_duration_ms, 3),
            "tool_count": len(tool_invocations),
            "file_analysis_concurrency": self.file_analysis_concurrency,
            "static_tool_concurrency": self.static_tool_concurrency,
            "per_tool": dict(sorted(per_tool.items())),
        }

    def _build_scan_manifest(
        self,
        repo_root: Path,
        file_limit: int,
        index_result: dict[str, Any],
        build_command: str | None,
        policy: InvestigationPolicy,
    ) -> dict[str, Any]:
        compile_database = self._discover_compile_database(repo_root)
        return {
            "repo_path": str(repo_root),
            "file_limit": file_limit,
            "indexed_file_count": index_result.get("count", 0),
            "compile_database": compile_database,
            "build_command": build_command,
            "tool_policy": policy.manifest(),
        }

    def _discover_compile_database(self, repo_root: Path) -> dict[str, Any]:
        candidates = [
            repo_root / "compile_commands.json",
            repo_root / "build" / "compile_commands.json",
            repo_root / "compilation.json",
        ]
        existing = [str(path) for path in candidates if path.exists()]
        return {
            "found": bool(existing),
            "paths": existing,
            "policy": "prefer compile_commands.json, then build/compile_commands.json, then LeakGuard compilation.json",
        }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Scan a C/C++ repository for memory leak candidates")
    parser.add_argument("repo_path", help="Path to the C/C++ repository")
    parser.add_argument("--limit", type=int, default=500, help="Maximum number of source files to index")
    parser.add_argument(
        "--dynamic-run-id",
        action="append",
        default=[],
        help="Optional dynamic analysis run_id to merge into the investigation",
    )
    parser.add_argument(
        "--build-command",
        help="Optional build command forwarded to project-level analyzers such as LeakGuard.",
    )
    parser.add_argument("--output", "-o", help="Write JSON report to this file")
    parser.add_argument("--markdown-output", help="Write human-readable Markdown report to this file")
    parser.add_argument("--html-output", help="Write human-readable HTML report to this file")
    parser.add_argument("--snapshot-output", help="Write compact experiment snapshot JSON to this file")
    parser.add_argument("--snapshot-mode", default="orchestrated", help="Label for snapshot comparison mode")
    args = parser.parse_args()

    control_plane = MemoryLeakControlPlane()
    try:
        report = control_plane.scan_repo(
            args.repo_path,
            file_limit=args.limit,
            dynamic_run_ids=args.dynamic_run_id,
            build_command=args.build_command,
        )
    finally:
        control_plane.close()

    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)
    if args.markdown_output:
        Path(args.markdown_output).write_text(render_markdown_report(report))
    if args.html_output:
        Path(args.html_output).write_text(render_html_report(report))
    if args.snapshot_output:
        Path(args.snapshot_output).write_text(
            json.dumps(build_result_snapshot(report, mode=args.snapshot_mode), indent=2)
        )


if __name__ == "__main__":
    main()
