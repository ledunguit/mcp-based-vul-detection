"""Memory leak control plane built around external MCP analyzer servers."""

from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Iterable

from src.mcp_protocol.remote_bridge import build_remote_client_from_env

from .candidate_manager import CandidateManager
from .dynamic_orchestration import DynamicValidationPlanner
from .investigation_policy import InvestigationPolicy, InvestigationTask, ToolDecision
from .judge import MemoryLeakJudge
from .reporting import build_result_snapshot, render_html_report, render_markdown_report
from .shared_schema import LeakConfidence, LeakEvidence, LeakLocation, LeakSeverity, ToolKind


logger = logging.getLogger(__name__)


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
        dynamic_mode: str | None = None,
        dynamic_binary_path: str | None = None,
        dynamic_args: list[str] | None = None,
        dynamic_timeout_sec: int | None = None,
        dynamic_tool_preference: str | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        repo_root = Path(repo_path).expanduser().resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            raise FileNotFoundError(f"Repository path does not exist or is not a directory: {repo_root}")

        logger.info(f"Starting memory leak scan for repository: {repo_root}")
        logger.info(f"Scan parameters: file_limit={file_limit}, dynamic_mode={dynamic_mode}")

        self._emit(progress_callback, "phase_started", phase="startup", message="Validating MCP tools")
        self._require_tool("repo.index_files")
        self._require_tool("memory.candidate_scan")

        available_tools = [tool["name"] for tool in self.mcp_client.list_tools()]
        logger.debug(f"Available MCP tools: {', '.join(available_tools)}")
        policy = InvestigationPolicy(available_tools)
        tool_invocations: list[dict[str, Any]] = []
        investigation_tasks: list[InvestigationTask] = []
        manager = CandidateManager(str(repo_root))

        logger.info("Indexing repository files...")
        index_result = self._call_tool_traced(
            tool_invocations,
            "repo.index_files",
            {"root_path": str(repo_root), "limit": file_limit},
            reason="Index repository files before candidate discovery.",
            subject=str(repo_root),
            progress_callback=progress_callback,
        )
        logger.info(f"Indexed {index_result.get('count', 0)} files")

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
                ownership_summary_result=analysis["expanded"].get("memory.ownership_summary"),
                ownership_conventions_result=analysis["expanded"].get("memory.ownership_conventions"),
                call_graph_result=analysis["expanded"].get("memory.call_graph"),
                path_constraints_result=analysis["expanded"].get("memory.path_constraints"),
                interprocedural_flow_result=analysis["expanded"].get("memory.interprocedural_flow"),
                call_path_summary_result=analysis["expanded"].get("memory.call_path_summary"),
            )

        dynamic_run_ids = list(dynamic_run_ids or [])
        auto_dynamic_run_ids: list[str] = []
        dynamic_run_reports: list[dict[str, Any]] = []
        dynamic_rounds: list[dict[str, Any]] = []
        dynamic_build_result = None
        leakguard_result = None
        leakguard_tool = None
        project_ownership_graph_result = None
        project_static_decisions = policy.project_static_decision(build_command=build_command)
        for decision in project_static_decisions:
            if decision.tool == "repo.project_ownership_graph":
                if candidate_source_files <= 0:
                    continue
                self._emit(progress_callback, "phase_started", phase="project_ownership_graph", message="Building repo ownership graph")
                project_ownership_graph_result = self._call_tool_traced(
                    tool_invocations,
                    "repo.project_ownership_graph",
                    {"root_path": str(repo_root)},
                    reason=decision.reason,
                    subject=str(repo_root),
                    progress_callback=progress_callback,
                )
            elif decision.tool == "memory.leakguard_run":
                self._emit(progress_callback, "phase_started", phase="leakguard_analysis", message="Running LeakGuard")
                leakguard_args: dict[str, Any] = {"project_path": str(repo_root)}
                if build_command:
                    leakguard_args["build_command"] = build_command
                leakguard_result = self._call_tool_traced(
                    tool_invocations,
                    "memory.leakguard_run",
                    leakguard_args,
                    reason=decision.reason,
                    subject=str(repo_root),
                    progress_callback=progress_callback,
                )
                leakguard_tool = "memory.leakguard_run"
            elif decision.tool == "memory.leakguard_get_report":
                self._emit(progress_callback, "phase_started", phase="leakguard_analysis", message="Importing existing LeakGuard report")
                leakguard_result = self._call_tool_traced(
                    tool_invocations,
                    "memory.leakguard_get_report",
                    {"project_path": str(repo_root)},
                    reason=decision.reason,
                    subject=str(repo_root),
                    progress_callback=progress_callback,
                )
                leakguard_tool = "memory.leakguard_get_report"

        if leakguard_result is not None:
            manager.ingest_dynamic_bundles(leakguard_result.get("bundles", []))

        if build_command and self.mcp_client.has_tool("dynamic.build_target"):
            self._emit(
                progress_callback,
                "phase_started",
                phase="dynamic_build",
                message="Building target inside dynamic analysis environment",
            )
            dynamic_build_args: dict[str, Any] = {
                "project_path": str(repo_root),
                "build_command": build_command,
            }
            if dynamic_binary_path:
                dynamic_build_args["expected_output_path"] = str(Path(dynamic_binary_path).expanduser().resolve())
            dynamic_build_result = self._call_tool_traced(
                tool_invocations,
                "dynamic.build_target",
                dynamic_build_args,
                reason="Build the target project inside the dynamic-analysis environment before runtime validation.",
                subject=str(repo_root),
                progress_callback=progress_callback,
            )

        dynamic_planner = DynamicValidationPlanner(
            available_tools=available_tools,
            dynamic_mode=dynamic_mode,
            tool_preference=dynamic_tool_preference,
        )
        round_budget = self._dynamic_round_budget(dynamic_planner.dynamic_mode)
        executed_target_paths: set[str] = set()
        merged_dynamic_run_ids = list(dynamic_run_ids)
        latest_dynamic_plan_report: dict[str, Any] = {
            "requested_mode": dynamic_planner.dynamic_mode,
            "effective_mode": dynamic_planner.dynamic_mode,
            "tool_preference": dynamic_planner.tool_preference,
            "round_index": 0,
            "target_count": 0,
            "targets": [],
            "skipped_reasons": [],
            "planning_notes": [],
            "discovered_executable_count": 0,
            "discovered_input_count": 0,
        }

        for round_index in range(1, round_budget + 1):
            self._emit(
                progress_callback,
                "phase_started",
                phase="dynamic_planning",
                message=f"Planning dynamic validation round {round_index}",
                round_index=round_index,
            )
            dynamic_plan = dynamic_planner.plan(
                repo_root=repo_root,
                bundles=manager.list_bundles(),
                binary_hint=dynamic_binary_path,
                args_hint=dynamic_args,
                timeout_sec=dynamic_timeout_sec,
                round_index=round_index,
                exclude_target_paths=executed_target_paths,
            )
            latest_dynamic_plan_report = dynamic_plan.to_report()
            self._emit(
                progress_callback,
                "dynamic_plan_ready",
                phase="dynamic_planning",
                message=f"Prepared {len(dynamic_plan.targets)} dynamic validation target(s) for round {round_index}",
                dynamic_plan=latest_dynamic_plan_report,
                round_index=round_index,
            )
            round_record = {
                "round_index": round_index,
                "plan": latest_dynamic_plan_report,
                "targets": [],
                "new_run_ids": [],
                "matched_bundle_ids": [],
                "attempted_bundle_ids": [],
            }
            dynamic_rounds.append(round_record)
            if not dynamic_plan.targets:
                break

            pre_dynamic_bundle_ids = {
                bundle.bundle_id
                for bundle in manager.list_bundles()
                if self._bundle_has_dynamic_evidence(bundle)
            }
            round_attempted_bundle_ids: set[str] = set()

            for target in dynamic_plan.targets:
                executed_target_paths.add(str(Path(target.target_path).resolve()))
                round_attempted_bundle_ids.update(target.bundle_ids)
                self._emit(
                    progress_callback,
                    "phase_started",
                    phase="dynamic_execution",
                    message=f"Running {target.tool} on {target.target_path}",
                    target=target.to_report(),
                    round_index=round_index,
                )
                run_result = self._call_tool_traced(
                    tool_invocations,
                    target.tool,
                    self._dynamic_runner_arguments(target),
                    reason=target.reason,
                    subject=target.target_path,
                    progress_callback=progress_callback,
                )
                dynamic_run_reports.append(run_result)
                round_record["targets"].append(target.to_report())
                run_id = run_result.get("run_id")
                if run_id:
                    auto_dynamic_run_ids.append(run_id)
                    merged_dynamic_run_ids.append(run_id)
                    round_record["new_run_ids"].append(run_id)
                    self._emit(
                        progress_callback,
                        "dynamic_run_created",
                        phase="dynamic_execution",
                        message=f"Dynamic run {run_id} finished",
                        run_id=run_id,
                        tool=target.tool,
                        target_path=target.target_path,
                        round_index=round_index,
                    )
                    self._merge_dynamic_run(
                        manager=manager,
                        tool_invocations=tool_invocations,
                        policy=policy,
                        run_id=run_id,
                        progress_callback=progress_callback,
                    )

            matched_bundle_ids = {
                bundle.bundle_id
                for bundle in manager.list_bundles()
                if bundle.bundle_id not in pre_dynamic_bundle_ids and self._bundle_has_dynamic_evidence(bundle)
            }
            round_record["matched_bundle_ids"] = sorted(matched_bundle_ids)
            round_record["attempted_bundle_ids"] = sorted(round_attempted_bundle_ids)
            self._annotate_negative_dynamic_attempts(
                bundles=manager.list_bundles(),
                attempted_bundle_ids=round_attempted_bundle_ids,
                matched_bundle_ids=matched_bundle_ids,
                round_index=round_index,
                targets=dynamic_plan.targets,
            )
            if self._all_bundles_exhausted(manager.list_bundles(), max_attempts=round_budget):
                break

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
        report["dynamic_run_ids"] = merged_dynamic_run_ids
        report["external_dynamic_run_ids"] = dynamic_run_ids
        report["auto_dynamic_run_ids"] = auto_dynamic_run_ids
        report["dynamic_execution_plan"] = latest_dynamic_plan_report
        report["dynamic_rounds"] = dynamic_rounds
        report["dynamic_run_reports"] = dynamic_run_reports
        report["dynamic_mode"] = latest_dynamic_plan_report.get("effective_mode")
        report["dynamic_binary_path"] = dynamic_binary_path
        report["dynamic_args"] = dynamic_args or []
        report["dynamic_timeout_sec"] = dynamic_timeout_sec
        report["dynamic_tool_preference"] = dynamic_tool_preference
        report["build_command"] = build_command
        report["dynamic_build"] = dynamic_build_result
        report["project_ownership_graph"] = project_ownership_graph_result
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
            dynamic_plan=latest_dynamic_plan_report,
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
        logger.info(f"Calling MCP tool: {tool_name}" + (f" for {subject}" if subject else ""))
        logger.debug(f"Tool arguments: {arguments}")

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
            result = self.mcp_client.call_tool(tool_name, arguments)
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            logger.info(f"Tool {tool_name} completed in {duration_ms}ms")
            return result
        except Exception as exc:
            status = "error"
            error = str(exc)
            logger.error(f"Tool {tool_name} failed: {error}")
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
        dynamic_plan: dict[str, Any],
    ) -> dict[str, Any]:
        compile_database = self._discover_compile_database(repo_root)
        return {
            "repo_path": str(repo_root),
            "file_limit": file_limit,
            "indexed_file_count": index_result.get("count", 0),
            "compile_database": compile_database,
            "build_command": build_command,
            "tool_policy": policy.manifest(),
            "dynamic_plan": dynamic_plan,
        }

    def _dynamic_runner_arguments(self, target: Any) -> dict[str, Any]:
        payload = {
            "target_path": target.target_path,
            "args": target.args,
            "cwd": target.cwd,
            "timeout_sec": target.timeout_sec,
            "labels": target.labels,
        }
        return payload

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

    def _merge_dynamic_run(
        self,
        manager: CandidateManager,
        tool_invocations: list[dict[str, Any]],
        policy: InvestigationPolicy,
        run_id: str,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        for current_run_id, decision in zip([run_id], policy.dynamic_decisions([run_id]), strict=False):
            self._emit(progress_callback, "phase_started", phase="dynamic_merge", message=f"Merging dynamic run {current_run_id}")
            self._require_tool("memory.get_leak_bundles")
            dynamic_result = self._call_tool_traced(
                tool_invocations,
                "memory.get_leak_bundles",
                {"run_id": current_run_id},
                reason=decision.reason,
                subject=current_run_id,
                progress_callback=progress_callback,
            )
            manager.ingest_dynamic_bundles(dynamic_result.get("bundles", []))

    def _bundle_has_dynamic_evidence(self, bundle: Any) -> bool:
        return any(evidence.tool_kind == ToolKind.DYNAMIC for evidence in bundle.candidate.evidence)

    def _all_bundles_exhausted(self, bundles: list[Any], max_attempts: int) -> bool:
        for bundle in bundles:
            if self._bundle_has_dynamic_evidence(bundle):
                continue
            attempt_count = sum(
                1
                for evidence in bundle.candidate.evidence
                if evidence.tool_kind == ToolKind.ORCHESTRATOR and evidence.kind == "dynamic_validation_attempt"
            )
            if attempt_count >= max_attempts:
                continue
            if any(
                evidence.tool_kind == ToolKind.ORCHESTRATOR and evidence.kind == "dynamic_validation_attempt"
                for evidence in bundle.candidate.evidence
            ):
                return False
            return False
        return True

    def _annotate_negative_dynamic_attempts(
        self,
        bundles: list[Any],
        attempted_bundle_ids: set[str],
        matched_bundle_ids: set[str],
        round_index: int,
        targets: list[Any],
    ) -> None:
        if not attempted_bundle_ids:
            return
        target_reports = [target.to_report() for target in targets]
        target_paths = [target.target_path for target in targets]
        for bundle in bundles:
            if bundle.bundle_id not in attempted_bundle_ids or bundle.bundle_id in matched_bundle_ids:
                continue
            if self._bundle_has_dynamic_evidence(bundle):
                continue
            message = (
                f"Dynamic validation round {round_index} executed {len(target_paths)} target(s) "
                "but did not correlate a leak finding back to this candidate."
            )
            if any(
                evidence.tool_kind == ToolKind.ORCHESTRATOR
                and evidence.kind == "dynamic_validation_attempt"
                and evidence.raw_evidence.get("round_index") == round_index
                for evidence in bundle.candidate.evidence
            ):
                continue
            bundle.candidate.evidence.append(
                LeakEvidence(
                    tool="memory.dynamic_validation_attempt",
                    tool_kind=ToolKind.ORCHESTRATOR,
                    kind="dynamic_validation_attempt",
                    message=message,
                    confidence=LeakConfidence.MEDIUM,
                    severity=LeakSeverity.INFO,
                    location=LeakLocation(
                        file=bundle.candidate.file,
                        line=bundle.candidate.line,
                        function=bundle.candidate.function,
                    ),
                    raw_evidence={
                        "round_index": round_index,
                        "matched_dynamic_evidence": False,
                        "workload_adequacy": "unknown",
                        "target_paths": target_paths,
                        "targets": target_reports,
                    },
                )
            )
            note = (
                f"Dynamic round {round_index} did not corroborate this bundle under the attempted workload(s)."
            )
            if note not in bundle.orchestrator_notes:
                bundle.orchestrator_notes.append(note)

    def _dynamic_round_budget(self, dynamic_mode: str) -> int:
        env_value = os.getenv("MEMORY_LEAK_DYNAMIC_MAX_ROUNDS", "").strip()
        if env_value.isdigit():
            return max(1, int(env_value))
        if dynamic_mode == "aggressive":
            return 3
        if dynamic_mode == "selective":
            return 2
        return 1


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
