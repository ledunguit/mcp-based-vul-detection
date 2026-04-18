"""Adaptive investigation policy for memory leak orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaskState(str, Enum):
    NEW = "new"
    NEEDS_STATIC_EXPANSION = "needs_static_expansion"
    NEEDS_DYNAMIC_VALIDATION = "needs_dynamic_validation"
    READY_FOR_JUDGE = "ready_for_judge"
    CLOSED = "closed"


@dataclass
class ToolDecision:
    tool: str
    reason: str
    required: bool = False


@dataclass
class InvestigationTask:
    task_id: str
    subject: str
    state: TaskState
    reason: str
    candidate_count: int = 0
    decisions: list[ToolDecision] = field(default_factory=list)

    def to_report(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "subject": self.subject,
            "state": self.state.value,
            "reason": self.reason,
            "candidate_count": self.candidate_count,
            "decisions": [
                {
                    "tool": decision.tool,
                    "reason": decision.reason,
                    "required": decision.required,
                }
                for decision in self.decisions
            ],
        }


class InvestigationPolicy:
    """Select the next analyzer calls from current evidence and available tools."""

    STATIC_EXPANSION_TOOLS = [
        "memory.ast_scan",
        "memory.function_summary",
        "memory.call_graph",
        "memory.path_constraints",
        "memory.interprocedural_flow",
        "memory.call_path_summary",
    ]

    PROJECT_STATIC_TOOLS = [
        "memory.leakguard_run",
        "memory.leakguard_get_report",
    ]

    DYNAMIC_TOOLS = [
        "memory.get_leak_bundles",
    ]

    def __init__(self, available_tools: list[str]):
        self.available_tools = set(available_tools)

    def file_task(self, file_path: str, scan_result: dict[str, Any]) -> InvestigationTask:
        candidate_count = scan_result.get("candidate_count", 0)
        if candidate_count <= 0:
            return InvestigationTask(
                task_id=f"file:{file_path}",
                subject=file_path,
                state=TaskState.CLOSED,
                reason="No allocation/free imbalance candidate was found by lexical scan.",
                candidate_count=0,
            )

        decisions = [
            ToolDecision(
                tool=tool,
                reason="Candidate-bearing file needs static context expansion before judging.",
            )
            for tool in self.STATIC_EXPANSION_TOOLS
            if tool in self.available_tools
        ]
        return InvestigationTask(
            task_id=f"file:{file_path}",
            subject=file_path,
            state=TaskState.NEEDS_STATIC_EXPANSION,
            reason="Lexical scan found memory-leak candidates.",
            candidate_count=candidate_count,
            decisions=decisions,
        )

    def project_static_decision(self, build_command: str | None = None) -> ToolDecision | None:
        if "memory.leakguard_run" in self.available_tools:
            reason = "Project-level static analyzer can corroborate local candidates."
            if build_command:
                reason += " Build command is available for compile database generation."
            return ToolDecision("memory.leakguard_run", reason)
        if "memory.leakguard_get_report" in self.available_tools:
            return ToolDecision(
                "memory.leakguard_get_report",
                "Existing LeakGuard artifacts can be imported without rerunning analysis.",
            )
        return None

    def dynamic_decisions(self, run_ids: list[str]) -> list[ToolDecision]:
        if "memory.get_leak_bundles" not in self.available_tools:
            return []
        return [
            ToolDecision(
                "memory.get_leak_bundles",
                f"Dynamic run {run_id} can confirm or refute static leak candidates.",
            )
            for run_id in run_ids
        ]

    def manifest(self) -> dict[str, Any]:
        return {
            "name": "memory-leak-investigation-policy/v1",
            "required": [
                tool for tool in ["repo.index_files", "memory.candidate_scan"] if tool in self.available_tools
            ],
            "static_expansion": [
                tool for tool in self.STATIC_EXPANSION_TOOLS if tool in self.available_tools
            ],
            "project_static": [
                tool for tool in self.PROJECT_STATIC_TOOLS if tool in self.available_tools
            ],
            "dynamic": [
                tool for tool in self.DYNAMIC_TOOLS if tool in self.available_tools
            ],
            "rules": [
                "Run lexical candidate scan for indexed C/C++ files.",
                "Only expand per-file static context when candidates are found.",
                "Use LeakGuard project-level evidence when available.",
                "Merge provided dynamic run bundles before final judging.",
                "Judge only after static expansion and available dynamic evidence are merged.",
            ],
        }
