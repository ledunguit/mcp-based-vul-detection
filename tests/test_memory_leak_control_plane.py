from __future__ import annotations

from pathlib import Path

from src.memory_leak.candidate_manager import CandidateManager
from src.memory_leak.control_plane import MemoryLeakControlPlane


class FakeMCPClient:
    def __init__(self):
        self._tools = {
            "repo.index_files",
            "memory.candidate_scan",
            "memory.ast_scan",
            "memory.function_summary",
            "memory.call_graph",
            "memory.path_constraints",
            "memory.interprocedural_flow",
            "memory.call_path_summary",
            "memory.leakguard_run",
            "memory.leakguard_get_report",
            "memory.get_leak_bundles",
        }

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self._tools

    def list_tools(self) -> list[dict]:
        return [{"name": name} for name in sorted(self._tools)]

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        if tool_name == "repo.index_files":
            root = Path(arguments["root_path"])
            files = [str(path) for path in sorted(root.glob("*.c"))]
            return {"root_path": str(root), "count": len(files), "files": files}

        if tool_name == "memory.candidate_scan":
            source = arguments["source_code"]
            file_path = arguments["file_path"]
            if "malloc" not in source:
                return {
                    "file_path": file_path,
                    "allocation_count": 0,
                    "deallocation_count": 0,
                    "candidate_count": 0,
                    "candidates": [],
                }
            return {
                "file_path": file_path,
                "allocation_count": 1,
                "deallocation_count": 0,
                "candidate_count": 1,
                "candidates": [
                    {
                        "candidate_id": f"cand:{Path(file_path).name}",
                        "signature": f"{file_path}:2:allocation",
                        "summary": "Potential leak candidate discovered by lexical allocation scan",
                        "tool": "memory.candidate_scan",
                        "file": file_path,
                        "line": 2,
                        "allocation_site": {
                            "file": file_path,
                            "line": 2,
                            "code_snippet": "char *buf = malloc(32);",
                        },
                        "early_return_lines": [3],
                        "raw_evidence": {},
                    }
                ],
            }

        if tool_name == "memory.ast_scan":
            return {
                "file_path": arguments["file_path"],
                "function_name": "demo",
                "function_calls": [
                    {"name": "malloc", "arguments": ["32"], "line": 2},
                    {"name": "return", "arguments": [], "line": 3},
                ],
                "allocation_calls": [{"name": "malloc", "arguments": ["32"], "line": 2}],
                "deallocation_calls": [],
            }

        if tool_name == "memory.function_summary":
            return {
                "file_path": arguments["file_path"],
                "function_count": 1,
                "functions": [
                    {
                        "function_name": "demo",
                        "start_line": 1,
                        "end_line": 4,
                        "parameter_count": 0,
                        "local_variable_count": 1,
                        "call_count": 1,
                        "allocation_count": 1,
                        "deallocation_count": 0,
                        "return_count": 1,
                        "allocation_variables": [{"variable": "buf", "allocator": "malloc", "line": 2}],
                        "freed_variables": [],
                        "leaked_variables": [{"variable": "buf", "allocator": "malloc", "line": 2}],
                        "has_allocation_without_local_free": True,
                    }
                ],
            }

        if tool_name == "memory.call_graph":
            return {
                "file_path": arguments["file_path"],
                "function_count": 1,
                "internal_function_count": 1,
                "edge_count": 1,
                "functions": ["demo"],
                "edges": [{"caller": "demo", "callee": "malloc", "line": 2, "kind": "external"}],
            }

        if tool_name == "memory.path_constraints":
            return {
                "file_path": arguments["file_path"],
                "function_count": 1,
                "functions": [
                    {
                        "function_name": "demo",
                        "start_line": 1,
                        "end_line": 4,
                        "allocation_variables": [{"variable": "buf", "allocator": "malloc", "line": 2}],
                        "freed_variables": [],
                        "unfreed_allocations": [{"variable": "buf", "allocator": "malloc", "line": 2}],
                        "early_return_conditions": [
                            {
                                "line": 3,
                                "condition": "buf == NULL",
                                "branch": "consequence",
                                "risk": "return_without_cleanup",
                            }
                        ],
                        "return_lines": [3],
                        "constraint_count": 2,
                        "constraints": [
                            "possible_unfreed_allocation:buf@2",
                            "return_without_cleanup:buf == NULL@3",
                        ],
                    }
                ],
            }

        if tool_name == "memory.interprocedural_flow":
            return {
                "file_path": arguments["file_path"],
                "function_count": 1,
                "edge_count": 0,
                "flows": [],
                "functions": [
                    {
                        "function_name": "demo",
                        "start_line": 1,
                        "end_line": 4,
                        "direct_allocations": [{"variable": "buf", "allocator": "malloc", "line": 2}],
                        "direct_frees": [],
                        "receives_allocated_memory_from": [],
                        "delegates_cleanup_to": [],
                        "unresolved_internal_calls": [],
                        "risk": "local_allocation_without_cleanup_delegate",
                        "constraints": ["interprocedural_unfreed_allocation:demo:buf@2"],
                    }
                ],
            }

        if tool_name == "memory.call_path_summary":
            return {
                "file_path": arguments["file_path"],
                "function_count": 1,
                "path_count": 1,
                "start_function": None,
                "paths": [
                    {
                        "root": "demo",
                        "terminal_function": "demo",
                        "terminal_kind": "allocation",
                        "terminal_line": 2,
                        "frames": [{"function": "demo"}],
                        "event": {"kind": "allocation", "function": "demo", "line": 2},
                    }
                ],
            }

        if tool_name == "memory.get_leak_bundles":
            return {
                "run_id": arguments["run_id"],
                "bundle_count": 1,
                "bundles": [
                    {
                        "bundle_id": "dynamic-1",
                        "repo_path": "/tmp/repo",
                        "candidate": {
                            "candidate_id": "dynamic-1",
                            "signature": "demo.c:2:allocation",
                            "summary": "Leak confirmed dynamically",
                            "primary_tool": "valgrind.analyze_memcheck",
                            "confidence": "high",
                            "severity": "high",
                            "file": "demo.c",
                            "line": 2,
                            "tags": ["dynamic"],
                            "evidence": [
                                {
                                    "tool": "valgrind.analyze_memcheck",
                                    "tool_kind": "dynamic",
                                    "kind": "leak",
                                    "message": "definitely lost",
                                    "confidence": "high",
                                    "severity": "high",
                                    "raw_evidence": {},
                                }
                            ],
                        },
                        "related_candidates": [],
                        "orchestrator_notes": [],
                        "verdict": None,
                    }
                ],
            }

        if tool_name in {"memory.leakguard_run", "memory.leakguard_get_report"}:
            project_path = arguments["project_path"]
            file_path = str(Path(project_path) / "demo.c")
            return {
                "ok": True,
                "tool": tool_name,
                "project_path": project_path,
                "bundle_count": 1,
                "bundles": [
                    {
                        "bundle_id": "leakguard:demo",
                        "repo_path": project_path,
                        "candidate": {
                            "candidate_id": "leakguard:demo",
                            "signature": f"{file_path}:2:unix.Malloc",
                            "summary": "Potential leak of memory pointed to by 'buf'",
                            "primary_tool": "memory.leakguard_run",
                            "confidence": "high",
                            "severity": "medium",
                            "repo_path": project_path,
                            "file": file_path,
                            "line": 2,
                            "function": "buf",
                            "allocation_site": {"file": file_path, "line": 2, "column": 15},
                            "missing_free_site": {"file": file_path, "line": 3, "column": 5},
                            "path_constraints": ["Memory is allocated", "Potential leak of memory pointed to by 'buf'"],
                            "tags": ["static", "leakguard", "unix.Malloc"],
                            "evidence": [
                                {
                                    "tool": "memory.leakguard_run",
                                    "tool_kind": "static",
                                    "kind": "leakguard_report",
                                    "message": "Potential leak of memory pointed to by 'buf'",
                                    "confidence": "high",
                                    "severity": "medium",
                                    "raw_evidence": {},
                                }
                            ],
                        },
                        "related_candidates": [],
                        "orchestrator_notes": ["Imported from LeakGuard current pipeline output"],
                        "verdict": None,
                    }
                ],
            }

        raise AssertionError(f"Unexpected tool call: {tool_name}")

    def close(self) -> None:
        return None


def test_candidate_manager_merges_same_signature() -> None:
    manager = CandidateManager("/tmp/repo")
    manager.ingest_static_scan(
        {
            "file_path": "demo.c",
            "candidates": [
                {
                    "candidate_id": "static-1",
                    "signature": "demo.c:2:allocation",
                    "summary": "Potential leak candidate discovered by lexical allocation scan",
                    "tool": "memory.candidate_scan",
                    "file": "demo.c",
                    "line": 2,
                    "allocation_site": {
                        "file": "demo.c",
                        "line": 2,
                        "code_snippet": "char *buf = malloc(32);",
                    },
                    "early_return_lines": [],
                    "raw_evidence": {},
                }
            ],
        }
        ,
        function_summary_result={
            "functions": [
                {
                    "function_name": "demo",
                    "start_line": 1,
                    "end_line": 4,
                    "has_allocation_without_local_free": True,
                }
            ]
        },
        path_constraints_result={
            "functions": [
                {
                    "function_name": "demo",
                    "start_line": 1,
                    "end_line": 4,
                    "constraints": ["possible_unfreed_allocation:buf@2"],
                }
            ]
        },
    )
    manager.ingest_dynamic_bundles(
        [
            {
                "bundle_id": "dynamic-1",
                "candidate": {
                    "candidate_id": "dynamic-1",
                    "signature": "demo.c:2:allocation",
                    "summary": "Leak confirmed dynamically",
                    "primary_tool": "valgrind.analyze_memcheck",
                    "confidence": "high",
                    "severity": "high",
                    "file": "demo.c",
                    "line": 2,
                    "tags": ["dynamic"],
                    "evidence": [
                        {
                            "tool": "valgrind.analyze_memcheck",
                            "tool_kind": "dynamic",
                            "kind": "leak",
                            "message": "definitely lost",
                            "confidence": "high",
                            "severity": "high",
                            "raw_evidence": {},
                        }
                    ],
                },
            }
        ]
    )

    bundles = manager.list_bundles()
    assert len(bundles) == 1
    assert len(bundles[0].candidate.evidence) == 4
    assert "Also reported by valgrind.analyze_memcheck" in bundles[0].orchestrator_notes
    assert bundles[0].candidate.function == "demo"
    assert "possible_unfreed_allocation:buf@2" in bundles[0].candidate.path_constraints


def test_candidate_manager_merges_cross_tool_bundle_by_allocation_identity() -> None:
    manager = CandidateManager("/tmp/repo")
    manager.ingest_static_scan(
        {
            "file_path": "/tmp/repo/demo.c",
            "candidates": [
                {
                    "candidate_id": "static-1",
                    "signature": "/tmp/repo/demo.c:2:allocation",
                    "summary": "Potential leak candidate discovered by lexical allocation scan",
                    "tool": "memory.candidate_scan",
                    "file": "/tmp/repo/demo.c",
                    "line": 2,
                    "allocation_site": {
                        "file": "/tmp/repo/demo.c",
                        "line": 2,
                        "code_snippet": "char *buf = malloc(32);",
                    },
                    "early_return_lines": [],
                    "raw_evidence": {},
                }
            ],
        }
    )
    manager.ingest_dynamic_bundles(
        [
            {
                "bundle_id": "leakguard:1",
                "candidate": {
                    "candidate_id": "leakguard:1",
                    "signature": "/tmp/repo/demo.c:11:unix.Malloc",
                    "summary": "Potential leak of memory pointed to by 'buf'",
                    "primary_tool": "memory.leakguard_run",
                    "confidence": "high",
                    "severity": "medium",
                    "file": "/tmp/repo/demo.c",
                    "line": 11,
                    "allocation_site": {"file": "/tmp/repo/demo.c", "line": 2, "column": 15},
                    "evidence": [
                        {
                            "tool": "memory.leakguard_run",
                            "tool_kind": "static",
                            "kind": "leakguard_report",
                            "message": "Potential leak of memory pointed to by 'buf'",
                            "confidence": "high",
                            "severity": "medium",
                            "raw_evidence": {},
                        }
                    ],
                },
            }
        ]
    )

    bundles = manager.list_bundles()
    assert len(bundles) == 1
    assert bundles[0].candidate.primary_tool == "memory.leakguard_run"
    assert bundles[0].related_candidates == ["leakguard:1"]


def test_candidate_manager_does_not_merge_same_basename_in_different_directories() -> None:
    manager = CandidateManager("/tmp/repo")
    for candidate_id, file_path in [
        ("static-a", "/tmp/repo/src/a/demo.c"),
        ("static-b", "/tmp/repo/src/b/demo.c"),
    ]:
        manager.ingest_static_scan(
            {
                "file_path": file_path,
                "candidates": [
                    {
                        "candidate_id": candidate_id,
                        "signature": f"{file_path}:2:allocation",
                        "summary": "Potential leak candidate discovered by lexical allocation scan",
                        "tool": "memory.candidate_scan",
                        "file": file_path,
                        "line": 2,
                        "allocation_site": {
                            "file": file_path,
                            "line": 2,
                            "code_snippet": "char *buf = malloc(32);",
                        },
                        "early_return_lines": [],
                        "raw_evidence": {},
                    }
                ],
            }
        )

    bundles = manager.list_bundles()
    assert len(bundles) == 2


def test_control_plane_scans_repo_with_fake_client(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "demo.c").write_text("int demo() {\n  char *buf = malloc(32);\n  return 0;\n}\n")
    (repo / "clean.c").write_text("int clean() {\n  return 0;\n}\n")

    control_plane = MemoryLeakControlPlane(mcp_client=FakeMCPClient())
    report = control_plane.scan_repo(str(repo), dynamic_run_ids=["run-123"])

    assert report["indexed_file_count"] == 2
    assert report["scanned_file_count"] == 2
    assert report["bundle_count"] == 1
    assert report["dynamic_run_ids"] == ["run-123"]
    signatures = {bundle["candidate"]["signature"] for bundle in report["bundles"]}
    assert any(signature.endswith(":2:allocation") for signature in signatures)
    static_bundle = report["bundles"][0]
    tools = {evidence["tool"] for evidence in static_bundle["candidate"]["evidence"]}
    assert "memory.function_summary" in tools
    assert "memory.call_graph" in tools
    assert "memory.path_constraints" in tools
    assert "memory.interprocedural_flow" in tools
    assert "memory.call_path_summary" in tools
    assert "memory.leakguard_run" in tools
    assert "valgrind.analyze_memcheck" in tools
    assert static_bundle["candidate"]["primary_tool"] == "valgrind.analyze_memcheck"
    assert static_bundle["verdict"]["verdict"] == "confirmed_leak"
    assert static_bundle["task_state"] == "closed"
    assert static_bundle["provenance_history"]
    assert static_bundle["verdict_quality"]["has_valid_supporting_evidence"] is True
    assert static_bundle["verdict_quality"]["has_human_explanation"] is True
    assert static_bundle["verdict"]["human_explanation"]
    assert static_bundle["verdict"]["fix_suggestions"]
    assert report["leakguard_run"]["ok"] is True
    assert report["leakguard_tool"] == "memory.leakguard_run"
    assert report["scan_manifest"]["tool_policy"]["required"] == ["repo.index_files", "memory.candidate_scan"]
    assert report["scan_manifest"]["tool_policy"]["name"] == "memory-leak-investigation-policy/v1"
    assert "memory.interprocedural_flow" in report["scan_manifest"]["tool_policy"]["static_expansion"]
    assert report["tool_invocations"]
    assert any(invocation["tool"] == "memory.candidate_scan" for invocation in report["tool_invocations"])
    assert len(report["investigation_tasks"]) == 2
    assert any(task["state"] == "closed" for task in report["investigation_tasks"])
    assert any(task["state"] == "needs_static_expansion" for task in report["investigation_tasks"])


def test_control_plane_can_ingest_existing_leakguard_report_when_run_tool_is_absent(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "demo.c").write_text("int demo() {\n  char *buf = malloc(32);\n  return 0;\n}\n")

    client = FakeMCPClient()
    client._tools.remove("memory.leakguard_run")
    control_plane = MemoryLeakControlPlane(mcp_client=client)
    report = control_plane.scan_repo(str(repo))

    assert report["bundle_count"] == 1
    assert report["leakguard_tool"] == "memory.leakguard_get_report"
    assert report["leakguard_run"]["tool"] == "memory.leakguard_get_report"


def test_control_plane_does_not_expand_static_context_for_clean_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "clean.c").write_text("int clean() {\n  return 0;\n}\n")

    client = FakeMCPClient()
    client._tools.remove("memory.leakguard_run")
    client._tools.remove("memory.leakguard_get_report")
    control_plane = MemoryLeakControlPlane(mcp_client=client)
    report = control_plane.scan_repo(str(repo))

    invoked_tools = [invocation["tool"] for invocation in report["tool_invocations"]]
    assert invoked_tools == ["repo.index_files", "memory.candidate_scan"]
    assert report["bundle_count"] == 0
    assert report["investigation_tasks"][0]["state"] == "closed"
