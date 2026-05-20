from __future__ import annotations

from src.memory_leak.reporting import (
    build_result_snapshot,
    compare_result_snapshots,
    render_html_report,
    render_markdown_report,
)


def _report() -> dict:
    return {
        "repo_path": "/tmp/repo",
        "indexed_file_count": 1,
        "scanned_file_count": 1,
        "candidate_source_file_count": 1,
        "bundle_count": 1,
        "evidence_count": 1,
        "dynamic_mode": "selective",
        "dynamic_tool_preference": "valgrind",
        "auto_dynamic_run_ids": ["run:auto-demo"],
        "external_dynamic_run_ids": [],
        "dynamic_execution_plan": {
            "requested_mode": "selective",
            "effective_mode": "selective",
            "tool_preference": "valgrind",
            "target_count": 1,
            "discovered_executable_count": 2,
            "discovered_input_count": 1,
            "planning_notes": ["Dynamic planner synthesized workload arguments from repository sample/corpus inputs."],
            "skipped_reasons": [],
            "targets": [
                {
                    "tool": "valgrind.analyze_memcheck",
                    "target_path": "/tmp/repo/bin/demo",
                    "args": ["/tmp/repo/examples/sample.txt"],
                    "cwd": "/tmp/repo/bin",
                    "timeout_sec": 120,
                    "labels": ["mode:selective"],
                    "reason": "Validate the highest-risk static bundles with a dynamic analyzer.",
                    "source": "auto_discovered",
                    "bundle_ids": ["bundle-1"],
                    "candidate_ids": ["candidate-1"],
                    "score": 72,
                    "arg_strategy": "auto_input_file",
                    "input_paths": ["/tmp/repo/examples/sample.txt"],
                }
            ],
        },
        "dynamic_rounds": [
            {
                "round_index": 1,
                "new_run_ids": ["run:auto-demo"],
                "matched_bundle_ids": [],
                "attempted_bundle_ids": ["bundle-1"],
            }
        ],
        "tool_invocations": [
            {
                "tool": "memory.candidate_scan",
                "status": "ok",
                "duration_ms": 1.2,
                "reason": "Discover lexical memory allocation/free imbalance candidates.",
            }
        ],
        "investigation_tasks": [
            {
                "task_id": "file:/tmp/repo/demo.c",
                "state": "needs_dynamic_validation",
                "reason": "Candidate needs dynamic validation.",
            }
        ],
        "bundles": [
            {
                "bundle_id": "bundle-1",
                "candidate": {
                    "candidate_id": "candidate-1",
                    "summary": "Potential leak of memory pointed to by 'buf'",
                    "primary_tool": "memory.leakguard_run",
                    "confidence": "high",
                    "file": "/tmp/repo/demo.c",
                    "line": 2,
                    "allocation_site": {"file": "/tmp/repo/demo.c", "line": 2},
                    "evidence": [
                        {
                            "tool": "memory.leakguard_run",
                            "kind": "leakguard_report",
                            "confidence": "high",
                            "message": "Potential leak of memory pointed to by 'buf'",
                            "artifacts": [
                                {
                                    "name": "leakguard_plist",
                                    "path": "/tmp/repo/report.plist",
                                }
                            ],
                        }
                    ],
                },
                "orchestrator_notes": ["Imported from LeakGuard current pipeline output"],
                "verdict_quality": {
                    "has_verdict": True,
                    "has_valid_supporting_evidence": True,
                    "has_human_explanation": True,
                    "has_fix_suggestions": True,
                    "issues": [],
                },
                "verdict": {
                    "verdict": "likely_leak",
                    "confidence": "high",
                    "human_explanation": "The allocation is not freed on all paths.",
                    "missing_evidence": ["dynamic confirmation"],
                    "fix_suggestions": [
                        {
                            "summary": "Add cleanup before early return",
                            "rationale": "A return path appears to bypass cleanup.",
                            "code_change_hint": "free(buf) before returning.",
                            "target_location": {"file": "/tmp/repo/demo.c", "line": 2},
                        }
                    ],
                },
            }
        ],
    }


def test_render_markdown_report_includes_verdict_evidence_and_fix() -> None:
    report = _report()

    markdown = render_markdown_report(report)

    assert "# Memory Leak Investigation Report" in markdown
    assert "## Dynamic Validation" in markdown
    assert "Planned targets: 1" in markdown
    assert "strategy=`auto_input_file`" in markdown
    assert "`/tmp/repo/examples/sample.txt`" in markdown
    assert "Dynamic rounds executed: 1" in markdown
    assert "`likely_leak`: 1" in markdown
    assert "#### Why This Is Considered A Leak" in markdown
    assert "Verdict quality: `complete`" in markdown
    assert "The allocation is not freed on all paths." in markdown
    assert "[0] `memory.leakguard_run`" in markdown
    assert "`leakguard_plist` /tmp/repo/report.plist" in markdown
    assert "## Investigation Trace" in markdown
    assert "`memory.candidate_scan` `ok`" in markdown
    assert "free(buf) before returning." in markdown


def test_render_html_report_wraps_markdown_summary() -> None:
    html = render_html_report(_report())

    assert "<!doctype html>" in html
    assert "<h1>Memory Leak Investigation Report</h1>" in html
    assert "<code>likely_leak</code>" in html


def test_result_snapshot_and_comparison_are_stable() -> None:
    baseline = build_result_snapshot(_report(), mode="static-only")
    current_report = _report()
    current_report["bundles"][0]["bundle_id"] = "bundle-2"
    current_report["bundle_count"] = 1
    current = build_result_snapshot(current_report, mode="orchestrated")
    comparison = compare_result_snapshots(baseline, current)

    assert baseline["schema_version"] == "memory-leak-snapshot/v1"
    assert baseline["tool_counts"]["memory.leakguard_run"] == 1
    assert baseline["tool_invocation_count"] == 1
    assert baseline["task_state_counts"]["needs_dynamic_validation"] == 1
    assert baseline["auto_dynamic_run_ids"] == ["run:auto-demo"]
    assert baseline["dynamic_execution_plan"]["target_count"] == 1
    assert baseline["dynamic_rounds"][0]["round_index"] == 1
    assert comparison["schema_version"] == "memory-leak-comparison/v1"
    assert comparison["added_bundle_ids"] == ["bundle-2"]
    assert comparison["removed_bundle_ids"] == ["bundle-1"]
