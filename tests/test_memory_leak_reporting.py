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
    assert comparison["schema_version"] == "memory-leak-comparison/v1"
    assert comparison["added_bundle_ids"] == ["bundle-2"]
    assert comparison["removed_bundle_ids"] == ["bundle-1"]
