"""Human-readable reporting for memory leak investigation runs."""

from __future__ import annotations

from collections import Counter
from html import escape
from typing import Any


def render_markdown_report(report: dict[str, Any]) -> str:
    bundles = report.get("bundles", [])
    verdict_counts = Counter(
        (bundle.get("verdict") or {}).get("verdict", "unjudged")
        for bundle in bundles
    )

    lines = [
        "# Memory Leak Investigation Report",
        "",
        f"- Repository: `{report.get('repo_path', 'unknown')}`",
        f"- Analysis mode: `{report.get('analysis_mode', 'unknown')}`",
        f"- Orchestration mode: `{report.get('orchestration_mode', 'deterministic_policy')}`",
        f"- Indexed files: {report.get('indexed_file_count', 0)}",
        f"- Scanned files: {report.get('scanned_file_count', 0)}",
        f"- Candidate source files: {report.get('candidate_source_file_count', 0)}",
        f"- Static expansion mode: `{report.get('static_expansion_mode', 'balanced')}`",
        f"- File analysis concurrency: {report.get('file_analysis_concurrency', 1)}",
        f"- Static tool concurrency: {report.get('static_tool_concurrency', 1)}",
        f"- Bundles: {report.get('bundle_count', len(bundles))}",
        f"- Evidence items: {report.get('evidence_count', 0)}",
        f"- Tool invocations: {len(report.get('tool_invocations', []))}",
        "",
    ]
    judge_summary = report.get("judge_summary") or {}
    if judge_summary:
        lines.extend(
            [
                "## Judge Summary",
                "",
                f"- Requested judge mode: `{judge_summary.get('requested_mode', 'unknown')}`",
                f"- Effective judge mode: `{judge_summary.get('effective_mode', 'unknown')}`",
                f"- LLM used: `{judge_summary.get('llm_used', False)}`",
                f"- LLM success count: {judge_summary.get('llm_success_count', 0)}",
                f"- Heuristic fallback count: {judge_summary.get('heuristic_fallback_count', 0)}",
                f"- LLM skipped count: {judge_summary.get('llm_skipped_count', 0)}",
            ]
        )
        if judge_summary.get("provider"):
            lines.append(f"- LLM provider: `{judge_summary['provider']}`")
        if judge_summary.get("judge_scope"):
            lines.append(f"- Judge scope: `{judge_summary['judge_scope']}`")
        if judge_summary.get("judge_batch_size"):
            lines.append(f"- Judge batch size: {judge_summary['judge_batch_size']}")
        if judge_summary.get("last_llm_error"):
            lines.append(f"- Last LLM error: {judge_summary['last_llm_error']}")
        lines.append("")

    lines.extend(
        [
            "## Verdict Summary",
            "",
        ]
    )

    if verdict_counts:
        for verdict, count in sorted(verdict_counts.items()):
            lines.append(f"- `{verdict}`: {count}")
    else:
        lines.append("- No candidates found.")

    lines.extend(["", "## Findings", ""])
    if not bundles:
        lines.append("No memory leak candidates were found.")
        lines.extend(_render_investigation_trace(report))
        return "\n".join(lines).rstrip() + "\n"

    for index, bundle in enumerate(bundles, start=1):
        candidate = bundle.get("candidate", {})
        verdict = bundle.get("verdict") or {}
        evidence = candidate.get("evidence", [])
        lines.extend(
            [
                f"### {index}. {_text(candidate.get('summary'), 'Memory leak candidate')}",
                "",
                f"- Bundle ID: `{bundle.get('bundle_id', 'unknown')}`",
                f"- Candidate ID: `{candidate.get('candidate_id', 'unknown')}`",
                f"- Verdict: `{verdict.get('verdict', 'unjudged')}`",
                f"- Confidence: `{verdict.get('confidence', candidate.get('confidence', 'unknown'))}`",
                f"- Primary tool: `{candidate.get('primary_tool', 'unknown')}`",
                f"- Location: {_format_location(candidate)}",
                f"- Allocation site: {_format_location(candidate.get('allocation_site'))}",
                f"- Missing free site: {_format_location(candidate.get('missing_free_site'))}",
                f"- Verdict quality: {_format_verdict_quality(bundle.get('verdict_quality'))}",
                "",
                "#### Why This Is Considered A Leak",
                "",
                _text(verdict.get("human_explanation") or verdict.get("why"), "No explanation was produced."),
                "",
                "#### Missing Evidence",
                "",
            ]
        )
        missing_evidence = verdict.get("missing_evidence") or []
        if missing_evidence:
            lines.extend(f"- {item}" for item in missing_evidence)
        else:
            lines.append("- None recorded.")

        lines.extend(["", "#### Supporting Evidence", ""])
        if evidence:
            for evidence_index, item in enumerate(evidence):
                tool = item.get("tool", "unknown")
                kind = item.get("kind", "evidence")
                message = _text(item.get("message"), "")
                lines.append(
                    f"- [{evidence_index}] `{tool}` `{kind}` `{item.get('confidence', 'unknown')}`: {message}"
                )
                for artifact in item.get("artifacts", []) or []:
                    artifact_ref = artifact.get("uri") or artifact.get("path")
                    if artifact_ref:
                        lines.append(f"- Artifact: `{artifact.get('name', 'artifact')}` {artifact_ref}")
        else:
            lines.append("- No evidence attached.")

        lines.extend(["", "#### How To Fix", ""])
        suggestions = verdict.get("fix_suggestions") or []
        if suggestions:
            for suggestion in suggestions:
                lines.append(
                    "- "
                    f"{_text(suggestion.get('summary'), 'Inspect cleanup path')}: "
                    f"{_text(suggestion.get('rationale'), 'No rationale provided.')}"
                )
                if suggestion.get("code_change_hint"):
                    lines.append(f"- Code hint: {suggestion['code_change_hint']}")
                target = _format_location(suggestion.get("target_location"))
                if target != "unknown":
                    lines.append(f"- Target: {target}")
                if suggestion.get("unified_diff"):
                    lines.extend(["```diff", suggestion["unified_diff"], "```"])
        else:
            lines.append("- No fix suggestion was produced.")

        notes = bundle.get("orchestrator_notes") or []
        if notes:
            lines.extend(["", "#### Orchestrator Notes", ""])
            lines.extend(f"- {note}" for note in notes)

        lines.append("")

    lines.extend(_render_investigation_trace(report))
    return "\n".join(lines).rstrip() + "\n"


def render_html_report(report: dict[str, Any]) -> str:
    markdown = render_markdown_report(report)
    body = []
    for line in markdown.splitlines():
        if line.startswith("# "):
            body.append(f"<h1>{escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body.append(f"<h3>{escape(line[4:])}</h3>")
        elif line.startswith("#### "):
            body.append(f"<h4>{escape(line[5:])}</h4>")
        elif line.startswith("- "):
            body.append(f"<p class=\"item\">{_inline_code_to_html(line[2:])}</p>")
        elif line:
            body.append(f"<p>{_inline_code_to_html(line)}</p>")
        else:
            body.append("")

    return "\n".join(
        [
            "<!doctype html>",
            "<html lang=\"en\">",
            "<head>",
            "  <meta charset=\"utf-8\">",
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "  <title>Memory Leak Investigation Report</title>",
            "  <style>",
            "    body { font-family: Georgia, serif; margin: 2rem auto; max-width: 980px; line-height: 1.55; color: #1f2933; }",
            "    h1, h2, h3, h4 { font-family: Optima, Candara, sans-serif; color: #102a43; }",
            "    h1 { border-bottom: 3px solid #d9e2ec; padding-bottom: .4rem; }",
            "    h3 { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #d9e2ec; }",
            "    code { background: #f0f4f8; padding: .1rem .3rem; border-radius: 4px; }",
            "    .item { margin: .35rem 0 .35rem 1rem; }",
            "  </style>",
            "</head>",
            "<body>",
            *body,
            "</body>",
            "</html>",
            "",
        ]
    )


def build_result_snapshot(report: dict[str, Any], mode: str = "orchestrated") -> dict[str, Any]:
    bundles = report.get("bundles", [])
    verdict_counts = Counter(
        (bundle.get("verdict") or {}).get("verdict", "unjudged")
        for bundle in bundles
    )
    tool_counts = Counter(
        evidence.get("tool", "unknown")
        for bundle in bundles
        for evidence in (bundle.get("candidate", {}).get("evidence", []) or [])
    )
    return {
        "schema_version": "memory-leak-snapshot/v1",
        "mode": mode,
        "repo_path": report.get("repo_path"),
        "analysis_mode": report.get("analysis_mode"),
        "orchestration_mode": report.get("orchestration_mode"),
        "static_expansion_mode": report.get("static_expansion_mode"),
        "file_analysis_concurrency": report.get("file_analysis_concurrency"),
        "static_tool_concurrency": report.get("static_tool_concurrency"),
        "judge_summary": report.get("judge_summary"),
        "performance_summary": report.get("performance_summary"),
        "bundle_count": report.get("bundle_count", len(bundles)),
        "candidate_count": report.get("candidate_count", len(bundles)),
        "evidence_count": report.get("evidence_count", 0),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "tool_counts": dict(sorted(tool_counts.items())),
        "dynamic_run_ids": report.get("dynamic_run_ids", []),
        "leakguard_tool": report.get("leakguard_tool"),
        "scan_manifest": report.get("scan_manifest", {}),
        "tool_invocation_count": len(report.get("tool_invocations", [])),
        "task_state_counts": dict(
            sorted(
                Counter(task.get("state", "unknown") for task in report.get("investigation_tasks", [])).items()
            )
        ),
        "bundle_summaries": [
            {
                "bundle_id": bundle.get("bundle_id"),
                "candidate_id": (bundle.get("candidate") or {}).get("candidate_id"),
                "primary_tool": (bundle.get("candidate") or {}).get("primary_tool"),
                "verdict": (bundle.get("verdict") or {}).get("verdict"),
                "confidence": (bundle.get("verdict") or {}).get("confidence"),
                "location": _format_location(bundle.get("candidate")),
                "verdict_quality": bundle.get("verdict_quality"),
            }
            for bundle in bundles
        ],
    }


def compare_result_snapshots(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    baseline_ids = {item.get("bundle_id") for item in baseline.get("bundle_summaries", [])}
    current_ids = {item.get("bundle_id") for item in current.get("bundle_summaries", [])}
    return {
        "schema_version": "memory-leak-comparison/v1",
        "baseline_mode": baseline.get("mode"),
        "current_mode": current.get("mode"),
        "bundle_delta": current.get("bundle_count", 0) - baseline.get("bundle_count", 0),
        "evidence_delta": current.get("evidence_count", 0) - baseline.get("evidence_count", 0),
        "added_bundle_ids": sorted(item for item in current_ids - baseline_ids if item),
        "removed_bundle_ids": sorted(item for item in baseline_ids - current_ids if item),
        "baseline_verdict_counts": baseline.get("verdict_counts", {}),
        "current_verdict_counts": current.get("verdict_counts", {}),
    }


def _format_location(value: dict[str, Any] | None) -> str:
    if not value:
        return "unknown"
    file_name = value.get("file")
    line = value.get("line")
    column = value.get("column")
    function = value.get("function")
    location = file_name or "unknown"
    if line is not None:
        location = f"{location}:{line}"
    if column is not None:
        location = f"{location}:{column}"
    if function:
        location = f"{location} ({function})"
    return f"`{location}`" if location != "unknown" else location


def _text(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _format_verdict_quality(value: dict[str, Any] | None) -> str:
    if not value:
        return "`unknown`"
    issues = value.get("issues") or []
    if not issues:
        return "`complete`"
    return "`needs_review` " + "; ".join(str(issue) for issue in issues)


def _render_investigation_trace(report: dict[str, Any]) -> list[str]:
    tasks = report.get("investigation_tasks", [])
    invocations = report.get("tool_invocations", [])
    lines = ["", "## Investigation Trace", ""]
    if tasks:
        lines.extend(
            f"- Task `{task.get('task_id')}` `{task.get('state')}`: {task.get('reason')}"
            for task in tasks
        )
    else:
        lines.append("- No task trace recorded.")

    lines.extend(["", "## Tool Invocations", ""])
    if invocations:
        for invocation in invocations:
            lines.append(
                "- "
                f"`{invocation.get('tool')}` `{invocation.get('status')}` "
                f"{invocation.get('duration_ms')}ms: {invocation.get('reason')}"
            )
    else:
        lines.append("- No tool invocations recorded.")
    return lines


def _inline_code_to_html(value: str) -> str:
    escaped = escape(value)
    parts = escaped.split("`")
    if len(parts) == 1:
        return escaped
    output = []
    in_code = False
    for part in parts:
        if in_code:
            output.append(f"<code>{part}</code>")
        else:
            output.append(part)
        in_code = not in_code
    return "".join(output)
