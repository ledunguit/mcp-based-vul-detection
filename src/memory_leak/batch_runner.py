from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .control_plane import MemoryLeakControlPlane
from .reporting import build_result_snapshot, render_html_report, render_markdown_report


def run_manifest(
    manifest_path: str,
    output_dir: str,
    *,
    file_limit: int = 500,
    snapshot_mode: str = "orchestrated",
) -> dict[str, Any]:
    manifest_file = Path(manifest_path).expanduser().resolve()
    output_root = Path(output_dir).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(manifest_file.read_text())
    cases = manifest.get("cases", [])
    results = []
    control_plane = MemoryLeakControlPlane()
    try:
        for case in cases:
            case_id = case["id"]
            repo_path = _resolve_case_path(manifest_file.parent, case["repo_path"])
            case_dir = output_root / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            report = control_plane.scan_repo(
                str(repo_path),
                file_limit=case.get("file_limit", file_limit),
                dynamic_run_ids=case.get("dynamic_run_ids", []),
                build_command=case.get("build_command"),
            )
            report["evaluation_case"] = {
                "id": case_id,
                "repo_path": str(repo_path),
                "expected_leak_count": case.get("expected_leak_count"),
                "notes": case.get("notes"),
            }
            snapshot = build_result_snapshot(report, mode=snapshot_mode)
            (case_dir / "report.json").write_text(json.dumps(report, indent=2))
            (case_dir / "report.md").write_text(render_markdown_report(report))
            (case_dir / "report.html").write_text(render_html_report(report))
            (case_dir / "snapshot.json").write_text(json.dumps(snapshot, indent=2))
            results.append(
                {
                    "case_id": case_id,
                    "repo_path": str(repo_path),
                    "report_path": str(case_dir / "report.json"),
                    "snapshot_path": str(case_dir / "snapshot.json"),
                    "bundle_count": report.get("bundle_count", 0),
                    "expected_leak_count": case.get("expected_leak_count"),
                    "evaluation": _evaluate_case(report, case),
                    "verdict_counts": snapshot.get("verdict_counts", {}),
                    "tool_invocation_count": snapshot.get("tool_invocation_count", 0),
                }
            )
    finally:
        control_plane.close()

    summary = {
        "schema_version": "memory-leak-evaluation-summary/v1",
        "manifest_path": str(manifest_file),
        "output_dir": str(output_root),
        "case_count": len(results),
        "results": results,
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def _evaluate_case(report: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    expected = case.get("expected_leak_count")
    confirmed_or_likely = sum(
        1
        for bundle in report.get("bundles", [])
        if (bundle.get("verdict") or {}).get("verdict") in {"confirmed_leak", "likely_leak"}
    )
    if expected is None:
        return {
            "has_ground_truth": False,
            "detected_confirmed_or_likely": confirmed_or_likely,
        }

    difference = confirmed_or_likely - int(expected)
    return {
        "has_ground_truth": True,
        "expected_leak_count": int(expected),
        "detected_confirmed_or_likely": confirmed_or_likely,
        "count_difference": difference,
        "count_matches": difference == 0,
    }


def _resolve_case_path(base_dir: Path, repo_path: str) -> Path:
    path = Path(repo_path).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (base_dir / path).resolve()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run memory leak investigation over a corpus manifest")
    parser.add_argument("manifest")
    parser.add_argument("--output-dir", "-o", required=True)
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--snapshot-mode", default="orchestrated")
    args = parser.parse_args()

    summary = run_manifest(
        args.manifest,
        args.output_dir,
        file_limit=args.limit,
        snapshot_mode=args.snapshot_mode,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
