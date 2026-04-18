from __future__ import annotations

import json
from pathlib import Path

from src.memory_leak import batch_runner


class FakeControlPlane:
    def scan_repo(self, repo_path: str, **kwargs):  # noqa: ARG002
        return {
            "repo_path": repo_path,
            "bundle_count": 1,
            "candidate_count": 1,
            "evidence_count": 1,
            "dynamic_run_ids": [],
            "leakguard_tool": None,
            "scan_manifest": {},
            "tool_invocations": [
                {
                    "tool": "memory.candidate_scan",
                    "status": "ok",
                    "duration_ms": 1.0,
                    "reason": "test",
                }
            ],
            "investigation_tasks": [
                {
                    "task_id": f"file:{repo_path}/demo.c",
                    "state": "needs_dynamic_validation",
                    "reason": "test",
                }
            ],
            "bundles": [
                {
                    "bundle_id": "bundle-1",
                    "candidate": {
                        "candidate_id": "candidate-1",
                        "summary": "Potential leak",
                        "primary_tool": "memory.candidate_scan",
                        "evidence": [
                            {
                                "tool": "memory.candidate_scan",
                                "kind": "candidate_discovery",
                                "confidence": "medium",
                                "message": "Potential leak",
                            }
                        ],
                    },
                    "verdict": {
                        "verdict": "likely_leak",
                        "confidence": "medium",
                        "why": "test",
                        "missing_evidence": [],
                        "fix_suggestions": [],
                    },
                }
            ],
        }

    def close(self) -> None:
        return None


def test_batch_runner_writes_case_outputs(tmp_path: Path, monkeypatch) -> None:
    corpus = tmp_path / "corpus"
    case_dir = corpus / "case-1"
    case_dir.mkdir(parents=True)
    manifest = corpus / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "id": "case-1",
                        "repo_path": "case-1",
                        "expected_leak_count": 1,
                    }
                ]
            }
        )
    )
    monkeypatch.setattr(batch_runner, "MemoryLeakControlPlane", lambda: FakeControlPlane())

    summary = batch_runner.run_manifest(str(manifest), str(tmp_path / "results"))

    assert summary["case_count"] == 1
    assert summary["results"][0]["case_id"] == "case-1"
    assert summary["results"][0]["evaluation"]["count_matches"] is True
    assert (tmp_path / "results" / "case-1" / "report.json").exists()
    assert (tmp_path / "results" / "case-1" / "snapshot.json").exists()
    assert (tmp_path / "results" / "summary.json").exists()
