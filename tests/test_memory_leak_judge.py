from __future__ import annotations

from pathlib import Path

from src.memory_leak.judge import MemoryLeakJudge
from src.memory_leak.shared_schema import LeakBundle, LeakEvidence


def _bundle() -> LeakBundle:
    return LeakBundle.model_validate(
        {
            "bundle_id": "bundle-1",
            "repo_path": "/tmp/repo",
            "candidate": {
                "candidate_id": "candidate-1",
                "signature": "/tmp/repo/demo.c:2:allocation",
                "summary": "Potential leak candidate",
                "primary_tool": "memory.candidate_scan",
                "confidence": "medium",
                "severity": "medium",
                "repo_path": "/tmp/repo",
                "file": "/tmp/repo/demo.c",
                "line": 2,
                "function": "demo",
                "allocation_site": {"file": "/tmp/repo/demo.c", "line": 2},
                "path_constraints": [
                    "possible_unfreed_allocation:buf@2",
                    "return_without_cleanup:buf == NULL@3",
                ],
                "tags": ["static", "candidate_scan", "allocation_without_local_free", "path_constraints"],
                "evidence": [
                    {
                        "tool": "memory.path_constraints",
                        "tool_kind": "static",
                        "kind": "path_constraints",
                        "message": "cleanup gap",
                        "confidence": "medium",
                        "severity": "info",
                        "raw_evidence": {},
                    },
                    {
                        "tool": "memory.function_summary",
                        "tool_kind": "static",
                        "kind": "function_summary",
                        "message": "allocation without local free",
                        "confidence": "medium",
                        "severity": "info",
                        "raw_evidence": {},
                    }
                ],
            },
        }
    )


class FakeResponse:
    def __init__(self, text: str):
        self.text = text
        self.tool_calls = []
        self.stop_reason = "end"
        self.raw_response = None


class GoodLLMClient:
    def chat(self, **kwargs):  # noqa: ARG002
        return FakeResponse(
            """
            {
              "verdict": "likely_leak",
              "confidence": "high",
              "why": "LeakGuard-like evidence and path constraints indicate cleanup is bypassed.",
              "supporting_evidence_ids": [0],
              "missing_evidence": ["dynamic confirmation"],
              "human_explanation": "The allocation is not freed on all paths.",
              "fix_suggestions": [
                {
                  "summary": "Add cleanup before returning",
                  "rationale": "A return path leaves the allocation live.",
                  "code_change_hint": "Free the allocation before returning from the error branch.",
                  "target_location": {
                    "file": "/tmp/repo/demo.c",
                    "line": 2,
                    "column": null,
                    "function": "demo",
                    "code_snippet": null
                  }
                }
              ]
            }
            """
        )


class BatchLLMClient:
    def __init__(self):
        self.calls = 0

    def chat(self, **kwargs):  # noqa: ARG002
        self.calls += 1
        return FakeResponse(
            """
            {
              "results": [
                {
                  "bundle_id": "bundle-1",
                  "verdict": "likely_leak",
                  "confidence": "high",
                  "why": "Merged evidence indicates cleanup is bypassed.",
                  "supporting_evidence_ids": [0],
                  "missing_evidence": ["dynamic confirmation"],
                  "human_explanation": "The allocation survives an early return path.",
                  "fix_suggestions": [
                    {
                      "summary": "Add cleanup before returning",
                      "rationale": "The error branch leaks the allocation.",
                      "code_change_hint": "Free the allocation before returning from the branch.",
                      "target_location": {
                        "file": "/tmp/repo/demo.c",
                        "line": 2,
                        "column": null,
                        "function": "demo",
                        "code_snippet": null
                      }
                    }
                  ]
                },
                {
                  "bundle_id": "bundle-2",
                  "verdict": "likely_leak",
                  "confidence": "medium",
                  "why": "The allocation appears to escape without cleanup.",
                  "supporting_evidence_ids": [0],
                  "missing_evidence": ["dynamic confirmation"],
                  "human_explanation": "The second allocation is also not freed on all paths.",
                  "fix_suggestions": []
                }
              ]
            }
            """
        )


class BrokenLLMClient:
    def chat(self, **kwargs):  # noqa: ARG002
        return FakeResponse("not valid json")


class OverconfidentLLMClient:
    def chat(self, **kwargs):  # noqa: ARG002
        return FakeResponse(
            """
            {
              "verdict": "confirmed_leak",
              "confidence": "high",
              "why": "The allocation appears leaked.",
              "supporting_evidence_ids": [0],
              "missing_evidence": [],
              "human_explanation": "The pointer is allocated and no free is visible.",
              "fix_suggestions": []
            }
            """
        )


def test_llm_judge_uses_llm_output_when_available() -> None:
    judge = MemoryLeakJudge(use_llm=True, client=GoodLLMClient())
    bundle = judge.judge_bundle(_bundle())

    assert bundle.verdict is not None
    assert bundle.verdict.verdict.value == "likely_leak"
    assert bundle.verdict.confidence.value == "high"
    assert bundle.verdict.fix_suggestions[0].summary == "Add cleanup before returning"


def test_llm_judge_falls_back_to_heuristic_when_output_is_invalid() -> None:
    judge = MemoryLeakJudge(use_llm=True, client=BrokenLLMClient())
    bundle = judge.judge_bundle(_bundle())

    assert bundle.verdict is not None
    assert bundle.verdict.verdict.value == "likely_leak"
    assert bundle.verdict.confidence.value == "medium"
    assert bundle.verdict.fix_suggestions


def test_llm_judge_calibrates_confirmed_without_dynamic_evidence() -> None:
    judge = MemoryLeakJudge(use_llm=True, client=OverconfidentLLMClient())
    bundle = judge.judge_bundle(_bundle())

    assert bundle.verdict is not None
    assert bundle.verdict.verdict.value == "likely_leak"
    assert bundle.verdict.confidence.value == "medium"
    assert "dynamic confirmation" in bundle.verdict.missing_evidence
    assert any(note.startswith("Judge calibration:") for note in bundle.orchestrator_notes)


def test_llm_judge_batches_multiple_bundles() -> None:
    client = BatchLLMClient()
    judge = MemoryLeakJudge(use_llm=True, client=client)
    bundles = [_bundle(), _bundle().model_copy(deep=True)]
    bundles[1].bundle_id = "bundle-2"
    bundles[1].candidate.candidate_id = "candidate-2"
    bundles[1].candidate.signature = "/tmp/repo/demo.c:8:allocation"

    judged = judge.judge_bundles(bundles)

    assert client.calls == 1
    assert judged[0].verdict is not None
    assert judged[1].verdict is not None
    assert judged[0].verdict.verdict.value == "likely_leak"
    assert judged[1].verdict.verdict.value == "likely_leak"
    assert judge.summary()["llm_batch_calls"] == 1


def test_llm_judge_selective_scope_skips_dynamic_bundle() -> None:
    client = BatchLLMClient()
    judge = MemoryLeakJudge(use_llm=True, client=client)
    bundle = _bundle()
    bundle.candidate.evidence.append(
        LeakEvidence.model_validate(
            {
                "tool": "valgrind.analyze_memcheck",
                "tool_kind": "dynamic",
                "kind": "leak",
                "message": "definitely lost",
                "confidence": "high",
                "severity": "high",
                "raw_evidence": {},
            }
        )
    )

    judged = judge.judge_bundle(bundle)

    assert client.calls == 0
    assert judged.verdict is not None
    assert judged.verdict.verdict.value == "confirmed_leak"
    assert judge.summary()["llm_skipped_count"] == 1


def test_heuristic_judge_generates_diff_preview_for_fix_suggestion(tmp_path: Path) -> None:
    repo_file = tmp_path / "demo.c"
    repo_file.write_text("int demo() {\n  char *buf = malloc(32);\n  return 0;\n}\n", encoding="utf-8")
    bundle = _bundle().model_copy(deep=True)
    bundle.candidate.file = str(repo_file)
    bundle.candidate.line = 2
    bundle.candidate.allocation_site.file = str(repo_file)
    bundle.candidate.allocation_site.line = 2
    bundle.candidate.allocation_site.code_snippet = "char *buf = malloc(32);"

    judged = MemoryLeakJudge(use_llm=False).judge_bundle(bundle)

    suggestion = judged.verdict.fix_suggestions[0]
    assert suggestion.target_location is not None
    assert suggestion.target_location.line == 3
    assert suggestion.before_snippet
    assert suggestion.before_start_line == 2
    assert suggestion.after_start_line == 2
    assert "char *buf = malloc(32);" in (suggestion.before_snippet or "")
    assert "return 0;" in (suggestion.before_snippet or "")
    assert "free(buf);" in (suggestion.after_snippet or "")
    assert "@@" in (suggestion.unified_diff or "")


def test_llm_fix_suggestion_preview_retargets_cleanup_line(tmp_path: Path) -> None:
    repo_file = tmp_path / "demo.c"
    repo_file.write_text("int demo() {\n  char *buf = malloc(32);\n  return 0;\n}\n", encoding="utf-8")
    bundle = _bundle().model_copy(deep=True)
    bundle.candidate.file = str(repo_file)
    bundle.candidate.line = 2
    bundle.candidate.allocation_site.file = str(repo_file)
    bundle.candidate.allocation_site.line = 2
    bundle.candidate.allocation_site.code_snippet = "char *buf = malloc(32);"

    judged = MemoryLeakJudge(use_llm=True, client=GoodLLMClient()).judge_bundle(bundle)

    suggestion = judged.verdict.fix_suggestions[0]
    assert suggestion.target_location is not None
    assert suggestion.target_location.line == 3
    assert "free(buf);" in (suggestion.after_snippet or "")


def test_heuristic_judge_treats_negative_dynamic_attempt_as_counterweight() -> None:
    judge = MemoryLeakJudge(use_llm=False)
    bundle = _bundle()
    bundle.candidate.evidence.append(
        LeakEvidence.model_validate(
            {
                "tool": "memory.dynamic_validation_attempt",
                "tool_kind": "orchestrator",
                "kind": "dynamic_validation_attempt",
                "message": "Dynamic validation round 1 did not correlate a leak",
                "confidence": "medium",
                "severity": "info",
                "raw_evidence": {
                    "round_index": 1,
                    "matched_dynamic_evidence": False,
                    "workload_adequacy": "adequate",
                },
            }
        )
    )

    judged = judge.judge_bundle(bundle)

    assert judged.verdict is not None
    assert judged.verdict.verdict.value == "inconclusive"
    assert "broader dynamic coverage" in judged.verdict.missing_evidence


def test_heuristic_judge_can_mark_weak_candidate_false_positive_after_negative_dynamic_attempt() -> None:
    judge = MemoryLeakJudge(use_llm=False)
    bundle = _bundle()
    bundle.candidate.path_constraints = []
    bundle.candidate.tags = ["static", "candidate_scan"]
    bundle.candidate.evidence = bundle.candidate.evidence[:1]
    bundle.candidate.evidence.append(
        LeakEvidence.model_validate(
            {
                "tool": "memory.dynamic_validation_attempt",
                "tool_kind": "orchestrator",
                "kind": "dynamic_validation_attempt",
                "message": "Dynamic validation round 1 did not correlate a leak",
                "confidence": "medium",
                "severity": "info",
                "raw_evidence": {
                    "round_index": 1,
                    "matched_dynamic_evidence": False,
                    "workload_adequacy": "adequate",
                },
            }
        )
    )

    judged = judge.judge_bundle(bundle)

    assert judged.verdict is not None
    assert judged.verdict.verdict.value == "false_positive"
    assert judged.verdict.confidence.value == "low"


def test_heuristic_judge_does_not_downgrade_on_low_coverage_dynamic_attempt() -> None:
    judge = MemoryLeakJudge(use_llm=False)
    bundle = _bundle()
    bundle.candidate.evidence.append(
        LeakEvidence.model_validate(
            {
                "tool": "memory.dynamic_validation_attempt",
                "tool_kind": "orchestrator",
                "kind": "dynamic_validation_attempt",
                "message": "Dynamic validation round 1 did not correlate a leak",
                "confidence": "medium",
                "severity": "info",
                "raw_evidence": {
                    "round_index": 1,
                    "matched_dynamic_evidence": False,
                    "workload_adequacy": "unknown",
                },
            }
        )
    )

    judged = judge.judge_bundle(bundle)

    assert judged.verdict is not None
    assert judged.verdict.verdict.value == "likely_leak"
    assert "higher-coverage dynamic validation" in judged.verdict.missing_evidence
