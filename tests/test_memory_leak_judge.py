from __future__ import annotations

from src.memory_leak.judge import MemoryLeakJudge
from src.memory_leak.shared_schema import LeakBundle


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
