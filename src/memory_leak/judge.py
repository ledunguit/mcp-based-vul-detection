"""Leak-centric verdict generation for merged investigation bundles."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from src.llm_client import LLMClient

from .shared_schema import (
    InvestigationVerdict,
    LeakBundle,
    LeakConfidence,
    LeakLocation,
    LeakSuggestion,
    ToolKind,
    VerdictResult,
)


LEAK_JUDGE_SYSTEM_PROMPT = """You are a memory leak investigation judge.

You receive a single normalized LeakBundle that already merges evidence from
static and dynamic analyzers.

Your job:
1. decide the final verdict
2. explain why the leak happens
3. describe what evidence is still missing
4. propose repair suggestions

Allowed verdicts:
- confirmed_leak
- likely_leak
- inconclusive
- false_positive

Rules:
- Use only the provided bundle evidence
- Prefer dynamic confirmation when available
- Treat project-level static analyzers such as LeakGuard as stronger than
  lightweight lexical scans
- Do not invent missing code details
- Keep fix suggestions concrete and scoped

Return JSON only with this structure:
{
  "verdict": "confirmed_leak|likely_leak|inconclusive|false_positive",
  "confidence": "high|medium|low",
  "why": "short rationale",
  "supporting_evidence_ids": [0, 1],
  "missing_evidence": ["dynamic confirmation"],
  "human_explanation": "human readable explanation",
  "fix_suggestions": [
    {
      "summary": "short fix title",
      "rationale": "why this helps",
      "code_change_hint": "optional patch direction",
      "target_location": {
        "file": "path/or/null",
        "line": 10,
        "column": null,
        "function": "name/or/null",
        "code_snippet": null
      }
    }
  ]
}
"""


class HeuristicMemoryLeakJudge:
    """Produce an initial verdict, explanation, and fix hints from merged evidence."""

    def judge_bundle(self, bundle: LeakBundle) -> LeakBundle:
        candidate = bundle.candidate
        dynamic_evidence_ids = [
            idx for idx, evidence in enumerate(candidate.evidence) if evidence.tool_kind == ToolKind.DYNAMIC
        ]
        leakguard_evidence_ids = [
            idx for idx, evidence in enumerate(candidate.evidence) if evidence.tool == "memory.leakguard_run"
        ]
        path_constraint_ids = [
            idx for idx, evidence in enumerate(candidate.evidence) if evidence.tool == "memory.path_constraints"
        ]

        has_dynamic = bool(dynamic_evidence_ids)
        has_leakguard = bool(leakguard_evidence_ids)
        has_cleanup_gap = any(
            constraint.startswith("possible_unfreed_allocation:")
            or constraint.startswith("return_without_cleanup:")
            for constraint in candidate.path_constraints
        )
        has_local_free_gap = "allocation_without_local_free" in candidate.tags

        if has_dynamic:
            verdict = InvestigationVerdict.CONFIRMED_LEAK
            confidence = LeakConfidence.HIGH
            supporting = dynamic_evidence_ids + leakguard_evidence_ids
            why = "Dynamic evidence confirms the leak and static evidence supports the same candidate."
        elif has_leakguard and (has_cleanup_gap or has_local_free_gap):
            verdict = InvestigationVerdict.LIKELY_LEAK
            confidence = LeakConfidence.HIGH
            supporting = leakguard_evidence_ids + path_constraint_ids
            why = "LeakGuard reported a leak and the static context shows missing cleanup or an unfreed allocation path."
        elif has_leakguard:
            verdict = InvestigationVerdict.LIKELY_LEAK
            confidence = LeakConfidence.MEDIUM
            supporting = leakguard_evidence_ids
            why = "LeakGuard reported a leak, but the surrounding static context is still limited."
        elif has_cleanup_gap and has_local_free_gap:
            verdict = InvestigationVerdict.LIKELY_LEAK
            confidence = LeakConfidence.MEDIUM
            supporting = path_constraint_ids
            why = "Static analysis found both an allocation without local free and a cleanup gap on a return path."
        elif has_cleanup_gap or has_local_free_gap:
            verdict = InvestigationVerdict.INCONCLUSIVE
            confidence = LeakConfidence.MEDIUM
            supporting = path_constraint_ids
            why = "Static analysis found a suspicious cleanup gap, but no stronger corroboration is available yet."
        else:
            verdict = InvestigationVerdict.INCONCLUSIVE
            confidence = LeakConfidence.LOW
            supporting = []
            why = "The candidate exists, but the evidence is still too weak to classify confidently."

        bundle.verdict = VerdictResult(
            candidate_id=candidate.candidate_id,
            verdict=verdict,
            confidence=confidence,
            why=why,
            supporting_evidence_ids=sorted(set(supporting)),
            missing_evidence=self._missing_evidence(has_dynamic, has_leakguard, has_cleanup_gap),
            human_explanation=self._human_explanation(bundle, verdict, why),
            fix_suggestions=self._fix_suggestions(bundle),
        )
        return bundle

    def judge_bundles(self, bundles: list[LeakBundle]) -> list[LeakBundle]:
        return [self.judge_bundle(bundle) for bundle in bundles]

    def _missing_evidence(
        self,
        has_dynamic: bool,
        has_leakguard: bool,
        has_cleanup_gap: bool,
    ) -> list[str]:
        missing = []
        if not has_dynamic:
            missing.append("dynamic confirmation")
        if not has_leakguard:
            missing.append("project-level static confirmation")
        if not has_cleanup_gap:
            missing.append("clear cleanup bypass path")
        return missing

    def _human_explanation(
        self,
        bundle: LeakBundle,
        verdict: InvestigationVerdict,
        why: str,
    ) -> str:
        candidate = bundle.candidate
        allocation_site = candidate.allocation_site or LeakLocation(file=candidate.file, line=candidate.line)
        missing_free_site = candidate.missing_free_site
        function = candidate.function or "unknown function"
        location = self._format_location(allocation_site)
        cleanup_location = self._format_location(missing_free_site) if missing_free_site else "no concrete cleanup site"
        evidence_tools = sorted({evidence.tool for evidence in candidate.evidence})
        evidence_text = ", ".join(evidence_tools) if evidence_tools else "no tool evidence"
        return (
            f"Verdict: {verdict.value}. "
            f"The candidate is tracked in {function} around allocation site {location}. "
            f"The current cleanup/leak endpoint is {cleanup_location}. "
            f"Evidence tools: {evidence_text}. "
            f"{why}"
        )

    def _format_location(self, location: LeakLocation | None) -> str:
        if not location or not location.file:
            return "unknown location"
        if location.line is None:
            return location.file
        if location.column is None:
            return f"{location.file}:{location.line}"
        return f"{location.file}:{location.line}:{location.column}"

    def _fix_suggestions(self, bundle: LeakBundle) -> list[LeakSuggestion]:
        suggestions = []
        candidate = bundle.candidate
        allocation_site = candidate.allocation_site or LeakLocation(file=candidate.file, line=candidate.line)

        if any(constraint.startswith("return_without_cleanup:") for constraint in candidate.path_constraints):
            suggestions.append(
                LeakSuggestion(
                    summary="Add cleanup before early return",
                    rationale="A return path appears to bypass cleanup after allocation.",
                    code_change_hint="Ensure the allocated object is freed before the branch returns.",
                    target_location=allocation_site,
                )
            )

        if "allocation_without_local_free" in candidate.tags:
            suggestions.append(
                LeakSuggestion(
                    summary="Clarify ownership or free before leaving the function",
                    rationale="The function allocates memory but no local deallocation is visible.",
                    code_change_hint="Either free the allocation locally or document/return ownership explicitly.",
                    target_location=allocation_site,
                )
            )

        if not suggestions:
            suggestions.append(
                LeakSuggestion(
                    summary="Inspect ownership and cleanup path",
                    rationale="The candidate needs stronger confirmation before a precise fix can be suggested.",
                    target_location=allocation_site,
                )
            )

        return suggestions


class MemoryLeakJudge:
    """LLM-first leak judge with heuristic fallback."""

    def __init__(
        self,
        provider: str | None = None,
        use_llm: bool | None = None,
        client: LLMClient | None = None,
    ):
        mode = (os.getenv("MEMORY_LEAK_JUDGE_MODE", "heuristic") or "heuristic").strip().lower()
        self.use_llm = use_llm if use_llm is not None else mode == "llm"
        self.client = client if self.use_llm else None
        self.provider = provider
        self.heuristic = HeuristicMemoryLeakJudge()

        if self.use_llm and self.client is None:
            self.client = LLMClient(provider=provider)

    def judge_bundle(self, bundle: LeakBundle) -> LeakBundle:
        if self.use_llm and self.client is not None:
            try:
                verdict = self._judge_with_llm(bundle)
                if verdict is not None:
                    bundle.verdict = self._calibrate_llm_verdict(bundle, verdict)
                    return bundle
            except Exception:
                pass
        return self.heuristic.judge_bundle(bundle)

    def judge_bundles(self, bundles: list[LeakBundle]) -> list[LeakBundle]:
        return [self.judge_bundle(bundle) for bundle in bundles]

    def _judge_with_llm(self, bundle: LeakBundle) -> VerdictResult | None:
        bundle_payload = bundle.model_dump(mode="json")
        response = self.client.chat(
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Judge this memory leak bundle and return JSON only.\n\n"
                        f"{json.dumps(bundle_payload, indent=2)}"
                    ),
                }
            ],
            system=LEAK_JUDGE_SYSTEM_PROMPT,
            max_tokens=2048,
            temperature=0.0,
        )
        data = self._extract_json_robust(response.text)
        if not data:
            return None
        return self._verdict_from_llm_data(bundle, data)

    def _extract_json_robust(self, text: str) -> dict[str, Any] | None:
        code_block_pattern = r"```(?:json)?\s*(\{[\s\S]*?\})\s*```"
        matches = re.findall(code_block_pattern, text)
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue

        def find_balanced_json(s: str) -> str | None:
            depth = 0
            start = None
            for i, char in enumerate(s):
                if char == "{":
                    if depth == 0:
                        start = i
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0 and start is not None:
                        return s[start : i + 1]
            return None

        json_str = find_balanced_json(text)
        if not json_str:
            return None

        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            fixed = re.sub(r",\s*}", "}", json_str)
            fixed = re.sub(r",\s*]", "]", fixed)
            try:
                return json.loads(fixed)
            except json.JSONDecodeError:
                return None

    def _verdict_from_llm_data(self, bundle: LeakBundle, data: dict[str, Any]) -> VerdictResult:
        verdict = InvestigationVerdict(data.get("verdict", InvestigationVerdict.INCONCLUSIVE.value))
        confidence = LeakConfidence(data.get("confidence", LeakConfidence.MEDIUM.value))

        suggestions = []
        for raw_suggestion in data.get("fix_suggestions", []):
            target_location = raw_suggestion.get("target_location")
            suggestions.append(
                LeakSuggestion(
                    summary=raw_suggestion.get("summary", "Investigate cleanup path"),
                    rationale=raw_suggestion.get("rationale", ""),
                    code_change_hint=raw_suggestion.get("code_change_hint"),
                    target_location=LeakLocation.model_validate(target_location) if target_location else None,
                )
            )

        return VerdictResult(
            candidate_id=bundle.candidate.candidate_id,
            verdict=verdict,
            confidence=confidence,
            why=data.get("why", "LLM judge produced no rationale."),
            supporting_evidence_ids=data.get("supporting_evidence_ids", []),
            missing_evidence=data.get("missing_evidence", []),
            human_explanation=data.get("human_explanation"),
            fix_suggestions=suggestions or self.heuristic._fix_suggestions(bundle),
        )

    def _calibrate_llm_verdict(
        self,
        bundle: LeakBundle,
        verdict: VerdictResult,
    ) -> VerdictResult:
        dynamic_ids = [
            idx for idx, evidence in enumerate(bundle.candidate.evidence) if evidence.tool_kind == ToolKind.DYNAMIC
        ]
        leakguard_ids = [
            idx for idx, evidence in enumerate(bundle.candidate.evidence) if evidence.tool == "memory.leakguard_run"
        ]
        path_ids = [
            idx for idx, evidence in enumerate(bundle.candidate.evidence) if evidence.tool == "memory.path_constraints"
        ]
        has_cleanup_gap = any(
            constraint.startswith("possible_unfreed_allocation:")
            or constraint.startswith("return_without_cleanup:")
            for constraint in bundle.candidate.path_constraints
        )
        calibration_notes: list[str] = []

        if dynamic_ids and verdict.verdict in {
            InvestigationVerdict.FALSE_POSITIVE,
            InvestigationVerdict.INCONCLUSIVE,
            InvestigationVerdict.LIKELY_LEAK,
        }:
            verdict.verdict = InvestigationVerdict.CONFIRMED_LEAK
            verdict.confidence = LeakConfidence.HIGH
            verdict.supporting_evidence_ids = sorted(set(verdict.supporting_evidence_ids + dynamic_ids))
            calibration_notes.append("dynamic evidence upgrades verdict to confirmed_leak")

        if not dynamic_ids and verdict.verdict == InvestigationVerdict.CONFIRMED_LEAK:
            verdict.verdict = InvestigationVerdict.LIKELY_LEAK
            verdict.confidence = self._max_confidence_without_dynamic(
                verdict.confidence,
                has_strong_static=bool(leakguard_ids and has_cleanup_gap),
            )
            if "dynamic confirmation" not in verdict.missing_evidence:
                verdict.missing_evidence.append("dynamic confirmation")
            calibration_notes.append("confirmed_leak requires dynamic evidence; downgraded to likely_leak")

        if not dynamic_ids and not leakguard_ids and not path_ids and verdict.confidence == LeakConfidence.HIGH:
            verdict.confidence = LeakConfidence.MEDIUM
            calibration_notes.append("high confidence requires corroborating static or dynamic evidence")

        if not verdict.human_explanation:
            verdict.human_explanation = self.heuristic._human_explanation(bundle, verdict.verdict, verdict.why)

        if calibration_notes:
            note_text = "; ".join(calibration_notes)
            verdict.why = f"{verdict.why} Calibration: {note_text}."
            bundle.orchestrator_notes.extend(
                note for note in (f"Judge calibration: {note}" for note in calibration_notes) if note not in bundle.orchestrator_notes
            )

        return verdict

    def _max_confidence_without_dynamic(
        self,
        confidence: LeakConfidence,
        has_strong_static: bool,
    ) -> LeakConfidence:
        if has_strong_static:
            return confidence
        if confidence == LeakConfidence.HIGH:
            return LeakConfidence.MEDIUM
        return confidence
