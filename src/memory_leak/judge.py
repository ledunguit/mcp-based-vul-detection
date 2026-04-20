"""Leak-centric verdict generation for merged investigation bundles."""

from __future__ import annotations

import json
import os
import re
from difflib import unified_diff
from pathlib import Path
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

LEAK_JUDGE_BATCH_SYSTEM_PROMPT = """You are a memory leak investigation judge.

You receive a list of normalized memory leak bundles that already merge evidence
from static and dynamic analyzers.

For each bundle:
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
- Return one result for every provided bundle_id

Return JSON only with this structure:
{
  "results": [
    {
      "bundle_id": "bundle-1",
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
            fix_suggestions=self._enrich_suggestions(bundle, self._fix_suggestions(bundle)),
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
        cleanup_target = self._cleanup_target_location(candidate, allocation_site)

        if any(constraint.startswith("return_without_cleanup:") for constraint in candidate.path_constraints):
            suggestions.append(
                LeakSuggestion(
                    summary="Add cleanup before early return",
                    rationale="A return path appears to bypass cleanup after allocation.",
                    code_change_hint="Ensure the allocated object is freed before the branch returns.",
                    target_location=cleanup_target,
                )
            )

        if "allocation_without_local_free" in candidate.tags:
            suggestions.append(
                LeakSuggestion(
                    summary="Clarify ownership or free before leaving the function",
                    rationale="The function allocates memory but no local deallocation is visible.",
                    code_change_hint="Either free the allocation locally or document/return ownership explicitly.",
                    target_location=cleanup_target,
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

    def _enrich_suggestions(self, bundle: LeakBundle, suggestions: list[LeakSuggestion]) -> list[LeakSuggestion]:
        enriched = []
        for suggestion in suggestions:
            preview = self._build_suggestion_preview(bundle, suggestion)
            if preview is None:
                enriched.append(suggestion)
                continue
            enriched.append(
                suggestion.model_copy(
                    update={
                        "target_location": preview["target_location"],
                        "before_snippet": preview["before_snippet"],
                        "after_snippet": preview["after_snippet"],
                        "unified_diff": preview["unified_diff"],
                        "before_start_line": preview["before_start_line"],
                        "after_start_line": preview["after_start_line"],
                    }
                )
            )
        return enriched

    def _build_suggestion_preview(self, bundle: LeakBundle, suggestion: LeakSuggestion) -> dict[str, Any] | None:
        candidate = bundle.candidate
        target_location = self._resolve_suggestion_target(bundle, suggestion)
        if not target_location or not target_location.file or target_location.line is None:
            return None

        file_path = Path(target_location.file)
        if not file_path.exists() or not file_path.is_file():
            return None

        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return None

        line_index = target_location.line - 1
        if line_index < 0 or line_index >= len(lines):
            return None

        original_line = lines[line_index]
        variable_name = self._guess_allocation_variable(candidate)
        if variable_name is None:
            return None

        indent = re.match(r"\s*", original_line).group(0)
        injected_cleanup = f"{indent}free({variable_name});"
        before_start_index = max(0, line_index - 1)
        before_end_index = min(len(lines), line_index + 2)
        before_lines = lines[before_start_index:before_end_index]
        relative_line_index = line_index - before_start_index

        if self._targets_cleanup_site(suggestion):
            after_lines = before_lines[:relative_line_index] + [injected_cleanup] + before_lines[relative_line_index:]
        else:
            return None

        diff_text = "\n".join(
            unified_diff(
                [f"{line}\n" for line in before_lines],
                [f"{line}\n" for line in after_lines],
                fromfile=str(file_path),
                tofile=str(file_path),
                lineterm="",
            )
        )
        return {
            "target_location": target_location.model_copy(update={"code_snippet": original_line}),
            "before_snippet": "\n".join(before_lines),
            "after_snippet": "\n".join(after_lines),
            "unified_diff": diff_text,
            "before_start_line": before_start_index + 1,
            "after_start_line": before_start_index + 1,
        }

    def _resolve_suggestion_target(self, bundle: LeakBundle, suggestion: LeakSuggestion) -> LeakLocation | None:
        candidate = bundle.candidate
        if suggestion.target_location and suggestion.target_location.file and suggestion.target_location.line is not None:
            if self._targets_cleanup_site(suggestion):
                allocation_site = candidate.allocation_site or LeakLocation(file=candidate.file, line=candidate.line)
                candidate_target = self._cleanup_target_location(candidate, allocation_site)
                if candidate_target and (
                    self._is_allocation_site(candidate, suggestion.target_location)
                    or suggestion.target_location.file != candidate.file
                    or not Path(suggestion.target_location.file).exists()
                ):
                    return candidate_target
            return suggestion.target_location
        if candidate.missing_free_site and candidate.missing_free_site.file and candidate.missing_free_site.line is not None:
            return candidate.missing_free_site
        if candidate.file and candidate.line is not None:
            return LeakLocation(file=candidate.file, line=self._find_return_line(candidate.file, candidate.line) or candidate.line)
        return candidate.allocation_site

    def _cleanup_target_location(self, candidate: Any, fallback: LeakLocation | None) -> LeakLocation | None:
        if candidate.missing_free_site and candidate.missing_free_site.file and candidate.missing_free_site.line is not None:
            return candidate.missing_free_site
        if candidate.file and candidate.line is not None:
            return LeakLocation(
                file=candidate.file,
                line=self._find_return_line(candidate.file, candidate.line) or candidate.line,
                column=(candidate.missing_free_site.column if candidate.missing_free_site else None),
                function=candidate.function,
            )
        return fallback

    def _targets_cleanup_site(self, suggestion: LeakSuggestion) -> bool:
        text = " ".join(
            part.lower()
            for part in [suggestion.summary, suggestion.rationale, suggestion.code_change_hint]
            if part
        )
        return any(token in text for token in ["return", "cleanup", "free before leaving", "error branch", "branch"])

    def _is_allocation_site(self, candidate: Any, location: LeakLocation) -> bool:
        allocation_site = candidate.allocation_site
        if not allocation_site:
            return False
        return (
            allocation_site.file == location.file
            and allocation_site.line == location.line
            and allocation_site.column == location.column
        )

    def _find_return_line(self, file_path: str, start_line: int) -> int | None:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return None
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return None
        for index, line in enumerate(lines[start_line - 1 : start_line + 40], start=start_line):
            if re.search(r"\breturn\b", line):
                return index
        return None

    def _guess_allocation_variable(self, candidate: Any) -> str | None:
        for constraint in candidate.path_constraints:
            match = re.match(r"(?:possible_unfreed_allocation|return_without_cleanup):([A-Za-z_]\w*)", constraint)
            if match:
                return match.group(1)

        if candidate.allocation_site and candidate.allocation_site.code_snippet:
            match = re.search(
                r"([A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc|strdup)\b",
                candidate.allocation_site.code_snippet,
            )
            if match:
                return match.group(1)

        if candidate.summary:
            match = re.search(r"'([A-Za-z_]\w*)'", candidate.summary)
            if match:
                return match.group(1)
        return None


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
        self._llm_success_count = 0
        self._heuristic_fallback_count = 0
        self._last_llm_error: str | None = None
        self._llm_batch_calls = 0
        self._llm_bundle_calls = 0
        self._batch_size = max(1, int(os.getenv("MEMORY_LEAK_JUDGE_BATCH_SIZE", "8")))
        scope = (os.getenv("MEMORY_LEAK_JUDGE_SCOPE", "selective") or "selective").strip().lower()
        self._llm_scope = scope if scope in {"all", "selective"} else "selective"
        self._llm_skipped_count = 0

        if self.use_llm and self.client is None:
            self.client = LLMClient(provider=provider)

    def judge_bundle(self, bundle: LeakBundle) -> LeakBundle:
        heuristic_bundle, should_use_llm, route_reason = self._route_bundle(bundle)
        if not should_use_llm:
            self._llm_skipped_count += 1
            heuristic_bundle.orchestrator_notes.extend(
                note for note in [f"Judge routing: {route_reason}"] if note not in heuristic_bundle.orchestrator_notes
            )
            return heuristic_bundle
        if self.use_llm and self.client is not None:
            try:
                verdict = self._judge_with_llm(bundle)
                if verdict is not None:
                    self._llm_success_count += 1
                    bundle.verdict = self._calibrate_llm_verdict(bundle, verdict)
                    bundle.verdict.fix_suggestions = self.heuristic._enrich_suggestions(bundle, bundle.verdict.fix_suggestions)
                    return bundle
            except Exception as exc:
                self._last_llm_error = str(exc)
                pass
            self._heuristic_fallback_count += 1
        return self.heuristic.judge_bundle(bundle)

    def judge_bundles(self, bundles: list[LeakBundle]) -> list[LeakBundle]:
        if not bundles:
            return []
        if not self.use_llm or self.client is None:
            return [self.heuristic.judge_bundle(bundle) for bundle in bundles]

        pending: list[LeakBundle] = []
        for bundle in bundles:
            heuristic_bundle, should_use_llm, route_reason = self._route_bundle(bundle)
            if should_use_llm:
                pending.append(bundle)
                continue
            self._llm_skipped_count += 1
            heuristic_bundle.orchestrator_notes.extend(
                note for note in [f"Judge routing: {route_reason}"] if note not in heuristic_bundle.orchestrator_notes
            )

        for start in range(0, len(pending), self._batch_size):
            chunk = pending[start : start + self._batch_size]
            if len(chunk) == 1:
                self.judge_bundle(chunk[0])
                continue
            try:
                verdicts = self._judge_batch_with_llm(chunk)
                if verdicts is None:
                    raise ValueError("LLM batch response did not include valid results.")
                self._llm_batch_calls += 1
                for bundle in chunk:
                    verdict = verdicts.get(bundle.bundle_id)
                    if verdict is None:
                        self._heuristic_fallback_count += 1
                        self.heuristic.judge_bundle(bundle)
                        continue
                    self._llm_success_count += 1
                    bundle.verdict = self._calibrate_llm_verdict(bundle, verdict)
                    bundle.verdict.fix_suggestions = self.heuristic._enrich_suggestions(bundle, bundle.verdict.fix_suggestions)
            except Exception as exc:
                self._last_llm_error = str(exc)
                for bundle in chunk:
                    self._heuristic_fallback_count += 1
                    self.heuristic.judge_bundle(bundle)
        return bundles

    def summary(self) -> dict[str, Any]:
        requested_mode = "llm" if self.use_llm else "heuristic"
        effective_mode = "llm" if self._llm_success_count > 0 else "heuristic"
        provider = None
        if self.use_llm:
            provider = self.provider or os.getenv("LLM_PROVIDER", "claude")
        return {
            "requested_mode": requested_mode,
            "effective_mode": effective_mode,
            "provider": provider,
            "llm_used": self._llm_success_count > 0,
            "llm_success_count": self._llm_success_count,
            "heuristic_fallback_count": self._heuristic_fallback_count,
            "last_llm_error": self._last_llm_error,
            "llm_batch_calls": self._llm_batch_calls,
            "llm_bundle_calls": self._llm_bundle_calls,
            "judge_batch_size": self._batch_size,
            "judge_scope": self._llm_scope,
            "llm_skipped_count": self._llm_skipped_count,
        }

    def _judge_with_llm(self, bundle: LeakBundle) -> VerdictResult | None:
        self._llm_bundle_calls += 1
        bundle_payload = self._bundle_prompt_payload(bundle)
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

    def _judge_batch_with_llm(self, bundles: list[LeakBundle]) -> dict[str, VerdictResult] | None:
        payload = {"bundles": [self._bundle_prompt_payload(bundle) for bundle in bundles]}
        response = self.client.chat(
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Judge these memory leak bundles and return JSON only.\n\n"
                        f"{json.dumps(payload, indent=2)}"
                    ),
                }
            ],
            system=LEAK_JUDGE_BATCH_SYSTEM_PROMPT,
            max_tokens=4096,
            temperature=0.0,
        )
        data = self._extract_json_robust(response.text)
        if not data:
            return None

        bundles_by_id = {bundle.bundle_id: bundle for bundle in bundles}
        verdicts: dict[str, VerdictResult] = {}
        for item in data.get("results", []):
            bundle_id = item.get("bundle_id")
            bundle = bundles_by_id.get(bundle_id)
            if bundle is None or not bundle_id:
                continue
            verdicts[bundle_id] = self._verdict_from_llm_data(bundle, item)
        return verdicts or None

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
                    before_snippet=raw_suggestion.get("before_snippet"),
                    after_snippet=raw_suggestion.get("after_snippet"),
                    unified_diff=raw_suggestion.get("unified_diff"),
                    before_start_line=raw_suggestion.get("before_start_line"),
                    after_start_line=raw_suggestion.get("after_start_line"),
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

    def _route_bundle(self, bundle: LeakBundle) -> tuple[LeakBundle, bool, str]:
        heuristic_bundle = self.heuristic.judge_bundle(bundle)
        if not self.use_llm or self.client is None:
            return heuristic_bundle, False, "LLM judge disabled"
        if self._llm_scope == "all":
            return heuristic_bundle, True, "LLM scope is set to all bundles"

        verdict = heuristic_bundle.verdict
        if verdict is None:
            return heuristic_bundle, True, "No heuristic verdict available"

        dynamic_count = sum(1 for evidence in bundle.candidate.evidence if evidence.tool_kind == ToolKind.DYNAMIC)
        leakguard_count = sum(1 for evidence in bundle.candidate.evidence if evidence.tool == "memory.leakguard_run")
        path_count = sum(1 for evidence in bundle.candidate.evidence if evidence.tool == "memory.path_constraints")
        has_cleanup_gap = any(
            constraint.startswith("possible_unfreed_allocation:")
            or constraint.startswith("return_without_cleanup:")
            for constraint in bundle.candidate.path_constraints
        )
        evidence_count = len(bundle.candidate.evidence)

        if dynamic_count:
            return heuristic_bundle, False, "dynamic evidence already provides strong confirmation"
        if leakguard_count and has_cleanup_gap and verdict.confidence == LeakConfidence.HIGH:
            return heuristic_bundle, False, "strong static corroboration already available"
        if evidence_count <= 1:
            return heuristic_bundle, False, "lexical evidence only; LLM would not add grounded support"
        if verdict.verdict in {InvestigationVerdict.CONFIRMED_LEAK, InvestigationVerdict.FALSE_POSITIVE}:
            return heuristic_bundle, False, "heuristic verdict is already decisive"
        if verdict.confidence == LeakConfidence.HIGH and verdict.verdict == InvestigationVerdict.LIKELY_LEAK:
            return heuristic_bundle, False, "high-confidence likely leak does not need LLM escalation"
        if verdict.verdict == InvestigationVerdict.INCONCLUSIVE and path_count == 0 and leakguard_count == 0:
            return heuristic_bundle, False, "insufficient corroborating evidence for grounded LLM escalation"
        return heuristic_bundle, True, "bundle remains ambiguous after heuristic triage"

    def _bundle_prompt_payload(self, bundle: LeakBundle) -> dict[str, Any]:
        candidate = bundle.candidate
        return {
            "bundle_id": bundle.bundle_id,
            "candidate": {
                "candidate_id": candidate.candidate_id,
                "signature": candidate.signature,
                "summary": candidate.summary,
                "primary_tool": candidate.primary_tool,
                "confidence": candidate.confidence.value,
                "severity": candidate.severity.value,
                "file": candidate.file,
                "line": candidate.line,
                "function": candidate.function,
                "allocation_site": self._location_payload(candidate.allocation_site),
                "missing_free_site": self._location_payload(candidate.missing_free_site),
                "path_constraints": candidate.path_constraints,
                "tags": candidate.tags,
                "evidence": [self._evidence_prompt_payload(index, evidence) for index, evidence in enumerate(candidate.evidence)],
            },
            "related_candidates": bundle.related_candidates,
            "orchestrator_notes": bundle.orchestrator_notes,
        }

    def _evidence_prompt_payload(self, evidence_id: int, evidence: Any) -> dict[str, Any]:
        payload = {
            "evidence_id": evidence_id,
            "tool": evidence.tool,
            "tool_kind": evidence.tool_kind.value,
            "kind": evidence.kind,
            "message": evidence.message,
            "confidence": evidence.confidence.value,
            "severity": evidence.severity.value,
            "location": self._location_payload(evidence.location),
            "allocation_site": self._location_payload(evidence.allocation_site),
            "missing_free_site": self._location_payload(evidence.missing_free_site),
        }
        if evidence.call_path is not None:
            payload["call_path"] = {
                "kind": evidence.call_path.kind,
                "constraints": evidence.call_path.constraints[:6],
                "notes": evidence.call_path.notes[:4],
                "frames": [self._location_payload(frame) for frame in evidence.call_path.frames[:6]],
            }
        if evidence.stack:
            payload["stack"] = [self._location_payload(frame) for frame in evidence.stack[:6]]
        if evidence.artifacts:
            payload["artifacts"] = [artifact.name for artifact in evidence.artifacts[:4]]
        if evidence.raw_evidence:
            payload["raw_evidence_keys"] = sorted(evidence.raw_evidence.keys())[:8]
        return payload

    def _location_payload(self, location: LeakLocation | None) -> dict[str, Any] | None:
        if location is None:
            return None
        return {
            "file": location.file,
            "line": location.line,
            "column": location.column,
            "function": location.function,
            "code_snippet": location.code_snippet,
        }

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
