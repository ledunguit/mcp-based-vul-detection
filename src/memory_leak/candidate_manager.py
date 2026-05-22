"""Candidate clustering and deduplication for memory leak investigation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .shared_schema import (
    LeakBundle,
    LeakCandidate,
    LeakConfidence,
    LeakEvidence,
    LeakLocation,
    LeakSeverity,
    MissingCleanupPath,
    OwnershipSummary,
    ReportFinding,
    ToolKind,
)


class CandidateManager:
    """Collect, deduplicate, and enrich leak candidates from multiple analyzers."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self._bundles_by_signature: dict[str, LeakBundle] = {}

    def ingest_static_scan(
        self,
        scan_result: dict[str, Any],
        ast_result: dict[str, Any] | None = None,
        function_summary_result: dict[str, Any] | None = None,
        ownership_summary_result: dict[str, Any] | None = None,
        ownership_conventions_result: dict[str, Any] | None = None,
        call_graph_result: dict[str, Any] | None = None,
        path_constraints_result: dict[str, Any] | None = None,
        interprocedural_flow_result: dict[str, Any] | None = None,
        call_path_summary_result: dict[str, Any] | None = None,
    ) -> list[LeakBundle]:
        added: list[LeakBundle] = []
        file_path = scan_result.get("file_path")
        shared_evidence = [
            evidence
            for evidence in [
                self._build_ast_evidence(ast_result, file_path),
                self._build_function_summary_evidence(function_summary_result, file_path),
                self._build_ownership_summary_evidence(ownership_summary_result, file_path),
                self._build_ownership_conventions_evidence(ownership_conventions_result, file_path),
                self._build_call_graph_evidence(call_graph_result, file_path),
                self._build_path_constraints_evidence(path_constraints_result, file_path),
                self._build_interprocedural_flow_evidence(interprocedural_flow_result, file_path),
                self._build_call_path_summary_evidence(call_path_summary_result, file_path),
            ]
            if evidence is not None
        ]

        for raw_candidate in scan_result.get("candidates", []):
            bundle = self._build_static_bundle(
                raw_candidate,
                shared_evidence,
                function_summary_result=function_summary_result,
                ownership_summary_result=ownership_summary_result,
                path_constraints_result=path_constraints_result,
            )
            merged = self._upsert_bundle(bundle)
            if merged is bundle:
                added.append(bundle)
        return added

    def ingest_dynamic_bundles(self, bundles: list[dict[str, Any]]) -> list[LeakBundle]:
        added: list[LeakBundle] = []
        for raw_bundle in bundles:
            bundle = LeakBundle.model_validate(raw_bundle)
            merged = self._upsert_bundle(bundle)
            if merged is bundle:
                added.append(bundle)
        return added

    def list_bundles(self) -> list[LeakBundle]:
        return list(self._bundles_by_signature.values())

    def build_report(self) -> dict[str, Any]:
        bundles = self.list_bundles()
        evidence_count = sum(len(bundle.candidate.evidence) for bundle in bundles)
        serialized_bundles = [self._bundle_to_report_item(bundle) for bundle in bundles]
        serialized_findings = [self._bundle_to_finding_item(bundle) for bundle in bundles]
        return {
            "repo_path": self.repo_path,
            "bundle_count": len(bundles),
            "finding_count": len(serialized_findings),
            "candidate_count": len(bundles),
            "evidence_count": evidence_count,
            "findings": serialized_findings,
            "bundles": serialized_bundles,
        }

    def _bundle_to_report_item(self, bundle: LeakBundle) -> dict[str, Any]:
        item = bundle.model_dump(mode="json")
        item["provenance_history"] = [
            {
                "evidence_id": index,
                "tool": evidence.tool,
                "tool_kind": evidence.tool_kind.value,
                "kind": evidence.kind,
                "confidence": evidence.confidence.value,
                "severity": evidence.severity.value,
            }
            for index, evidence in enumerate(bundle.candidate.evidence)
        ]
        item["task_state"] = self._task_state(bundle)
        item["verdict_quality"] = self._verdict_quality(bundle)
        return item

    def _bundle_to_finding_item(self, bundle: LeakBundle) -> dict[str, Any]:
        candidate = bundle.candidate
        finding = ReportFinding(
            finding_id=self._finding_id(bundle),
            bundle_id=bundle.bundle_id,
            candidate_id=candidate.candidate_id,
            repo_path=bundle.repo_path or self.repo_path,
            candidate=candidate,
            verdict=bundle.verdict,
            related_candidates=list(bundle.related_candidates),
            orchestrator_notes=list(bundle.orchestrator_notes),
            provenance_history=[
                {
                    "evidence_id": index,
                    "tool": evidence.tool,
                    "tool_kind": evidence.tool_kind.value,
                    "kind": evidence.kind,
                    "confidence": evidence.confidence.value,
                    "severity": evidence.severity.value,
                }
                for index, evidence in enumerate(candidate.evidence)
            ],
            task_state=self._task_state(bundle),
            verdict_quality=self._verdict_quality(bundle),
        )
        return finding.model_dump(mode="json")

    def _finding_id(self, bundle: LeakBundle) -> str:
        candidate = bundle.candidate
        return candidate.signature or candidate.candidate_id or bundle.bundle_id

    def _verdict_quality(self, bundle: LeakBundle) -> dict[str, Any]:
        verdict = bundle.verdict
        evidence_count = len(bundle.candidate.evidence)
        if verdict is None:
            return {
                "has_verdict": False,
                "has_valid_supporting_evidence": False,
                "has_human_explanation": False,
                "has_fix_suggestions": False,
                "issues": ["missing verdict"],
            }

        issues = []
        valid_ids = [
            evidence_id
            for evidence_id in verdict.supporting_evidence_ids
            if isinstance(evidence_id, int) and 0 <= evidence_id < evidence_count
        ]
        if verdict.supporting_evidence_ids and len(valid_ids) != len(verdict.supporting_evidence_ids):
            issues.append("supporting evidence contains invalid ids")
        if not verdict.supporting_evidence_ids:
            issues.append("no supporting evidence ids")
        if not verdict.human_explanation:
            issues.append("missing human explanation")
        if not verdict.fix_suggestions:
            issues.append("missing fix suggestions")

        return {
            "has_verdict": True,
            "has_valid_supporting_evidence": bool(valid_ids),
            "has_human_explanation": bool(verdict.human_explanation),
            "has_fix_suggestions": bool(verdict.fix_suggestions),
            "supporting_evidence_id_count": len(valid_ids),
            "issues": issues,
        }

    def _task_state(self, bundle: LeakBundle) -> str:
        verdict = bundle.verdict.verdict.value if bundle.verdict else None
        has_dynamic = any(evidence.tool_kind == ToolKind.DYNAMIC for evidence in bundle.candidate.evidence)
        has_static_expansion = any(
            evidence.tool
            in {
                "memory.ast_scan",
                "memory.function_summary",
                "memory.call_graph",
                "memory.path_constraints",
                "memory.interprocedural_flow",
                "memory.call_path_summary",
                "memory.leakguard_run",
            }
            for evidence in bundle.candidate.evidence
        )

        if verdict in {"confirmed_leak", "false_positive"}:
            return "closed"
        if not has_static_expansion:
            return "needs_static_expansion"
        if not has_dynamic:
            return "needs_dynamic_validation"
        if bundle.verdict is None:
            return "ready_for_judge"
        return "closed"

    def _bundle_key(self, bundle: LeakBundle) -> str:
        return bundle.candidate.signature or bundle.bundle_id

    def _upsert_bundle(self, bundle: LeakBundle) -> LeakBundle:
        key = self._bundle_key(bundle)
        existing = self._bundles_by_signature.get(key) or self._find_similar_bundle(bundle)
        if existing is None:
            self._bundles_by_signature[key] = bundle
            return bundle

        self._merge_bundle(existing, bundle)
        return existing

    def _merge_bundle(self, existing: LeakBundle, incoming: LeakBundle) -> None:
        if incoming.bundle_id != existing.bundle_id and incoming.bundle_id not in existing.related_candidates:
            existing.related_candidates.append(incoming.bundle_id)

        if incoming.candidate.primary_tool != existing.candidate.primary_tool:
            note = f"Also reported by {incoming.candidate.primary_tool}"
            if note not in existing.orchestrator_notes:
                existing.orchestrator_notes.append(note)

        existing.candidate.tags = sorted(
            set(existing.candidate.tags).union(incoming.candidate.tags)
        )
        existing.candidate.path_constraints = sorted(
            set(existing.candidate.path_constraints).union(incoming.candidate.path_constraints)
        )
        existing.candidate.evidence.extend(incoming.candidate.evidence)
        existing.orchestrator_notes = sorted(
            set(existing.orchestrator_notes).union(incoming.orchestrator_notes)
        )

        if existing.candidate.line is None:
            existing.candidate.line = incoming.candidate.line
        if existing.candidate.function is None:
            existing.candidate.function = incoming.candidate.function
        if existing.candidate.allocation_site is None:
            existing.candidate.allocation_site = incoming.candidate.allocation_site
        if existing.candidate.missing_free_site is None:
            existing.candidate.missing_free_site = incoming.candidate.missing_free_site
        if self._tool_rank(incoming.candidate.primary_tool) > self._tool_rank(existing.candidate.primary_tool):
            existing.candidate.primary_tool = incoming.candidate.primary_tool
        if self._confidence_rank(incoming.candidate.confidence) > self._confidence_rank(existing.candidate.confidence):
            existing.candidate.confidence = incoming.candidate.confidence
        if self._severity_rank(incoming.candidate.severity) > self._severity_rank(existing.candidate.severity):
            existing.candidate.severity = incoming.candidate.severity

    def _build_static_bundle(
        self,
        raw_candidate: dict[str, Any],
        shared_evidence: list[LeakEvidence],
        function_summary_result: dict[str, Any] | None = None,
        ownership_summary_result: dict[str, Any] | None = None,
        path_constraints_result: dict[str, Any] | None = None,
    ) -> LeakBundle:
        candidate_id = self._static_candidate_id(raw_candidate)
        allocation_site = LeakLocation.model_validate(raw_candidate.get("allocation_site", {}))
        function_context = self._match_function_context(
            raw_candidate.get("line"),
            function_summary_result,
        )
        matched_constraints = self._match_path_constraints(
            raw_candidate.get("line"),
            path_constraints_result,
        )
        matched_ownership = self._match_ownership_summary(
            raw_candidate.get("line"),
            ownership_summary_result,
        )
        function_name = raw_candidate.get("function")
        if function_context and function_context.get("function_name"):
            function_name = function_context["function_name"]
        location = LeakLocation(
            file=raw_candidate.get("file"),
            line=raw_candidate.get("line"),
            function=function_name,
            code_snippet=allocation_site.code_snippet,
        )

        lexical_evidence = LeakEvidence(
            tool=raw_candidate.get("tool", "memory.candidate_scan"),
            tool_kind=ToolKind.STATIC,
            kind="candidate_discovery",
            message=raw_candidate.get("summary", "Potential memory leak candidate"),
            confidence=LeakConfidence.MEDIUM,
            severity=LeakSeverity.MEDIUM,
            location=location,
            allocation_site=allocation_site,
            raw_evidence=raw_candidate.get("raw_evidence", {}),
        )

        evidence = [lexical_evidence, *shared_evidence]

        candidate = LeakCandidate(
            candidate_id=candidate_id,
            signature=self._normalized_signature(raw_candidate),
            summary=self._candidate_summary(raw_candidate, function_name),
            primary_tool=raw_candidate.get("tool", "memory.candidate_scan"),
            confidence=LeakConfidence.MEDIUM,
            severity=LeakSeverity.MEDIUM,
            repo_path=self.repo_path,
            file=raw_candidate.get("file"),
            line=raw_candidate.get("line"),
            function=function_name,
            allocation_site=allocation_site,
            path_constraints=[
                f"early_return_line:{line}"
                for line in raw_candidate.get("early_return_lines", [])
            ]
            + matched_constraints,
            tags=["static", "candidate_scan"]
            + self._derive_static_tags(
                function_context,
                matched_constraints,
                candidate_line=raw_candidate.get("line"),
                ownership_summary=matched_ownership,
            ),
            allocation_records=matched_ownership.get("allocations", []) if matched_ownership else [],
            cleanup_records=matched_ownership.get("cleanups", []) if matched_ownership else [],
            ownership_transfers=matched_ownership.get("transfers", []) if matched_ownership else [],
            cleanup_obligations=matched_ownership.get("cleanup_obligations", []) if matched_ownership else [],
            missing_cleanup_paths=matched_ownership.get("missing_cleanup_paths", []) if matched_ownership else [],
            false_positive_hints=matched_ownership.get("false_positive_hints", []) if matched_ownership else [],
            evidence=evidence,
        )
        return LeakBundle(
            bundle_id=candidate_id,
            repo_path=self.repo_path,
            candidate=candidate,
            orchestrator_notes=["Discovered during static repository sweep"],
        )

    def _candidate_summary(self, raw_candidate: dict[str, Any], function_name: str | None) -> str:
        line = raw_candidate.get("line")
        file_path = str(raw_candidate.get("file") or raw_candidate.get("file_path") or "unknown")
        relative = self._relative_file_key(file_path)
        code = str(raw_candidate.get("allocation_site", {}).get("code_snippet") or "").strip()
        function_label = function_name or raw_candidate.get("function") or "unknown function"
        if code:
            return f"Potential leak candidate in {function_label} at {relative}:{line} from `{code}`"
        return f"Potential leak candidate in {function_label} at {relative}:{line}"

    def _static_candidate_id(self, raw_candidate: dict[str, Any]) -> str:
        file_path = str(raw_candidate.get("file") or raw_candidate.get("file_path") or "unknown")
        line = int(raw_candidate.get("line") or 0)
        kind = str(raw_candidate.get("allocation_site", {}).get("kind") or raw_candidate.get("kind") or "allocation")
        snippet = str(raw_candidate.get("allocation_site", {}).get("code_snippet") or "")
        relative = self._relative_file_key(file_path)
        digest = hashlib.sha1(f"{relative}:{line}:{kind}:{snippet}".encode("utf-8")).hexdigest()[:10]
        return f"static:{relative}:{line}:{kind}:{digest}"

    def _normalized_signature(self, raw_candidate: dict[str, Any]) -> str:
        file_path = str(raw_candidate.get("file") or raw_candidate.get("file_path") or "unknown")
        line = int(raw_candidate.get("line") or 0)
        kind = str(raw_candidate.get("allocation_site", {}).get("kind") or raw_candidate.get("kind") or "allocation")
        snippet = str(raw_candidate.get("allocation_site", {}).get("code_snippet") or "")
        relative = self._relative_file_key(file_path)
        snippet_hash = hashlib.sha1(snippet.encode("utf-8")).hexdigest()[:12]
        return f"{relative}:{line}:{kind}:{snippet_hash}"

    def _build_ast_evidence(
        self,
        ast_result: dict[str, Any] | None,
        file_path: str | None,
    ) -> LeakEvidence | None:
        if not ast_result or ast_result.get("parse_error"):
            return None

        allocation_calls = ast_result.get("allocation_calls", [])
        deallocation_calls = ast_result.get("deallocation_calls", [])
        function_name = ast_result.get("function_name")
        summary = (
            f"AST scan found {len(allocation_calls)} allocation calls and "
            f"{len(deallocation_calls)} deallocation calls"
        )

        return LeakEvidence(
            tool="memory.ast_scan",
            tool_kind=ToolKind.STATIC,
            kind="structural_context",
            message=summary,
            confidence=LeakConfidence.MEDIUM,
            severity=LeakSeverity.INFO,
            location=LeakLocation(file=file_path, function=function_name),
            raw_evidence={
                "function_name": function_name,
                "function_calls": ast_result.get("function_calls", []),
                "allocation_calls": allocation_calls,
                "deallocation_calls": deallocation_calls,
            },
        )

    def _build_function_summary_evidence(
        self,
        function_summary_result: dict[str, Any] | None,
        file_path: str | None,
    ) -> LeakEvidence | None:
        if not function_summary_result or function_summary_result.get("parse_error"):
            return None

        functions = function_summary_result.get("functions", [])
        risky_functions = [
            function["function_name"]
            for function in functions
            if function.get("has_allocation_without_local_free")
        ]
        return LeakEvidence(
            tool="memory.function_summary",
            tool_kind=ToolKind.STATIC,
            kind="function_summary",
            message=(
                f"Summarized {len(functions)} functions; "
                f"{len(risky_functions)} have allocation without local free"
            ),
            confidence=LeakConfidence.MEDIUM,
            severity=LeakSeverity.INFO,
            location=LeakLocation(file=file_path),
            raw_evidence={
                "function_count": function_summary_result.get("function_count", len(functions)),
                "risky_functions": risky_functions,
                "functions": functions,
            },
        )

    def _build_ownership_summary_evidence(
        self,
        ownership_summary_result: dict[str, Any] | None,
        file_path: str | None,
    ) -> LeakEvidence | None:
        if not ownership_summary_result or ownership_summary_result.get("parse_error"):
            return None

        functions = ownership_summary_result.get("functions", [])
        missing_paths = [
            path
            for function in functions
            for path in function.get("missing_cleanup_paths", [])
        ]
        cleanup_obligations = [
            obligation
            for function in functions
            for obligation in function.get("cleanup_obligations", [])
        ]
        ownership_summaries = [
            OwnershipSummary(
                function=function.get("function_name"),
                allocations=function.get("allocations", []),
                cleanups=function.get("cleanups", []),
                transfers=function.get("transfers", []),
                cleanup_obligations=function.get("cleanup_obligations", []),
                missing_cleanup_paths=function.get("missing_cleanup_paths", []),
                false_positive_hints=function.get("false_positive_hints", []),
            )
            for function in functions
        ]
        return LeakEvidence(
            tool="memory.ownership_summary",
            tool_kind=ToolKind.STATIC,
            kind="ownership_summary",
            message=(
                f"Ownership summary found {len(cleanup_obligations)} cleanup obligation(s) "
                f"and {len(missing_paths)} missing cleanup path(s)"
            ),
            confidence=LeakConfidence.HIGH if missing_paths else LeakConfidence.MEDIUM,
            severity=LeakSeverity.MEDIUM if missing_paths else LeakSeverity.INFO,
            location=LeakLocation(file=file_path),
            cleanup_obligations=cleanup_obligations,
            missing_cleanup_paths=[MissingCleanupPath.model_validate(path) for path in missing_paths],
            ownership_summaries=ownership_summaries,
            raw_evidence=ownership_summary_result,
        )

    def _build_ownership_conventions_evidence(
        self,
        ownership_conventions_result: dict[str, Any] | None,
        file_path: str | None,
    ) -> LeakEvidence | None:
        if not ownership_conventions_result or ownership_conventions_result.get("parse_error"):
            return None

        allocator_like = ownership_conventions_result.get("allocator_like", [])
        deallocator_like = ownership_conventions_result.get("deallocator_like", [])
        return LeakEvidence(
            tool="memory.ownership_conventions",
            tool_kind=ToolKind.STATIC,
            kind="ownership_conventions",
            message=(
                f"Ownership conventions detected {len(allocator_like)} allocator-like and "
                f"{len(deallocator_like)} deallocator-like function(s)"
            ),
            confidence=LeakConfidence.MEDIUM,
            severity=LeakSeverity.INFO,
            location=LeakLocation(file=file_path),
            raw_evidence=ownership_conventions_result,
        )

    def _build_call_graph_evidence(
        self,
        call_graph_result: dict[str, Any] | None,
        file_path: str | None,
    ) -> LeakEvidence | None:
        if not call_graph_result or call_graph_result.get("parse_error"):
            return None

        edges = call_graph_result.get("edges", [])
        internal_edges = [edge for edge in edges if edge.get("kind") == "internal"]
        return LeakEvidence(
            tool="memory.call_graph",
            tool_kind=ToolKind.STATIC,
            kind="call_graph",
            message=(
                f"Call graph captured {len(edges)} call edges; "
                f"{len(internal_edges)} remain inside the current file"
            ),
            confidence=LeakConfidence.MEDIUM,
            severity=LeakSeverity.INFO,
            location=LeakLocation(file=file_path),
            raw_evidence=call_graph_result,
        )

    def _build_path_constraints_evidence(
        self,
        path_constraints_result: dict[str, Any] | None,
        file_path: str | None,
    ) -> LeakEvidence | None:
        if not path_constraints_result or path_constraints_result.get("parse_error"):
            return None

        functions = path_constraints_result.get("functions", [])
        return LeakEvidence(
            tool="memory.path_constraints",
            tool_kind=ToolKind.STATIC,
            kind="path_constraints",
            message=f"Path constraint analysis extracted hints for {len(functions)} functions",
            confidence=LeakConfidence.MEDIUM,
            severity=LeakSeverity.INFO,
            location=LeakLocation(file=file_path),
            raw_evidence=path_constraints_result,
        )

    def _build_interprocedural_flow_evidence(
        self,
        interprocedural_flow_result: dict[str, Any] | None,
        file_path: str | None,
    ) -> LeakEvidence | None:
        if not interprocedural_flow_result or interprocedural_flow_result.get("parse_error"):
            return None

        risky_functions = [
            function["function_name"]
            for function in interprocedural_flow_result.get("functions", [])
            if function.get("risk") and function.get("risk") != "none"
        ]
        return LeakEvidence(
            tool="memory.interprocedural_flow",
            tool_kind=ToolKind.STATIC,
            kind="interprocedural_flow",
            message=(
                f"Interprocedural flow extracted {interprocedural_flow_result.get('edge_count', 0)} edges; "
                f"{len(risky_functions)} functions need ownership review"
            ),
            confidence=LeakConfidence.MEDIUM,
            severity=LeakSeverity.INFO,
            location=LeakLocation(file=file_path),
            raw_evidence=interprocedural_flow_result,
        )

    def _build_call_path_summary_evidence(
        self,
        call_path_summary_result: dict[str, Any] | None,
        file_path: str | None,
    ) -> LeakEvidence | None:
        if not call_path_summary_result or call_path_summary_result.get("parse_error"):
            return None

        paths = call_path_summary_result.get("paths", [])
        return LeakEvidence(
            tool="memory.call_path_summary",
            tool_kind=ToolKind.STATIC,
            kind="call_path_summary",
            message=f"Call-path summary found {len(paths)} allocation/cleanup terminal paths",
            confidence=LeakConfidence.MEDIUM,
            severity=LeakSeverity.INFO,
            location=LeakLocation(file=file_path),
            raw_evidence=call_path_summary_result,
        )

    def _match_function_context(
        self,
        line: int | None,
        function_summary_result: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        if line is None or not function_summary_result:
            return None
        for function in function_summary_result.get("functions", []):
            start_line = function.get("start_line")
            end_line = function.get("end_line")
            if start_line is None or end_line is None:
                continue
            if start_line <= line <= end_line:
                return function
        return None

    def _match_path_constraints(
        self,
        line: int | None,
        path_constraints_result: dict[str, Any] | None,
    ) -> list[str]:
        if line is None or not path_constraints_result:
            return []

        matched = []
        for function in path_constraints_result.get("functions", []):
            start_line = function.get("start_line")
            end_line = function.get("end_line")
            if start_line is None or end_line is None or not (start_line <= line <= end_line):
                continue
            matched.extend(function.get("constraints", []))
        return matched

    def _match_ownership_summary(
        self,
        line: int | None,
        ownership_summary_result: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        if line is None or not ownership_summary_result:
            return None
        for function in ownership_summary_result.get("functions", []):
            start_line = function.get("start_line")
            end_line = function.get("end_line")
            if start_line is None or end_line is None:
                continue
            if start_line <= line <= end_line:
                return function
        return None

    def _derive_static_tags(
        self,
        function_context: dict[str, Any] | None,
        matched_constraints: list[str],
        candidate_line: int | None = None,
        ownership_summary: dict[str, Any] | None = None,
    ) -> list[str]:
        tags = []
        if function_context and function_context.get("has_allocation_without_local_free"):
            tags.append("allocation_without_local_free")
        if function_context and candidate_line is not None and any(
            item.get("line") == candidate_line
            for item in function_context.get("nonlocal_allocation_variables", [])
        ):
            tags.append("global_allocation_without_local_free")
        if matched_constraints:
            tags.append("path_constraints")
        if ownership_summary and ownership_summary.get("cleanup_obligations"):
            tags.append("cleanup_obligation")
        if ownership_summary and ownership_summary.get("missing_cleanup_paths"):
            tags.append("missing_cleanup_path")
        if ownership_summary and ownership_summary.get("false_positive_hints"):
            tags.append("ownership_false_positive_hints")
        return tags

    def _find_similar_bundle(self, incoming: LeakBundle) -> LeakBundle | None:
        for existing in self._bundles_by_signature.values():
            if self._bundles_match(existing, incoming):
                return existing
        return None

    def _bundles_match(self, left: LeakBundle, right: LeakBundle) -> bool:
        left_file = self._bundle_file(left)
        right_file = self._bundle_file(right)
        if not self._same_file_identity(left_file, right_file):
            return False

        if left.candidate.signature and left.candidate.signature == right.candidate.signature:
            return True

        left_line = self._bundle_identity_line(left)
        right_line = self._bundle_identity_line(right)
        if left_line is not None and right_line is not None:
            if left_line == right_line:
                return True
            line_delta = abs(left_line - right_line)
            if line_delta <= 1 and self._same_function_identity(left, right) and self._same_allocation_snippet(left, right):
                return True
            return False

        if self._same_function_identity(left, right) and self._same_allocation_snippet(left, right):
            return True
        return False

    def _bundle_file(self, bundle: LeakBundle) -> str | None:
        allocation_site = bundle.candidate.allocation_site
        if allocation_site and allocation_site.file:
            return allocation_site.file
        return bundle.candidate.file

    def _bundle_identity_line(self, bundle: LeakBundle) -> int | None:
        allocation_site = bundle.candidate.allocation_site
        if allocation_site and allocation_site.line is not None:
            return allocation_site.line
        return bundle.candidate.line

    def _same_file_identity(self, left_file: str | None, right_file: str | None) -> bool:
        if not left_file or not right_file:
            return False

        left_path = Path(left_file)
        right_path = Path(right_file)
        if str(left_path) == str(right_path):
            return True

        left_relative = self._relative_to_repo(left_path)
        right_relative = self._relative_to_repo(right_path)
        if left_relative and right_relative and left_relative == right_relative:
            return True

        left_parts = left_path.parts
        right_parts = right_path.parts
        if len(left_parts) > 1 and len(right_parts) > 1:
            return left_path.name == right_path.name and left_parts[-2:] == right_parts[-2:]

        return left_path.name == right_path.name

    def _same_function_identity(self, left: LeakBundle, right: LeakBundle) -> bool:
        left_function = (left.candidate.function or "").strip()
        right_function = (right.candidate.function or "").strip()
        return bool(left_function and right_function and left_function == right_function)

    def _same_allocation_snippet(self, left: LeakBundle, right: LeakBundle) -> bool:
        left_snippet = (left.candidate.allocation_site.code_snippet if left.candidate.allocation_site else "") or ""
        right_snippet = (right.candidate.allocation_site.code_snippet if right.candidate.allocation_site else "") or ""
        return bool(left_snippet and right_snippet and left_snippet.strip() == right_snippet.strip())

    def _relative_to_repo(self, path: Path) -> Path | None:
        repo_path = Path(self.repo_path)
        try:
            return path.resolve().relative_to(repo_path.resolve())
        except (OSError, ValueError):
            return None

    def _relative_file_key(self, file_path: str) -> str:
        relative = self._relative_to_repo(Path(file_path))
        if relative is not None:
            return relative.as_posix()
        return Path(file_path).as_posix().lstrip("/")

    def _confidence_rank(self, confidence: LeakConfidence) -> int:
        order = {
            LeakConfidence.LOW: 0,
            LeakConfidence.MEDIUM: 1,
            LeakConfidence.HIGH: 2,
        }
        return order[confidence]

    def _severity_rank(self, severity: LeakSeverity) -> int:
        order = {
            LeakSeverity.INFO: 0,
            LeakSeverity.LOW: 1,
            LeakSeverity.MEDIUM: 2,
            LeakSeverity.HIGH: 3,
            LeakSeverity.CRITICAL: 4,
        }
        return order[severity]

    def _tool_rank(self, tool_name: str) -> int:
        if tool_name.startswith("valgrind.") or tool_name.startswith("asan.") or tool_name.startswith("lsan."):
            return 3
        if tool_name == "memory.leakguard_run":
            return 2
        if tool_name.startswith("memory.") or tool_name.startswith("repo."):
            return 1
        return 0
