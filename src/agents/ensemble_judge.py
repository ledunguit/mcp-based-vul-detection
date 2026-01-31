"""
Ensemble Judge - Phase 2.2

Multi-perspective verdict validation to reduce single-point-of-failure
in the Judge agent. Uses multiple judges with different perspectives
and aggregates their verdicts.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from src.schemas import (
    Verdict,
    OrchestratorHypothesis,
    JudgeVerdict,
    JudgeValidation,
    ValidationCheck,
)
from src.config import MAX_TOKENS, TEMPERATURE
from src.llm_client import LLMClient
import json


class JudgePerspective(Enum):
    """Different perspectives for judging."""
    SECURITY_EXPERT = "security_expert"
    CODE_QUALITY = "code_quality"
    FALSE_POSITIVE_FILTER = "false_positive_filter"
    CONSERVATIVE = "conservative"


# Perspective-specific system prompts
PERSPECTIVE_PROMPTS = {
    JudgePerspective.SECURITY_EXPERT: """You are a SECURITY EXPERT judge focusing on exploit potential.

Your perspective: Prioritize identifying real security risks. Consider:
- Attack feasibility and exploitability
- Real-world attack scenarios
- Impact severity if exploited

You should be THOROUGH in identifying genuine vulnerabilities but also recognize when code is genuinely safe.
""",
    
    JudgePerspective.CODE_QUALITY: """You are a CODE QUALITY EXPERT judge focusing on best practices.

Your perspective: Evaluate code against security coding standards. Consider:
- Industry best practices (CERT C, SEI guidelines)
- Defensive programming patterns
- Code maintainability and clarity

You should flag code that violates best practices even if not immediately exploitable.
""",
    
    JudgePerspective.FALSE_POSITIVE_FILTER: """You are a SKEPTICAL JUDGE focused on reducing false positives.

Your perspective: Be skeptical of vulnerability claims. Consider:
- Is the evidence truly conclusive?
- Are there mitigating factors not considered?
- Could this be a false alarm?

You should push back on weak evidence and require strong proof for VULNERABLE verdicts.
""",
    
    JudgePerspective.CONSERVATIVE: """You are a CONSERVATIVE JUDGE with balanced perspective.

Your perspective: Apply standard security judgment. Consider:
- Balance between false positives and false negatives
- Standard vulnerability definitions
- Typical security assessment criteria

You should apply consistent, well-calibrated judgment without bias toward either direction.
""",
}


@dataclass
class PerspectiveVerdict:
    """Verdict from a single perspective."""
    perspective: JudgePerspective
    verdict: Verdict
    confidence: float
    reasoning: str
    validation: Optional[JudgeValidation] = None


@dataclass
class EnsembleVerdict:
    """Aggregated verdict from ensemble of judges."""
    final_verdict: Verdict
    final_confidence: float
    
    # Individual verdicts
    perspective_verdicts: list[PerspectiveVerdict] = field(default_factory=list)
    
    # Voting statistics
    vote_counts: dict[str, int] = field(default_factory=dict)
    agreement_ratio: float = 0.0
    
    # Aggregated reasoning
    combined_reasoning: str = ""
    
    # Conflict information
    has_conflict: bool = False
    conflict_details: str = ""
    
    def to_judge_verdict(self) -> JudgeVerdict:
        """Convert to standard JudgeVerdict format."""
        # Use the validation from the perspective closest to final verdict
        validation = None
        for pv in self.perspective_verdicts:
            if pv.verdict == self.final_verdict and pv.validation:
                validation = pv.validation
                break
        
        if validation is None:
            validation = JudgeValidation(
                dangerous_sink=ValidationCheck(present=False, citation="Ensemble aggregation", confidence="medium"),
                data_flow=ValidationCheck(present=False, citation="Ensemble aggregation", confidence="medium"),
                missing_checks=ValidationCheck(present=False, citation="Ensemble aggregation", confidence="medium"),
            )
        
        return JudgeVerdict(
            verdict=self.final_verdict,
            validation=validation,
            final_reasoning=self.combined_reasoning,
            confidence=self.final_confidence,
            evidence_quality="strong" if self.agreement_ratio > 0.8 else "medium",
            hallucination_flags=[],
        )


class EnsembleJudge:
    """
    Multi-perspective verdict validation.
    
    Uses multiple judges with different perspectives and aggregates
    their verdicts using weighted voting.
    
    Example:
        ensemble = EnsembleJudge()
        result = ensemble.validate(hypothesis, tool_outputs, source_code)
        
        # Or use specific perspectives
        ensemble = EnsembleJudge(perspectives=[
            JudgePerspective.SECURITY_EXPERT,
            JudgePerspective.FALSE_POSITIVE_FILTER,
        ])
    """
    
    # Default weights for each perspective
    DEFAULT_WEIGHTS = {
        JudgePerspective.SECURITY_EXPERT: 1.0,
        JudgePerspective.CODE_QUALITY: 0.8,
        JudgePerspective.FALSE_POSITIVE_FILTER: 1.0,
        JudgePerspective.CONSERVATIVE: 0.9,
    }
    
    def __init__(
        self,
        perspectives: list[JudgePerspective] = None,
        weights: dict[JudgePerspective, float] = None,
        provider: str = None,
    ):
        """
        Initialize ensemble judge.
        
        Args:
            perspectives: List of perspectives to use (default: all)
            weights: Custom weights for perspectives
            provider: LLM provider to use
        """
        self.perspectives = perspectives or [
            JudgePerspective.SECURITY_EXPERT,
            JudgePerspective.FALSE_POSITIVE_FILTER,
            JudgePerspective.CONSERVATIVE,
        ]
        self.weights = weights or self.DEFAULT_WEIGHTS
        self.client = LLMClient(provider=provider)
    
    def validate(
        self,
        hypothesis: OrchestratorHypothesis,
        tool_outputs: dict,
        source_code: str,
    ) -> EnsembleVerdict:
        """
        Validate hypothesis using ensemble of judges.
        
        Args:
            hypothesis: The orchestrator's hypothesis
            tool_outputs: Raw outputs from MCP tools
            source_code: The original source code
        
        Returns:
            EnsembleVerdict with aggregated result
        """
        perspective_verdicts = []
        
        # Get verdict from each perspective
        for perspective in self.perspectives:
            verdict = self._get_perspective_verdict(
                perspective,
                hypothesis,
                tool_outputs,
                source_code,
            )
            perspective_verdicts.append(verdict)
        
        # Aggregate verdicts
        return self._aggregate_verdicts(perspective_verdicts)
    
    def _get_perspective_verdict(
        self,
        perspective: JudgePerspective,
        hypothesis: OrchestratorHypothesis,
        tool_outputs: dict,
        source_code: str,
    ) -> PerspectiveVerdict:
        """Get verdict from a single perspective."""
        perspective_prompt = PERSPECTIVE_PROMPTS.get(perspective, "")
        
        base_prompt = self._get_base_judge_prompt()
        full_system_prompt = f"{base_prompt}\n\n{perspective_prompt}"
        
        evidence_text = self._format_evidence(tool_outputs)
        
        messages = [{
            "role": "user",
            "content": f"""Validate the following security hypothesis against the provided evidence.

HYPOTHESIS:
- Verdict: {hypothesis.hypothesis.value}
- Confidence: {hypothesis.confidence}
- Reasoning: {hypothesis.reasoning}

EVIDENCE FROM TOOLS:
{evidence_text}

Provide your verdict in JSON format:
{{
  "verdict": "VULNERABLE" | "SAFE" | "NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "reasoning": "your reasoning from your perspective",
  "validation": {{
    "dangerous_sink": {{"present": true/false, "citation": "...", "confidence": "strong/medium/weak"}},
    "data_flow": {{"present": true/false, "citation": "...", "confidence": "strong/medium/weak"}},
    "missing_checks": {{"present": true/false, "citation": "...", "confidence": "strong/medium/weak"}}
  }}
}}"""
        }]
        
        try:
            response = self.client.chat(
                messages=messages,
                system=full_system_prompt,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
            )
            return self._parse_perspective_verdict(perspective, response.text)
        except Exception as e:
            # Return fallback verdict on error
            return PerspectiveVerdict(
                perspective=perspective,
                verdict=Verdict.NOT_ENOUGH_EVIDENCE,
                confidence=0.3,
                reasoning=f"Error getting verdict: {str(e)}",
            )
    
    def _parse_perspective_verdict(
        self,
        perspective: JudgePerspective,
        text: str,
    ) -> PerspectiveVerdict:
        """Parse verdict from LLM response."""
        try:
            json_start = text.find("{")
            json_end = text.rfind("}") + 1
            
            if json_start != -1 and json_end > json_start:
                data = json.loads(text[json_start:json_end])
                
                verdict_str = data.get("verdict", "NOT_ENOUGH_EVIDENCE").upper()
                if verdict_str not in ["VULNERABLE", "SAFE", "NOT_ENOUGH_EVIDENCE"]:
                    verdict_str = "NOT_ENOUGH_EVIDENCE"
                
                validation_data = data.get("validation", {})
                validation = JudgeValidation(
                    dangerous_sink=self._parse_check(validation_data.get("dangerous_sink", {})),
                    data_flow=self._parse_check(validation_data.get("data_flow", {})),
                    missing_checks=self._parse_check(validation_data.get("missing_checks", {})),
                )
                
                return PerspectiveVerdict(
                    perspective=perspective,
                    verdict=Verdict(verdict_str),
                    confidence=float(data.get("confidence", 0.5)),
                    reasoning=data.get("reasoning", text),
                    validation=validation,
                )
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Fallback parsing
        text_upper = text.upper()
        if "VULNERABLE" in text_upper:
            verdict = Verdict.VULNERABLE
        elif "SAFE" in text_upper:
            verdict = Verdict.SAFE
        else:
            verdict = Verdict.NOT_ENOUGH_EVIDENCE
        
        return PerspectiveVerdict(
            perspective=perspective,
            verdict=verdict,
            confidence=0.5,
            reasoning=text[:500],
        )
    
    def _parse_check(self, data: dict) -> ValidationCheck:
        """Parse validation check from data."""
        return ValidationCheck(
            present=data.get("present", False),
            citation=data.get("citation", "No citation"),
            confidence=data.get("confidence", "medium"),
        )
    
    def _aggregate_verdicts(
        self,
        verdicts: list[PerspectiveVerdict],
    ) -> EnsembleVerdict:
        """Aggregate multiple perspective verdicts."""
        if not verdicts:
            return EnsembleVerdict(
                final_verdict=Verdict.NOT_ENOUGH_EVIDENCE,
                final_confidence=0.0,
            )
        
        # Count weighted votes
        vote_scores = {
            Verdict.VULNERABLE: 0.0,
            Verdict.SAFE: 0.0,
            Verdict.NOT_ENOUGH_EVIDENCE: 0.0,
        }
        vote_counts = {v.value: 0 for v in Verdict}
        
        for pv in verdicts:
            weight = self.weights.get(pv.perspective, 1.0)
            vote_scores[pv.verdict] += weight * pv.confidence
            vote_counts[pv.verdict.value] += 1
        
        # Determine final verdict
        final_verdict = max(vote_scores, key=vote_scores.get)
        
        # Calculate confidence
        total_weight = sum(self.weights.get(pv.perspective, 1.0) for pv in verdicts)
        if total_weight > 0:
            final_confidence = vote_scores[final_verdict] / total_weight
        else:
            final_confidence = 0.5
        
        # Check for agreement
        agreement_count = sum(1 for pv in verdicts if pv.verdict == final_verdict)
        agreement_ratio = agreement_count / len(verdicts)
        
        # Build reasoning
        reasoning_parts = []
        for pv in verdicts:
            reasoning_parts.append(
                f"[{pv.perspective.value}] {pv.verdict.value} (conf: {pv.confidence:.2f}): "
                f"{pv.reasoning[:200]}..."
            )
        
        combined_reasoning = f"Ensemble verdict: {final_verdict.value} with {agreement_ratio:.0%} agreement.\n\n"
        combined_reasoning += "\n\n".join(reasoning_parts)
        
        # Detect conflicts
        has_conflict = agreement_ratio < 0.5
        conflict_details = ""
        if has_conflict:
            dissenting = [pv for pv in verdicts if pv.verdict != final_verdict]
            conflict_details = f"Dissenting opinions: {[pv.perspective.value for pv in dissenting]}"
        
        return EnsembleVerdict(
            final_verdict=final_verdict,
            final_confidence=final_confidence,
            perspective_verdicts=verdicts,
            vote_counts=vote_counts,
            agreement_ratio=agreement_ratio,
            combined_reasoning=combined_reasoning,
            has_conflict=has_conflict,
            conflict_details=conflict_details,
        )
    
    def _format_evidence(self, tool_outputs: dict) -> str:
        """Format tool outputs for display."""
        parts = []
        for name, output in tool_outputs.items():
            parts.append(f"=== {name.upper()} ===")
            parts.append(json.dumps(output, indent=2, default=str))
        return "\n\n".join(parts)
    
    def _get_base_judge_prompt(self) -> str:
        """Get the base judge system prompt."""
        return """You are a security validation judge. Your role is to verify a security hypothesis against provided evidence.

DECISION CRITERIA (Buffer Overflow Family):
A VULNERABLE verdict requires evidence for ALL conditions:
1. DANGEROUS SINK EXISTS - AST shows risky function calls
2. DATA FLOW TO SINK - External input reaches the sink
3. MISSING SAFETY CHECKS - No bounds validation before sink

VERDICT OPTIONS:
- VULNERABLE: All conditions confirmed by tool evidence
- SAFE: Evidence shows proper bounds checking
- NOT_ENOUGH_EVIDENCE: Cannot confirm from tool outputs"""


# Convenience function
def validate_with_ensemble(
    hypothesis: OrchestratorHypothesis,
    tool_outputs: dict,
    source_code: str,
    perspectives: list[JudgePerspective] = None,
) -> EnsembleVerdict:
    """
    Validate hypothesis using ensemble judging.
    
    Args:
        hypothesis: The orchestrator's hypothesis
        tool_outputs: Tool output dictionary
        source_code: The source code
        perspectives: Optional list of perspectives to use
    
    Returns:
        EnsembleVerdict with aggregated result
    """
    ensemble = EnsembleJudge(perspectives=perspectives)
    return ensemble.validate(hypothesis, tool_outputs, source_code)
