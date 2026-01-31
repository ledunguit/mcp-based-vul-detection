"""
Explanation Scorer Module - Phase 1.1 Enhancement

This module provides tools to evaluate the quality of LLM-generated explanations
and reasoning in vulnerability detection.

Metrics include:
- Evidence citation quality
- Logical flow coherence
- Technical accuracy indicators
- Completeness of explanation
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExplanationScore:
    """Aggregated score for explanation quality."""
    overall_score: float  # 0-1 scale
    evidence_citation_score: float
    logical_flow_score: float
    technical_accuracy_score: float
    completeness_score: float
    details: dict = field(default_factory=dict)


class ExplanationScorer:
    """Score quality of LLM explanations for vulnerability analysis."""
    
    # Common vulnerability-related terms that indicate technical grounding
    TECHNICAL_TERMS = {
        "buffer", "overflow", "memory", "allocation", "bounds",
        "strcpy", "memcpy", "sprintf", "gets", "scanf",
        "null", "terminator", "size", "length", "parameter",
        "tainted", "source", "sink", "sanitize", "validate",
        "pointer", "array", "index", "heap", "stack",
        "cwe", "vulnerability", "exploit", "attack", "security",
    }
    
    # Evidence source indicators
    EVIDENCE_INDICATORS = {
        "ast analysis": "ast_analyze",
        "static analysis": "static_analyze",
        "clang analyzer": "static_analyze",
        "cwe knowledge": "cwe_lookup",
        "taint analysis": "taint_analyze",
        "taint tracking": "taint_analyze",
        "pattern matching": "pattern_analyze",
        "pattern analysis": "pattern_analyze",
        "control flow": "cfg_analyze",
        "cfg analysis": "cfg_analyze",
    }
    
    # Subjective language that suggests speculation
    SUBJECTIVE_MARKERS = [
        "i think", "i believe", "seems like", "appears to",
        "probably", "possibly", "might be", "could be",
        "perhaps", "likely", "unlikely", "maybe",
    ]
    
    # Logical connectors that indicate structured reasoning
    LOGICAL_CONNECTORS = [
        "because", "therefore", "since", "as a result",
        "consequently", "due to", "based on", "according to",
        "first", "second", "third", "finally",
        "however", "additionally", "furthermore", "moreover",
    ]
    
    def __init__(self, tools_used: Optional[list[str]] = None):
        """
        Initialize scorer.
        
        Args:
            tools_used: List of tool names that were actually called.
                        Used to verify evidence citations.
        """
        self.tools_used = tools_used or []
    
    def score(
        self, 
        reasoning: str, 
        evidence: Optional[list[dict]] = None,
        verdict: Optional[str] = None,
    ) -> ExplanationScore:
        """
        Score the quality of an explanation.
        
        Args:
            reasoning: The explanation text from the LLM
            evidence: List of evidence items (optional)
            verdict: The predicted verdict (optional)
        
        Returns:
            ExplanationScore with detailed breakdown
        """
        evidence = evidence or []
        
        citation_score = self.score_evidence_citation(reasoning, evidence)
        logical_score = self.score_logical_flow(reasoning)
        technical_score = self.score_technical_accuracy(reasoning)
        completeness_score = self.score_completeness(reasoning, verdict)
        
        # Weighted overall score
        overall = (
            citation_score * 0.3 +
            logical_score * 0.25 +
            technical_score * 0.25 +
            completeness_score * 0.2
        )
        
        return ExplanationScore(
            overall_score=overall,
            evidence_citation_score=citation_score,
            logical_flow_score=logical_score,
            technical_accuracy_score=technical_score,
            completeness_score=completeness_score,
            details={
                "reasoning_length": len(reasoning),
                "technical_terms_found": self._count_technical_terms(reasoning),
                "subjective_phrases": self._count_subjective_phrases(reasoning),
                "logical_connectors": self._count_logical_connectors(reasoning),
                "evidence_citations": self._count_evidence_citations(reasoning),
            }
        )
    
    def score_evidence_citation(
        self, 
        reasoning: str, 
        evidence: list[dict]
    ) -> float:
        """
        Check if reasoning properly cites evidence from tools.
        
        Scores higher when:
        - Reasoning mentions tool outputs
        - Evidence items are referenced
        - Specific findings are cited
        """
        reasoning_lower = reasoning.lower()
        score = 0.0
        
        # Check for tool citations
        tools_cited = 0
        for indicator, tool_name in self.EVIDENCE_INDICATORS.items():
            if indicator in reasoning_lower:
                tools_cited += 1
                # Bonus if this tool was actually used
                if tool_name in self.tools_used:
                    score += 0.2
        
        # Base score for citing any tools
        if tools_cited > 0:
            score += min(0.3, tools_cited * 0.1)
        
        # Check if evidence count is mentioned
        if evidence:
            # Check if specific evidence is referenced
            for ev in evidence:
                tool = ev.get("tool", "")
                if tool.lower() in reasoning_lower:
                    score += 0.1
        
        # Penalize if no evidence citations at all
        citation_count = self._count_evidence_citations(reasoning)
        if citation_count == 0:
            score = max(0, score - 0.3)
        
        return min(1.0, score)
    
    def score_logical_flow(self, reasoning: str) -> float:
        """
        Analyze logical coherence of reasoning.
        
        Scores higher when:
        - Uses logical connectors
        - Has clear cause-effect relationships
        - Avoids contradictions
        """
        reasoning_lower = reasoning.lower()
        score = 0.0
        
        # Count logical connectors
        connector_count = self._count_logical_connectors(reasoning)
        score += min(0.4, connector_count * 0.08)
        
        # Check for structured reasoning indicators
        if any(x in reasoning_lower for x in ["first", "second", "finally"]):
            score += 0.2
        
        # Check for cause-effect language
        if any(x in reasoning_lower for x in ["because", "therefore", "since", "due to"]):
            score += 0.2
        
        # Penalize subjective language
        subjective_count = self._count_subjective_phrases(reasoning)
        score -= min(0.3, subjective_count * 0.1)
        
        # Minimum length check
        word_count = len(reasoning.split())
        if word_count < 20:
            score -= 0.2
        elif word_count > 50:
            score += 0.1
        
        return max(0.0, min(1.0, score + 0.3))  # Base score of 0.3
    
    def score_technical_accuracy(self, reasoning: str) -> float:
        """
        Score based on technical terminology usage.
        
        This is a heuristic - presence of relevant technical
        terms suggests the reasoning is grounded in code analysis.
        """
        technical_count = self._count_technical_terms(reasoning)
        
        # Scale based on technical term density
        word_count = len(reasoning.split())
        if word_count == 0:
            return 0.0
        
        density = technical_count / word_count
        
        # Target density around 5-15%
        if density < 0.03:
            score = density * 10  # Low technical content
        elif density < 0.15:
            score = 0.6 + (density - 0.03) * 3  # Good density
        else:
            score = 1.0  # Very technical
        
        return min(1.0, score)
    
    def score_completeness(
        self, 
        reasoning: str, 
        verdict: Optional[str] = None
    ) -> float:
        """
        Score completeness of the explanation.
        
        Checks for:
        - Sufficient length
        - Mention of key analysis aspects
        - Conclusion alignment with verdict
        """
        score = 0.0
        reasoning_lower = reasoning.lower()
        word_count = len(reasoning.split())
        
        # Length-based score
        if word_count >= 100:
            score += 0.3
        elif word_count >= 50:
            score += 0.2
        elif word_count >= 20:
            score += 0.1
        
        # Key aspects mentioned
        if any(x in reasoning_lower for x in ["function", "parameter", "variable", "argument"]):
            score += 0.1
        if any(x in reasoning_lower for x in ["input", "source", "user"]):
            score += 0.1
        if any(x in reasoning_lower for x in ["risk", "danger", "unsafe", "vulnerable"]):
            score += 0.1
        if any(x in reasoning_lower for x in ["check", "validate", "sanitize", "bounds"]):
            score += 0.1
        
        # Verdict alignment
        if verdict:
            verdict_lower = verdict.lower()
            if verdict_lower == "vulnerable" and "vulnerable" in reasoning_lower:
                score += 0.15
            elif verdict_lower == "safe" and ("safe" in reasoning_lower or "no vulnerability" in reasoning_lower):
                score += 0.15
        
        return min(1.0, score)
    
    def _count_technical_terms(self, text: str) -> int:
        """Count occurrences of technical terms."""
        text_lower = text.lower()
        return sum(1 for term in self.TECHNICAL_TERMS if term in text_lower)
    
    def _count_subjective_phrases(self, text: str) -> int:
        """Count subjective language markers."""
        text_lower = text.lower()
        return sum(1 for phrase in self.SUBJECTIVE_MARKERS if phrase in text_lower)
    
    def _count_logical_connectors(self, text: str) -> int:
        """Count logical connector phrases."""
        text_lower = text.lower()
        return sum(1 for conn in self.LOGICAL_CONNECTORS if conn in text_lower)
    
    def _count_evidence_citations(self, text: str) -> int:
        """Count evidence citations."""
        text_lower = text.lower()
        return sum(1 for indicator in self.EVIDENCE_INDICATORS if indicator in text_lower)


def score_explanation(
    reasoning: str,
    evidence: Optional[list[dict]] = None,
    tools_used: Optional[list[str]] = None,
    verdict: Optional[str] = None,
) -> ExplanationScore:
    """
    Convenience function to score an explanation.
    
    Args:
        reasoning: The explanation text
        evidence: List of evidence items
        tools_used: List of tools that were called
        verdict: The predicted verdict
    
    Returns:
        ExplanationScore with all metrics
    """
    scorer = ExplanationScorer(tools_used=tools_used)
    return scorer.score(reasoning, evidence, verdict)
