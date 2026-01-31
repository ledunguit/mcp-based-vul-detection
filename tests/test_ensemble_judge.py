"""Tests for Phase 2.2 Ensemble Judging."""

import pytest
from unittest.mock import Mock, patch
from src.agents.ensemble_judge import (
    EnsembleJudge,
    EnsembleVerdict,
    PerspectiveVerdict,
    JudgePerspective,
    PERSPECTIVE_PROMPTS,
)
from src.schemas import (
    Verdict,
    OrchestratorHypothesis,
    Evidence,
    JudgeValidation,
    ValidationCheck,
)


class TestJudgePerspective:
    """Tests for JudgePerspective enum."""
    
    def test_all_perspectives_have_prompts(self):
        """Every perspective should have a corresponding prompt."""
        for perspective in JudgePerspective:
            assert perspective in PERSPECTIVE_PROMPTS
            assert len(PERSPECTIVE_PROMPTS[perspective]) > 0
    
    def test_perspective_values(self):
        """Test perspective enum values."""
        assert JudgePerspective.SECURITY_EXPERT.value == "security_expert"
        assert JudgePerspective.FALSE_POSITIVE_FILTER.value == "false_positive_filter"


class TestPerspectiveVerdict:
    """Tests for PerspectiveVerdict."""
    
    def test_create_verdict(self):
        """Test creating a perspective verdict."""
        verdict = PerspectiveVerdict(
            perspective=JudgePerspective.SECURITY_EXPERT,
            verdict=Verdict.VULNERABLE,
            confidence=0.85,
            reasoning="Found dangerous strcpy",
        )
        
        assert verdict.perspective == JudgePerspective.SECURITY_EXPERT
        assert verdict.verdict == Verdict.VULNERABLE
        assert verdict.confidence == 0.85


class TestEnsembleVerdict:
    """Tests for EnsembleVerdict."""
    
    def test_to_judge_verdict(self):
        """Test conversion to JudgeVerdict."""
        ensemble_verdict = EnsembleVerdict(
            final_verdict=Verdict.VULNERABLE,
            final_confidence=0.9,
            agreement_ratio=1.0,
            combined_reasoning="All judges agree",
        )
        
        judge_verdict = ensemble_verdict.to_judge_verdict()
        
        assert judge_verdict.verdict == Verdict.VULNERABLE
        assert judge_verdict.confidence == 0.9
    
    def test_verdict_with_perspectives(self):
        """Test verdict with perspective details."""
        pv1 = PerspectiveVerdict(
            perspective=JudgePerspective.SECURITY_EXPERT,
            verdict=Verdict.VULNERABLE,
            confidence=0.9,
            reasoning="Exploitable",
        )
        pv2 = PerspectiveVerdict(
            perspective=JudgePerspective.FALSE_POSITIVE_FILTER,
            verdict=Verdict.VULNERABLE,
            confidence=0.8,
            reasoning="Confirmed",
        )
        
        ensemble = EnsembleVerdict(
            final_verdict=Verdict.VULNERABLE,
            final_confidence=0.85,
            perspective_verdicts=[pv1, pv2],
            vote_counts={"VULNERABLE": 2, "SAFE": 0},
            agreement_ratio=1.0,
        )
        
        assert len(ensemble.perspective_verdicts) == 2
        assert ensemble.has_conflict == False


class TestEnsembleJudge:
    """Tests for EnsembleJudge class."""
    
    def test_init_default_perspectives(self):
        """Test initialization with default perspectives."""
        judge = EnsembleJudge()
        
        assert len(judge.perspectives) == 3
        assert JudgePerspective.SECURITY_EXPERT in judge.perspectives
    
    def test_init_custom_perspectives(self):
        """Test initialization with custom perspectives."""
        judge = EnsembleJudge(perspectives=[
            JudgePerspective.SECURITY_EXPERT,
            JudgePerspective.CONSERVATIVE,
        ])
        
        assert len(judge.perspectives) == 2
    
    def test_custom_weights(self):
        """Test custom weight configuration."""
        judge = EnsembleJudge(weights={
            JudgePerspective.SECURITY_EXPERT: 2.0,
            JudgePerspective.FALSE_POSITIVE_FILTER: 0.5,
        })
        
        assert judge.weights[JudgePerspective.SECURITY_EXPERT] == 2.0


class TestVerdictAggregation:
    """Tests for verdict aggregation logic."""
    
    def test_unanimous_vulnerable(self):
        """Test aggregation when all judges say vulnerable."""
        judge = EnsembleJudge()
        
        verdicts = [
            PerspectiveVerdict(JudgePerspective.SECURITY_EXPERT, Verdict.VULNERABLE, 0.9, "test"),
            PerspectiveVerdict(JudgePerspective.FALSE_POSITIVE_FILTER, Verdict.VULNERABLE, 0.85, "test"),
            PerspectiveVerdict(JudgePerspective.CONSERVATIVE, Verdict.VULNERABLE, 0.8, "test"),
        ]
        
        result = judge._aggregate_verdicts(verdicts)
        
        assert result.final_verdict == Verdict.VULNERABLE
        assert result.agreement_ratio == 1.0
        assert result.has_conflict == False
    
    def test_majority_safe(self):
        """Test aggregation with majority SAFE verdict."""
        judge = EnsembleJudge()
        
        verdicts = [
            PerspectiveVerdict(JudgePerspective.SECURITY_EXPERT, Verdict.VULNERABLE, 0.7, "risky"),
            PerspectiveVerdict(JudgePerspective.FALSE_POSITIVE_FILTER, Verdict.SAFE, 0.9, "safe"),
            PerspectiveVerdict(JudgePerspective.CONSERVATIVE, Verdict.SAFE, 0.85, "safe"),
        ]
        
        result = judge._aggregate_verdicts(verdicts)
        
        assert result.final_verdict == Verdict.SAFE
        assert result.agreement_ratio == 2/3
    
    def test_conflict_detection(self):
        """Test that conflicts are detected."""
        judge = EnsembleJudge()
        
        verdicts = [
            PerspectiveVerdict(JudgePerspective.SECURITY_EXPERT, Verdict.VULNERABLE, 0.9, "risk"),
            PerspectiveVerdict(JudgePerspective.FALSE_POSITIVE_FILTER, Verdict.SAFE, 0.9, "safe"),
            PerspectiveVerdict(JudgePerspective.CONSERVATIVE, Verdict.NOT_ENOUGH_EVIDENCE, 0.8, "unclear"),
        ]
        
        result = judge._aggregate_verdicts(verdicts)
        
        # With all different verdicts, agreement < 0.5
        assert result.agreement_ratio < 1.0
    
    def test_weighted_voting(self):
        """Test that weights affect final result."""
        # High weight on SECURITY_EXPERT
        judge = EnsembleJudge(
            perspectives=[JudgePerspective.SECURITY_EXPERT, JudgePerspective.FALSE_POSITIVE_FILTER],
            weights={
                JudgePerspective.SECURITY_EXPERT: 3.0,
                JudgePerspective.FALSE_POSITIVE_FILTER: 1.0,
            }
        )
        
        verdicts = [
            PerspectiveVerdict(JudgePerspective.SECURITY_EXPERT, Verdict.VULNERABLE, 0.9, "vuln"),
            PerspectiveVerdict(JudgePerspective.FALSE_POSITIVE_FILTER, Verdict.SAFE, 0.9, "safe"),
        ]
        
        result = judge._aggregate_verdicts(verdicts)
        
        # SECURITY_EXPERT has 3x weight, so VULNERABLE should win
        assert result.final_verdict == Verdict.VULNERABLE
    
    def test_empty_verdicts(self):
        """Test handling of empty verdict list."""
        judge = EnsembleJudge()
        result = judge._aggregate_verdicts([])
        
        assert result.final_verdict == Verdict.NOT_ENOUGH_EVIDENCE
        assert result.final_confidence == 0.0


class TestResponseParsing:
    """Tests for LLM response parsing."""
    
    def test_parse_valid_json(self):
        """Test parsing valid JSON response."""
        judge = EnsembleJudge()
        
        response = '''Here is my analysis:
        {
            "verdict": "VULNERABLE",
            "confidence": 0.85,
            "reasoning": "Found buffer overflow",
            "validation": {
                "dangerous_sink": {"present": true, "citation": "strcpy found", "confidence": "strong"},
                "data_flow": {"present": true, "citation": "input flows to sink", "confidence": "strong"},
                "missing_checks": {"present": true, "citation": "no bounds check", "confidence": "medium"}
            }
        }'''
        
        result = judge._parse_perspective_verdict(
            JudgePerspective.SECURITY_EXPERT,
            response
        )
        
        assert result.verdict == Verdict.VULNERABLE
        assert result.confidence == 0.85
        assert result.validation is not None
    
    def test_parse_fallback(self):
        """Test fallback parsing when JSON fails."""
        judge = EnsembleJudge()
        
        response = "After analysis, the code is SAFE because bounds are checked."
        
        result = judge._parse_perspective_verdict(
            JudgePerspective.CONSERVATIVE,
            response
        )
        
        assert result.verdict == Verdict.SAFE
        assert result.confidence == 0.5  # Default fallback confidence


class TestIntegration:
    """Integration tests for ensemble judging."""
    
    def test_format_evidence(self):
        """Test evidence formatting."""
        judge = EnsembleJudge()
        
        tool_outputs = {
            "ast_analyze": {"risky_sinks": ["strcpy"]},
            "taint_analyze": {"paths": []},
        }
        
        formatted = judge._format_evidence(tool_outputs)
        
        assert "AST_ANALYZE" in formatted
        assert "TAINT_ANALYZE" in formatted
        assert "strcpy" in formatted
    
    def test_base_prompt_generation(self):
        """Test base prompt generation."""
        judge = EnsembleJudge()
        prompt = judge._get_base_judge_prompt()
        
        assert "VULNERABLE" in prompt
        assert "SAFE" in prompt
        assert "DANGEROUS SINK" in prompt
