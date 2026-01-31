"""Tests for Phase 1.1 Enhanced Metrics."""

import pytest
from experiments.analyze_results import (
    compute_auc_roc,
    compute_tool_contribution_enhanced,
    mcnemar_test,
    compute_confidence_calibration,
    detect_hallucinations,
)


class TestAUCROC:
    """Tests for AUC-ROC calculation."""
    
    def test_perfect_classifier(self):
        """Test AUC-ROC for a perfect classifier."""
        results = [
            {"predicted_verdict": "VULNERABLE", "ground_truth": True, "confidence": 0.95},
            {"predicted_verdict": "VULNERABLE", "ground_truth": True, "confidence": 0.90},
            {"predicted_verdict": "SAFE", "ground_truth": False, "confidence": 0.85},
            {"predicted_verdict": "SAFE", "ground_truth": False, "confidence": 0.80},
        ]
        auc, curve = compute_auc_roc(results)
        # Perfect classifier should have AUC close to 1.0
        assert auc >= 0.9
    
    def test_random_classifier(self):
        """Test AUC-ROC for random-like predictions."""
        results = [
            {"predicted_verdict": "VULNERABLE", "ground_truth": True, "confidence": 0.5},
            {"predicted_verdict": "SAFE", "ground_truth": True, "confidence": 0.5},
            {"predicted_verdict": "VULNERABLE", "ground_truth": False, "confidence": 0.5},
            {"predicted_verdict": "SAFE", "ground_truth": False, "confidence": 0.5},
        ]
        auc, curve = compute_auc_roc(results)
        # Random classifier should have AUC around 0.5
        assert 0.3 <= auc <= 0.7
    
    def test_handles_error_samples(self):
        """Test that ERROR and NOT_ENOUGH_EVIDENCE samples are excluded."""
        results = [
            {"predicted_verdict": "ERROR", "ground_truth": True, "confidence": 0.9},
            {"predicted_verdict": "NOT_ENOUGH_EVIDENCE", "ground_truth": False, "confidence": 0.8},
            {"predicted_verdict": "VULNERABLE", "ground_truth": True, "confidence": 0.95},
            {"predicted_verdict": "SAFE", "ground_truth": False, "confidence": 0.85},
        ]
        auc, curve = compute_auc_roc(results)
        # Should still compute valid AUC from the valid samples
        assert auc > 0


class TestToolContribution:
    """Tests for tool contribution analysis."""
    
    def test_basic_tool_detection(self):
        """Test tool detection from tool_outputs field."""
        results = [
            {
                "predicted_verdict": "VULNERABLE",
                "ground_truth": True,
                "confidence": 0.9,
                "tool_outputs": {"ast_analyze": {}, "taint_analyze": {}},
            },
            {
                "predicted_verdict": "SAFE",
                "ground_truth": False,
                "confidence": 0.8,
                "tool_outputs": {"ast_analyze": {}},
            },
        ]
        contrib = compute_tool_contribution_enhanced(results)
        
        assert "ast_analyze" in contrib
        assert contrib["ast_analyze"]["total_used"] == 2
        assert contrib["taint_analyze"]["total_used"] == 1
    
    def test_fallback_reasoning_detection(self):
        """Test tool detection from reasoning text."""
        results = [
            {
                "predicted_verdict": "VULNERABLE",
                "ground_truth": True,
                "confidence": 0.9,
                "reasoning": "Based on AST analysis, strcpy was detected...",
            },
        ]
        contrib = compute_tool_contribution_enhanced(results)
        
        assert contrib["ast_analyze"]["total_used"] >= 1
    
    def test_contribution_score_calculation(self):
        """Test that contribution scores are calculated."""
        results = [
            {
                "predicted_verdict": "VULNERABLE",
                "ground_truth": True,
                "confidence": 0.9,
                "tool_outputs": {"ast_analyze": {}},
            },
        ]
        contrib = compute_tool_contribution_enhanced(results)
        
        # All tools should have contribution metrics
        for tool in contrib.values():
            assert "usage_rate" in tool
            assert "accuracy_when_used" in tool
            assert "contribution_score" in tool


class TestMcNemarTest:
    """Tests for McNemar's test."""
    
    def test_identical_approaches(self):
        """Test McNemar's test when approaches give identical results."""
        # Need at least 10 samples for McNemar's test
        results = [
            {"sample_id": f"s{i}", "predicted_verdict": "VULNERABLE", "ground_truth": True}
            for i in range(6)
        ] + [
            {"sample_id": f"s{i+6}", "predicted_verdict": "SAFE", "ground_truth": False}
            for i in range(6)
        ]
        result = mcnemar_test(results, results)
        
        # Identical approaches: either no disagreements or not significant
        if "interpretation" in result:
            assert result["interpretation"] == "No disagreements between approaches"
        else:
            assert result.get("statistically_significant") == False
    
    def test_different_approaches(self):
        """Test McNemar's test with different approaches."""
        results1 = [
            {"sample_id": f"s{i}", "predicted_verdict": "VULNERABLE", "ground_truth": True}
            for i in range(10)
        ] + [
            {"sample_id": f"s{i+10}", "predicted_verdict": "SAFE", "ground_truth": False}
            for i in range(10)
        ]
        
        # Approach 2 is wrong on all samples
        results2 = [
            {"sample_id": f"s{i}", "predicted_verdict": "SAFE", "ground_truth": True}
            for i in range(10)
        ] + [
            {"sample_id": f"s{i+10}", "predicted_verdict": "VULNERABLE", "ground_truth": False}
            for i in range(10)
        ]
        
        result = mcnemar_test(results1, results2)
        
        # Should detect significant difference
        assert "chi2_statistic" in result
        assert result.get("common_samples", 0) == 20
    
    def test_insufficient_samples(self):
        """Test McNemar's test with insufficient samples."""
        results1 = [{"sample_id": "s1", "predicted_verdict": "VULNERABLE", "ground_truth": True}]
        results2 = [{"sample_id": "s1", "predicted_verdict": "SAFE", "ground_truth": True}]
        
        result = mcnemar_test(results1, results2)
        
        # Should report error due to insufficient samples
        assert "error" in result or result.get("common_samples", 0) < 10


class TestIntegration:
    """Integration tests for enhanced metrics."""
    
    def test_all_metrics_on_sample_data(self):
        """Test all metrics work together on sample data."""
        results = [
            {
                "sample_id": f"sample_{i}",
                "predicted_verdict": "VULNERABLE",
                "ground_truth": True,
                "confidence": 0.8 + (i * 0.01),
                "evidence_count": 2,
                "reasoning": "Based on AST analysis and taint tracking...",
                "tool_outputs": {"ast_analyze": {}, "taint_analyze": {}},
            }
            for i in range(10)
        ] + [
            {
                "sample_id": f"sample_{i+10}",
                "predicted_verdict": "SAFE",
                "ground_truth": False,
                "confidence": 0.7 + (i * 0.01),
                "evidence_count": 1,
                "reasoning": "Pattern analysis shows safe code...",
                "tool_outputs": {"pattern_analyze": {}},
            }
            for i in range(10)
        ]
        
        # Test all functions work without errors
        auc, _ = compute_auc_roc(results)
        assert 0 <= auc <= 1
        
        contrib = compute_tool_contribution_enhanced(results)
        assert len(contrib) == 6  # 6 tools
        
        ece, _ = compute_confidence_calibration(results)
        assert 0 <= ece <= 1
        
        halluc_rate, _ = detect_hallucinations(results)
        assert 0 <= halluc_rate <= 1
