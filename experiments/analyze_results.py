"""Analyze experiment results and compute metrics.

This script computes:
- Precision, Recall, F1 for each approach
- Evidence-backed decision rate (for MCP approach)
- Hallucination detection and confidence calibration
- Per-CWE breakdown analysis
- Error analysis and confusion matrices
- AUC-ROC curve analysis (Phase 1 Enhancement)
- Tool contribution analysis with actual tool call data
- Statistical significance tests (McNemar's test)
"""

import json
import argparse
import math
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

# Optional numpy/scipy for advanced metrics
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None


@dataclass
class Metrics:
    """Metrics for an approach."""
    approach: str
    total_samples: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    not_enough_evidence: int
    errors: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    avg_duration: float
    evidence_backed_rate: float = 0.0
    # Enhanced metrics (Phase 1.1)
    avg_confidence: float = 0.0
    confidence_calibration_error: float = 0.0
    hallucination_rate: float = 0.0
    tool_coverage: float = 0.0
    per_cwe_metrics: dict = field(default_factory=dict)
    # New Phase 1.1 metrics
    auc_roc: float = 0.0  # Area Under ROC Curve
    tool_contribution: dict = field(default_factory=dict)  # Per-tool impact


@dataclass
class ErrorCase:
    """Details of an error case for analysis."""
    sample_id: str
    function_name: str
    ground_truth: bool
    predicted: str
    error_type: str  # FP, FN, NEE
    reasoning: str
    evidence_count: int
    confidence: float = 0.0


# ============================================================================
# Phase 1.1 Enhanced Metrics Functions
# ============================================================================

def compute_auc_roc(results: list[dict]) -> tuple[float, list[tuple[float, float]]]:
    """
    Compute AUC-ROC using confidence scores as probabilities.
    
    For binary classification (VULNERABLE vs SAFE), we treat:
    - VULNERABLE with high confidence = high probability of positive
    - SAFE with high confidence = low probability of positive
    
    Returns:
        Tuple of (auc_score, roc_curve_points)
    """
    # Collect scores and labels
    y_true = []  # 1 for vulnerable, 0 for safe
    y_scores = []  # Probability of being vulnerable
    
    for r in results:
        verdict = r.get("predicted_verdict", "")
        if verdict in ["ERROR", "NOT_ENOUGH_EVIDENCE"]:
            continue
        
        ground_truth = r.get("ground_truth", False)
        confidence = r.get("confidence", 0.5)
        
        y_true.append(1 if ground_truth else 0)
        
        # Convert verdict + confidence to probability of vulnerable
        if verdict == "VULNERABLE":
            y_scores.append(confidence)
        else:  # SAFE
            y_scores.append(1 - confidence)
    
    if len(y_true) < 2 or len(set(y_true)) < 2:
        # Not enough samples or only one class
        return 0.0, []
    
    # Use numpy if available for efficient computation
    if HAS_NUMPY:
        y_true_np = np.array(y_true)
        y_scores_np = np.array(y_scores)
        
        # Sort by score descending
        sorted_indices = np.argsort(-y_scores_np)
        y_true_sorted = y_true_np[sorted_indices]
        
        # Compute ROC curve points
        n_pos = np.sum(y_true_np)
        n_neg = len(y_true_np) - n_pos
        
        tpr_points = []
        fpr_points = []
        tp = 0
        fp = 0
        
        for label in y_true_sorted:
            if label == 1:
                tp += 1
            else:
                fp += 1
            tpr_points.append(tp / n_pos if n_pos > 0 else 0)
            fpr_points.append(fp / n_neg if n_neg > 0 else 0)
        
        # Compute AUC using trapezoidal rule
        auc = np.trapezoid(tpr_points, fpr_points) if hasattr(np, 'trapezoid') else np.trapz(tpr_points, fpr_points)
        roc_curve = list(zip(fpr_points, tpr_points))
        
        return abs(auc), roc_curve
    else:
        # Fallback: Simple Wilcoxon-Mann-Whitney statistic
        n_pos = sum(y_true)
        n_neg = len(y_true) - n_pos
        
        if n_pos == 0 or n_neg == 0:
            return 0.0, []
        
        # Count concordant pairs (simplified AUC calculation)
        concordant = 0
        for i, (label_i, score_i) in enumerate(zip(y_true, y_scores)):
            for j, (label_j, score_j) in enumerate(zip(y_true, y_scores)):
                if label_i > label_j and score_i > score_j:
                    concordant += 1
                elif label_i > label_j and score_i == score_j:
                    concordant += 0.5
        
        auc = concordant / (n_pos * n_neg)
        return auc, []


def compute_tool_contribution_enhanced(results: list[dict]) -> dict:
    """
    Analyze tool contribution using actual tool call data.
    
    For each tool, computes:
    - Usage frequency
    - Accuracy when tool is used vs not used
    - Contribution to correct predictions
    - Average impact on confidence
    
    Returns:
        Dict with detailed tool contribution metrics
    """
    all_tools = ["ast_analyze", "static_analyze", "cwe_lookup", 
                 "taint_analyze", "pattern_analyze", "cfg_analyze"]
    
    tool_stats = {tool: {
        "used_count": 0,
        "correct_when_used": 0,
        "incorrect_when_used": 0,
        "confidence_sum_when_used": 0.0,
        "not_used_count": 0,
        "correct_when_not_used": 0,
    } for tool in all_tools}
    
    for r in results:
        verdict = r.get("predicted_verdict", "")
        if verdict in ["ERROR", "NOT_ENOUGH_EVIDENCE"]:
            continue
        
        ground_truth = r.get("ground_truth", False)
        is_correct = (verdict == "VULNERABLE" and ground_truth) or \
                     (verdict == "SAFE" and not ground_truth)
        confidence = r.get("confidence", 0.5)
        
        # Get tools used from result data
        tools_used = set()
        
        # Check tool_calls field if available
        if "tool_calls" in r and isinstance(r["tool_calls"], list):
            for tc in r["tool_calls"]:
                if isinstance(tc, dict) and "name" in tc:
                    tools_used.add(tc["name"])
                elif isinstance(tc, str):
                    tools_used.add(tc)
        
        # Check tool_outputs field
        if "tool_outputs" in r and isinstance(r["tool_outputs"], dict):
            tools_used.update(r["tool_outputs"].keys())
        
        # Fallback: detect from reasoning
        if not tools_used:
            reasoning = r.get("reasoning", "").lower()
            if "ast" in reasoning:
                tools_used.add("ast_analyze")
            if "static" in reasoning or "clang" in reasoning:
                tools_used.add("static_analyze")
            if "cwe" in reasoning:
                tools_used.add("cwe_lookup")
            if "taint" in reasoning:
                tools_used.add("taint_analyze")
            if "pattern" in reasoning:
                tools_used.add("pattern_analyze")
            if "cfg" in reasoning or "control flow" in reasoning:
                tools_used.add("cfg_analyze")
        
        # Update stats for each tool
        for tool in all_tools:
            if tool in tools_used:
                tool_stats[tool]["used_count"] += 1
                tool_stats[tool]["confidence_sum_when_used"] += confidence
                if is_correct:
                    tool_stats[tool]["correct_when_used"] += 1
                else:
                    tool_stats[tool]["incorrect_when_used"] += 1
            else:
                tool_stats[tool]["not_used_count"] += 1
                if is_correct:
                    tool_stats[tool]["correct_when_not_used"] += 1
    
    # Compute derived metrics
    contribution = {}
    for tool, stats in tool_stats.items():
        used = stats["used_count"]
        not_used = stats["not_used_count"]
        
        accuracy_when_used = (stats["correct_when_used"] / used) if used > 0 else 0.0
        accuracy_when_not_used = (stats["correct_when_not_used"] / not_used) if not_used > 0 else 0.0
        avg_confidence = (stats["confidence_sum_when_used"] / used) if used > 0 else 0.0
        
        # Contribution score: how much does using this tool improve accuracy?
        contribution_score = accuracy_when_used - accuracy_when_not_used
        
        contribution[tool] = {
            "usage_rate": used / (used + not_used) if (used + not_used) > 0 else 0.0,
            "accuracy_when_used": accuracy_when_used,
            "accuracy_when_not_used": accuracy_when_not_used,
            "contribution_score": contribution_score,
            "avg_confidence_when_used": avg_confidence,
            "total_used": used,
        }
    
    return contribution


def mcnemar_test(results1: list[dict], results2: list[dict]) -> dict:
    """
    Perform McNemar's test to compare two approaches.
    
    McNemar's test is appropriate for paired nominal data, comparing
    the proportions of disagreement between two classifiers.
    
    Args:
        results1: Results from first approach
        results2: Results from second approach (must have same samples)
    
    Returns:
        Dict with test statistic, p-value, and interpretation
    """
    # Build sample_id to result mapping
    results1_map = {r.get("sample_id"): r for r in results1}
    results2_map = {r.get("sample_id"): r for r in results2}
    
    # Find common samples
    common_ids = set(results1_map.keys()) & set(results2_map.keys())
    
    if len(common_ids) < 10:
        return {
            "error": "Not enough common samples for McNemar's test",
            "common_samples": len(common_ids),
        }
    
    # Count disagreement table
    # b = approach1 correct, approach2 incorrect
    # c = approach1 incorrect, approach2 correct
    b = 0
    c = 0
    
    for sample_id in common_ids:
        r1 = results1_map[sample_id]
        r2 = results2_map[sample_id]
        
        verdict1 = r1.get("predicted_verdict", "")
        verdict2 = r2.get("predicted_verdict", "")
        ground_truth = r1.get("ground_truth", False)
        
        if verdict1 in ["ERROR", "NOT_ENOUGH_EVIDENCE"]:
            continue
        if verdict2 in ["ERROR", "NOT_ENOUGH_EVIDENCE"]:
            continue
        
        correct1 = (verdict1 == "VULNERABLE" and ground_truth) or \
                   (verdict1 == "SAFE" and not ground_truth)
        correct2 = (verdict2 == "VULNERABLE" and ground_truth) or \
                   (verdict2 == "SAFE" and not ground_truth)
        
        if correct1 and not correct2:
            b += 1
        elif not correct1 and correct2:
            c += 1
    
    # McNemar's test statistic (with continuity correction)
    if b + c == 0:
        return {
            "b": b,
            "c": c,
            "interpretation": "No disagreements between approaches",
            "statistically_significant": False,
        }
    
    chi2 = ((abs(b - c) - 1) ** 2) / (b + c)
    
    # Approximate p-value using chi-squared distribution with 1 df
    # For chi2 > 3.84, p < 0.05 (statistically significant at 95% confidence)
    p_value_approx = "< 0.05" if chi2 > 3.84 else ">= 0.05"
    significant = chi2 > 3.84
    
    # Determine which approach is better
    better = None
    if significant:
        if b > c:
            better = "approach1"
        else:
            better = "approach2"
    
    return {
        "b": b,  # approach1 correct, approach2 wrong
        "c": c,  # approach1 wrong, approach2 correct
        "chi2_statistic": chi2,
        "p_value": p_value_approx,
        "statistically_significant": significant,
        "better_approach": better,
        "common_samples": len(common_ids),
    }


def compute_confidence_calibration(results: list[dict]) -> tuple[float, dict]:
    """
    Compute confidence calibration error.
    
    Measures how well confidence scores align with actual accuracy.
    A well-calibrated model should have confidence ≈ accuracy for each bin.
    
    Returns:
        Tuple of (expected_calibration_error, bin_details)
    """
    # Bin confidences into 10 buckets
    bins = {i: {"correct": 0, "total": 0, "confidence_sum": 0.0} for i in range(10)}
    
    for r in results:
        verdict = r.get("predicted_verdict", "")
        if verdict in ["ERROR", "NOT_ENOUGH_EVIDENCE"]:
            continue
        
        confidence = r.get("confidence", 0.5)
        ground_truth = r.get("ground_truth", False)
        
        # Determine correctness
        is_correct = (verdict == "VULNERABLE" and ground_truth) or \
                     (verdict == "SAFE" and not ground_truth)
        
        # Bin index (0-9)
        bin_idx = min(int(confidence * 10), 9)
        bins[bin_idx]["total"] += 1
        bins[bin_idx]["confidence_sum"] += confidence
        if is_correct:
            bins[bin_idx]["correct"] += 1
    
    # Compute Expected Calibration Error (ECE)
    total_samples = sum(b["total"] for b in bins.values())
    ece = 0.0
    bin_details = {}
    
    for bin_idx, b in bins.items():
        if b["total"] > 0:
            avg_confidence = b["confidence_sum"] / b["total"]
            accuracy = b["correct"] / b["total"]
            weight = b["total"] / total_samples if total_samples > 0 else 0
            ece += weight * abs(accuracy - avg_confidence)
            bin_details[f"{bin_idx*10}-{(bin_idx+1)*10}%"] = {
                "samples": b["total"],
                "accuracy": accuracy,
                "avg_confidence": avg_confidence,
                "gap": abs(accuracy - avg_confidence),
            }
    
    return ece, bin_details


def detect_hallucinations(results: list[dict]) -> tuple[float, list[dict]]:
    """
    Detect potential hallucinations in reasoning.
    
    A hallucination is when:
    1. Evidence count is 0 but verdict is definitive (not NEE)
    2. Reasoning mentions facts not in tool outputs
    3. High confidence with no evidence
    
    Returns:
        Tuple of (hallucination_rate, hallucination_details)
    """
    hallucinations = []
    total_definitive = 0
    
    for r in results:
        verdict = r.get("predicted_verdict", "")
        if verdict in ["ERROR", "NOT_ENOUGH_EVIDENCE"]:
            continue
        
        total_definitive += 1
        evidence_count = r.get("evidence_count", 0)
        confidence = r.get("confidence", 0.5)
        reasoning = r.get("reasoning", "")
        
        hallucination_flags = []
        
        # Flag 1: No evidence but definitive verdict
        if evidence_count == 0:
            hallucination_flags.append("no_evidence_definitive_verdict")
        
        # Flag 2: High confidence (>0.8) with no or minimal evidence
        if confidence > 0.8 and evidence_count < 2:
            hallucination_flags.append("high_confidence_low_evidence")
        
        # Flag 3: Very short reasoning (likely not citing tools)
        if len(reasoning) < 50 and verdict != "SAFE":
            hallucination_flags.append("insufficient_reasoning")
        
        # Flag 4: Reasoning contains "I think" or "I believe" (direct analysis)
        reasoning_lower = reasoning.lower()
        if any(phrase in reasoning_lower for phrase in ["i think", "i believe", "seems like", "appears to"]):
            hallucination_flags.append("subjective_language")
        
        if hallucination_flags:
            hallucinations.append({
                "sample_id": r.get("sample_id", "unknown"),
                "verdict": verdict,
                "confidence": confidence,
                "evidence_count": evidence_count,
                "flags": hallucination_flags,
            })
    
    rate = len(hallucinations) / total_definitive if total_definitive > 0 else 0.0
    return rate, hallucinations


def analyze_errors(results: list[dict]) -> dict:
    """
    Detailed analysis of error cases (FP, FN, NEE).
    
    Returns breakdown of errors with patterns and suggestions.
    """
    errors = {
        "false_positives": [],
        "false_negatives": [],
        "not_enough_evidence": [],
        "parse_errors": [],
    }
    
    error_patterns = defaultdict(int)
    
    for r in results:
        verdict = r.get("predicted_verdict", "")
        ground_truth = r.get("ground_truth", False)
        
        error_case = ErrorCase(
            sample_id=r.get("sample_id", "unknown"),
            function_name=r.get("function_name", "unknown"),
            ground_truth=ground_truth,
            predicted=verdict,
            error_type="",
            reasoning=r.get("reasoning", "")[:200],
            evidence_count=r.get("evidence_count", 0),
            confidence=r.get("confidence", 0.0),
        )
        
        if verdict == "ERROR":
            error_case.error_type = "ERROR"
            errors["parse_errors"].append(vars(error_case))
            error_patterns["parse_error"] += 1
        elif verdict == "NOT_ENOUGH_EVIDENCE":
            error_case.error_type = "NEE"
            errors["not_enough_evidence"].append(vars(error_case))
            error_patterns["insufficient_evidence"] += 1
        elif verdict == "VULNERABLE" and not ground_truth:
            error_case.error_type = "FP"
            errors["false_positives"].append(vars(error_case))
            # Analyze FP patterns
            reasoning = r.get("reasoning", "").lower()
            if "strcpy" in reasoning or "memcpy" in reasoning:
                error_patterns["fp_misidentified_safe_copy"] += 1
            else:
                error_patterns["fp_other"] += 1
        elif verdict == "SAFE" and ground_truth:
            error_case.error_type = "FN"
            errors["false_negatives"].append(vars(error_case))
            # Analyze FN patterns
            reasoning = r.get("reasoning", "").lower()
            if "bounds check" in reasoning or "size" in reasoning:
                error_patterns["fn_missed_bounds_issue"] += 1
            else:
                error_patterns["fn_other"] += 1
    
    return {
        "error_cases": errors,
        "error_patterns": dict(error_patterns),
        "summary": {
            "total_fp": len(errors["false_positives"]),
            "total_fn": len(errors["false_negatives"]),
            "total_nee": len(errors["not_enough_evidence"]),
            "total_parse_errors": len(errors["parse_errors"]),
        }
    }


def compute_per_cwe_metrics(results: list[dict]) -> dict:
    """Compute metrics broken down by CWE type."""
    cwe_results = defaultdict(lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "nee": 0})
    
    for r in results:
        cwe_id = r.get("cwe_id", "CWE-120")
        verdict = r.get("predicted_verdict", "")
        ground_truth = r.get("ground_truth", False)
        
        if verdict == "NOT_ENOUGH_EVIDENCE":
            cwe_results[cwe_id]["nee"] += 1
        elif verdict == "VULNERABLE":
            if ground_truth:
                cwe_results[cwe_id]["tp"] += 1
            else:
                cwe_results[cwe_id]["fp"] += 1
        elif verdict == "SAFE":
            if ground_truth:
                cwe_results[cwe_id]["fn"] += 1
            else:
                cwe_results[cwe_id]["tn"] += 1
    
    per_cwe = {}
    for cwe_id, counts in cwe_results.items():
        tp, tn, fp, fn = counts["tp"], counts["tn"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        per_cwe[cwe_id] = {
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "not_enough_evidence": counts["nee"],
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
        }
    
    return per_cwe


def compute_tool_coverage(results: list[dict]) -> dict:
    """Analyze which tools were used and their impact."""
    tool_usage = defaultdict(int)
    tool_success = defaultdict(lambda: {"correct": 0, "total": 0})
    
    for r in results:
        # This would need tool call data - for now estimate from evidence
        evidence_count = r.get("evidence_count", 0)
        reasoning = r.get("reasoning", "").lower()
        verdict = r.get("predicted_verdict", "")
        ground_truth = r.get("ground_truth", False)
        
        is_correct = (verdict == "VULNERABLE" and ground_truth) or \
                     (verdict == "SAFE" and not ground_truth)
        
        # Detect tool usage from reasoning
        if "ast" in reasoning:
            tool_usage["ast_analyze"] += 1
            tool_success["ast_analyze"]["total"] += 1
            if is_correct:
                tool_success["ast_analyze"]["correct"] += 1
        
        if "static" in reasoning or "clang" in reasoning:
            tool_usage["static_analyze"] += 1
            tool_success["static_analyze"]["total"] += 1
            if is_correct:
                tool_success["static_analyze"]["correct"] += 1
        
        if "cwe" in reasoning:
            tool_usage["cwe_lookup"] += 1
            tool_success["cwe_lookup"]["total"] += 1
            if is_correct:
                tool_success["cwe_lookup"]["correct"] += 1
    
    tool_impact = {}
    for tool, counts in tool_success.items():
        if counts["total"] > 0:
            tool_impact[tool] = {
                "usage_count": tool_usage[tool],
                "accuracy_when_used": counts["correct"] / counts["total"],
            }
    
    return {
        "tool_usage_counts": dict(tool_usage),
        "tool_impact": tool_impact,
    }


def compute_metrics(results: list[dict], approach: str) -> Metrics:
    """Compute comprehensive metrics for a set of results."""
    tp = tn = fp = fn = nee = errors = 0
    total_duration = 0.0
    evidence_backed = 0
    confidence_sum = 0.0
    confidence_count = 0
    
    for r in results:
        verdict = r["predicted_verdict"]
        ground_truth = r["ground_truth"]
        total_duration += r["duration_seconds"]
        
        # Collect confidence
        if "confidence" in r:
            confidence_sum += r["confidence"]
            confidence_count += 1
        
        if verdict == "ERROR":
            errors += 1
            continue
        
        if verdict == "NOT_ENOUGH_EVIDENCE":
            nee += 1
            continue
        
        if verdict == "VULNERABLE":
            if ground_truth:
                tp += 1
            else:
                fp += 1
        elif verdict == "SAFE":
            if ground_truth:
                fn += 1
            else:
                tn += 1
        
        # Check if evidence-backed
        if r.get("evidence_count", 0) > 0:
            evidence_backed += 1
    
    total = len(results)
    predicted_positive = tp + fp
    actual_positive = tp + fn
    valid_predictions = total - errors - nee
    
    precision = tp / predicted_positive if predicted_positive > 0 else 0.0
    recall = tp / actual_positive if actual_positive > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / valid_predictions if valid_predictions > 0 else 0.0
    
    evidence_rate = evidence_backed / valid_predictions if valid_predictions > 0 else 0.0
    avg_confidence = confidence_sum / confidence_count if confidence_count > 0 else 0.0
    
    # Compute enhanced metrics
    ece, _ = compute_confidence_calibration(results)
    hallucination_rate, _ = detect_hallucinations(results)
    per_cwe = compute_per_cwe_metrics(results)
    
    # Phase 1.1: New enhanced metrics
    auc_roc, _ = compute_auc_roc(results)
    tool_contribution = compute_tool_contribution_enhanced(results)
    
    return Metrics(
        approach=approach,
        total_samples=total,
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        not_enough_evidence=nee,
        errors=errors,
        precision=precision,
        recall=recall,
        f1_score=f1,
        accuracy=accuracy,
        avg_duration=total_duration / total if total > 0 else 0.0,
        evidence_backed_rate=evidence_rate,
        avg_confidence=avg_confidence,
        confidence_calibration_error=ece,
        hallucination_rate=hallucination_rate,
        per_cwe_metrics=per_cwe,
        auc_roc=auc_roc,
        tool_contribution=tool_contribution,
    )


def print_confusion_matrix(metrics: Metrics, approach: str):
    """Print a confusion matrix for the approach."""
    print(f"\nConfusion Matrix ({approach}):")
    print("                  Predicted")
    print("                  VULN    SAFE")
    print(f"Actual  VULN      {metrics.true_positives:4d}    {metrics.false_negatives:4d}")
    print(f"        SAFE      {metrics.false_positives:4d}    {metrics.true_negatives:4d}")


def analyze_results(results_path: Path, output_path: Path | None = None, verbose: bool = False) -> dict:
    """
    Analyze experiment results and generate comprehensive report.
    
    Args:
        results_path: Path to combined results JSON
        output_path: Optional path to save report
        verbose: If True, print detailed error analysis
    """
    with open(results_path, "r") as f:
        data = json.load(f)
    
    all_metrics = {}
    all_errors = {}
    all_hallucinations = {}
    all_calibration = {}
    
    print("\n" + "="*70)
    print("EXPERIMENT RESULTS ANALYSIS (Enhanced)")
    print("="*70)
    print(f"\nDataset: {data['dataset_info']['source']}")
    print(f"Total samples: {data['dataset_info']['total_samples']}")
    print(f"Vulnerable: {data['dataset_info']['vulnerable_count']}")
    print(f"Safe: {data['dataset_info']['safe_count']}")
    
    if "per_cwe_stats" in data["dataset_info"]:
        print("\nPer-CWE Distribution:")
        for cwe, stats in data["dataset_info"]["per_cwe_stats"].items():
            print(f"  {cwe}: {stats.get('vulnerable', 0)} vuln, {stats.get('safe', 0)} safe")
    
    for approach, results in data["results"].items():
        metrics = compute_metrics(results, approach)
        all_metrics[approach] = metrics
        
        # Compute additional analysis
        ece, calibration_bins = compute_confidence_calibration(results)
        hallucination_rate, hallucination_details = detect_hallucinations(results)
        error_analysis = analyze_errors(results)
        tool_coverage = compute_tool_coverage(results)
        
        all_errors[approach] = error_analysis
        all_hallucinations[approach] = hallucination_details
        all_calibration[approach] = calibration_bins
        
        print(f"\n{'-'*50}")
        print(f"Approach: {approach.upper()}")
        print(f"{'-'*50}")
        
        print("\n📊 Core Metrics:")
        print(f"  Precision:       {metrics.precision:.3f}")
        print(f"  Recall:          {metrics.recall:.3f}")
        print(f"  F1 Score:        {metrics.f1_score:.3f}")
        print(f"  Accuracy:        {metrics.accuracy:.3f}")
        
        print("\n📈 Classification Results:")
        print(f"  True Positives:  {metrics.true_positives}")
        print(f"  True Negatives:  {metrics.true_negatives}")
        print(f"  False Positives: {metrics.false_positives}")
        print(f"  False Negatives: {metrics.false_negatives}")
        print(f"  Not Enough Ev:   {metrics.not_enough_evidence}")
        print(f"  Errors:          {metrics.errors}")
        
        print_confusion_matrix(metrics, approach)
        
        if approach == "mcp_based":
            print("\n🔍 Quality Metrics (MCP-specific):")
            print(f"  Evidence-backed Rate:      {metrics.evidence_backed_rate:.1%}")
            print(f"  Avg Confidence:            {metrics.avg_confidence:.3f}")
            print(f"  Calibration Error (ECE):   {metrics.confidence_calibration_error:.3f}")
            print(f"  Hallucination Rate:        {hallucination_rate:.1%}")
            
            if metrics.per_cwe_metrics:
                print("\n📋 Per-CWE Performance:")
                for cwe, cwe_metrics in metrics.per_cwe_metrics.items():
                    print(f"  {cwe}:")
                    print(f"    F1: {cwe_metrics['f1_score']:.3f}, "
                          f"Prec: {cwe_metrics['precision']:.3f}, "
                          f"Rec: {cwe_metrics['recall']:.3f}")
            
            if verbose and hallucination_details:
                print("\n⚠️ Potential Hallucinations:")
                for h in hallucination_details[:5]:
                    print(f"  - {h['sample_id']}: {h['flags']}")
        
        print(f"\n⏱️  Avg Duration: {metrics.avg_duration:.2f}s")
        
        if verbose:
            print("\n🔴 Error Analysis:")
            print(f"  FP patterns: {error_analysis['error_patterns']}")
    
    # Comparison summary
    print(f"\n{'='*70}")
    print("COMPARISON SUMMARY")
    print("="*70)
    
    headers = ["Metric", "Static-only", "LLM-only", "MCP-based"]
    default_metric = Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    rows = [
        ["Precision", 
         f"{all_metrics.get('static_only', default_metric).precision:.3f}",
         f"{all_metrics.get('llm_only', default_metric).precision:.3f}",
         f"{all_metrics.get('mcp_based', default_metric).precision:.3f}"],
        ["Recall",
         f"{all_metrics.get('static_only', default_metric).recall:.3f}",
         f"{all_metrics.get('llm_only', default_metric).recall:.3f}",
         f"{all_metrics.get('mcp_based', default_metric).recall:.3f}"],
        ["F1 Score",
         f"{all_metrics.get('static_only', default_metric).f1_score:.3f}",
         f"{all_metrics.get('llm_only', default_metric).f1_score:.3f}",
         f"{all_metrics.get('mcp_based', default_metric).f1_score:.3f}"],
        ["Accuracy",
         f"{all_metrics.get('static_only', default_metric).accuracy:.3f}",
         f"{all_metrics.get('llm_only', default_metric).accuracy:.3f}",
         f"{all_metrics.get('mcp_based', default_metric).accuracy:.3f}"],
    ]
    
    # Print table
    col_widths = [max(len(row[i]) for row in [headers] + rows) + 2 for i in range(4)]
    
    header_line = "|".join(h.center(w) for h, w in zip(headers, col_widths))
    separator = "+".join("-" * w for w in col_widths)
    
    print(separator)
    print(header_line)
    print(separator)
    for row in rows:
        print("|".join(c.center(w) for c, w in zip(row, col_widths)))
    print(separator)
    
    # Phase 1.1: Add AUC-ROC to comparison
    print("\n📈 AUC-ROC Scores:")
    for approach_name, metrics in all_metrics.items():
        print(f"  {approach_name}: {metrics.auc_roc:.3f}")
    
    # MCP-specific metrics comparison
    if "mcp_based" in all_metrics:
        mcp = all_metrics["mcp_based"]
        print(f"\n📊 MCP-Based Quality Assessment:")
        print(f"  Evidence Backing:    {mcp.evidence_backed_rate:.1%}")
        print(f"  Confidence Accuracy: {1 - mcp.confidence_calibration_error:.1%}")
        print(f"  Hallucination-Free:  {1 - mcp.hallucination_rate:.1%}")
        print(f"  AUC-ROC:             {mcp.auc_roc:.3f}")
        
        # Phase 1.1: Tool contribution analysis
        if mcp.tool_contribution:
            print("\n🔧 Tool Contribution Analysis:")
            sorted_tools = sorted(
                mcp.tool_contribution.items(),
                key=lambda x: x[1].get("contribution_score", 0),
                reverse=True
            )
            for tool_name, contrib in sorted_tools:
                if contrib.get("total_used", 0) > 0:
                    print(f"  {tool_name}:")
                    print(f"    Usage Rate:        {contrib['usage_rate']:.1%}")
                    print(f"    Accuracy (used):   {contrib['accuracy_when_used']:.1%}")
                    print(f"    Contribution:      {contrib['contribution_score']:+.2f}")
    
    # Phase 1.1: Statistical significance tests
    print(f"\n{'='*70}")
    print("STATISTICAL SIGNIFICANCE TESTS (McNemar)")
    print("="*70)
    
    approaches_list = list(data["results"].keys())
    for i, approach1 in enumerate(approaches_list):
        for approach2 in approaches_list[i+1:]:
            result = mcnemar_test(
                data["results"][approach1],
                data["results"][approach2]
            )
            sig_marker = "✓" if result.get("statistically_significant") else "✗"
            better = result.get("better_approach", "")
            better_name = approach1 if better == "approach1" else (approach2 if better == "approach2" else "N/A")
            
            print(f"\n{approach1} vs {approach2}:")
            print(f"  Chi² Statistic: {result.get('chi2_statistic', 0):.3f}")
            print(f"  p-value: {result.get('p_value', 'N/A')}")
            print(f"  Significant: {sig_marker}")
            if result.get("statistically_significant"):
                print(f"  Better approach: {better_name}")
    
    # Generate report
    report = {
        "timestamp": data.get("timestamp", ""),
        "dataset_info": data["dataset_info"],
        "metrics": {k: vars(v) for k, v in all_metrics.items()},
        "error_analysis": all_errors,
        "hallucination_analysis": {k: v for k, v in all_hallucinations.items()},
        "confidence_calibration": all_calibration,
        "statistical_tests": {},  # Will be populated below
    }
    
    # Add statistical tests to report
    for i, approach1 in enumerate(approaches_list):
        for approach2 in approaches_list[i+1:]:
            test_result = mcnemar_test(
                data["results"][approach1],
                data["results"][approach2]
            )
            report["statistical_tests"][f"{approach1}_vs_{approach2}"] = test_result
    
    if output_path:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n✅ Report saved to {output_path}")
    
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Analyze experiment results with enhanced metrics"
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to combined results JSON"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path for report JSON"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed error and hallucination analysis"
    )
    
    args = parser.parse_args()
    
    if not args.input.exists():
        print(f"Results file not found: {args.input}")
        return
    
    analyze_results(args.input, args.output, args.verbose)


if __name__ == "__main__":
    main()
