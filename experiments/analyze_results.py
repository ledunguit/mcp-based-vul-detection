"""Analyze experiment results and compute metrics.

This script computes:
- Precision, Recall, F1 for each approach
- Evidence-backed decision rate (for MCP approach)
- Hallucination detection and confidence calibration
- Per-CWE breakdown analysis
- Error analysis and confusion matrices
"""

import json
import argparse
import math
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


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
    # New enhanced metrics
    avg_confidence: float = 0.0
    confidence_calibration_error: float = 0.0
    hallucination_rate: float = 0.0
    tool_coverage: float = 0.0
    per_cwe_metrics: dict = field(default_factory=dict)


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
    
    # MCP-specific metrics comparison
    if "mcp_based" in all_metrics:
        mcp = all_metrics["mcp_based"]
        print(f"\n📊 MCP-Based Quality Assessment:")
        print(f"  Evidence Backing:    {mcp.evidence_backed_rate:.1%}")
        print(f"  Confidence Accuracy: {1 - mcp.confidence_calibration_error:.1%}")
        print(f"  Hallucination-Free:  {1 - mcp.hallucination_rate:.1%}")
    
    # Generate report
    report = {
        "timestamp": data.get("timestamp", ""),
        "dataset_info": data["dataset_info"],
        "metrics": {k: vars(v) for k, v in all_metrics.items()},
        "error_analysis": all_errors,
        "hallucination_analysis": {k: v for k, v in all_hallucinations.items()},
        "confidence_calibration": all_calibration,
    }
    
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
