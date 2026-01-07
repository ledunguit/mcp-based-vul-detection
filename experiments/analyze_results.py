"""Analyze experiment results and compute metrics.

This script computes:
- Precision, Recall, F1 for each approach
- Evidence-backed decision rate (for MCP approach)
- Comparison summary
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass


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


def compute_metrics(results: list[dict], approach: str) -> Metrics:
    """Compute metrics for a set of results."""
    tp = tn = fp = fn = nee = errors = 0
    total_duration = 0.0
    evidence_backed = 0
    
    for r in results:
        verdict = r["predicted_verdict"]
        ground_truth = r["ground_truth"]
        total_duration += r["duration_seconds"]
        
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
    )


def analyze_results(results_path: Path, output_path: Path | None = None) -> dict:
    """
    Analyze experiment results and generate report.
    
    Args:
        results_path: Path to combined results JSON
        output_path: Optional path to save report
    """
    with open(results_path, "r") as f:
        data = json.load(f)
    
    all_metrics = {}
    
    print("\n" + "="*60)
    print("EXPERIMENT RESULTS ANALYSIS")
    print("="*60)
    print(f"\nDataset: {data['dataset_info']['source']}")
    print(f"Total samples: {data['dataset_info']['total_samples']}")
    print(f"Vulnerable: {data['dataset_info']['vulnerable_count']}")
    print(f"Safe: {data['dataset_info']['safe_count']}")
    
    for approach, results in data["results"].items():
        metrics = compute_metrics(results, approach)
        all_metrics[approach] = metrics
        
        print(f"\n{'-'*40}")
        print(f"Approach: {approach.upper()}")
        print(f"{'-'*40}")
        print(f"  Precision:  {metrics.precision:.3f}")
        print(f"  Recall:     {metrics.recall:.3f}")
        print(f"  F1 Score:   {metrics.f1_score:.3f}")
        print(f"  Accuracy:   {metrics.accuracy:.3f}")
        print(f"")
        print(f"  True Positives:  {metrics.true_positives}")
        print(f"  True Negatives:  {metrics.true_negatives}")
        print(f"  False Positives: {metrics.false_positives}")
        print(f"  False Negatives: {metrics.false_negatives}")
        print(f"  Not Enough Ev:   {metrics.not_enough_evidence}")
        print(f"  Errors:          {metrics.errors}")
        print(f"")
        print(f"  Avg Duration:    {metrics.avg_duration:.2f}s")
        
        if approach == "mcp_based":
            print(f"  Evidence-backed: {metrics.evidence_backed_rate:.1%}")
    
    # Comparison summary
    print(f"\n{'='*60}")
    print("COMPARISON SUMMARY")
    print("="*60)
    
    headers = ["Metric", "Static-only", "LLM-only", "MCP-based"]
    rows = [
        ["Precision", 
         f"{all_metrics.get('static_only', Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).precision:.3f}",
         f"{all_metrics.get('llm_only', Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).precision:.3f}",
         f"{all_metrics.get('mcp_based', Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).precision:.3f}"],
        ["Recall",
         f"{all_metrics.get('static_only', Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).recall:.3f}",
         f"{all_metrics.get('llm_only', Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).recall:.3f}",
         f"{all_metrics.get('mcp_based', Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).recall:.3f}"],
        ["F1 Score",
         f"{all_metrics.get('static_only', Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).f1_score:.3f}",
         f"{all_metrics.get('llm_only', Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).f1_score:.3f}",
         f"{all_metrics.get('mcp_based', Metrics('', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).f1_score:.3f}"],
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
    
    # Generate report
    report = {
        "timestamp": data["timestamp"],
        "dataset_info": data["dataset_info"],
        "metrics": {k: vars(v) for k, v in all_metrics.items()},
    }
    
    if output_path:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to {output_path}")
    
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Analyze experiment results"
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
    
    args = parser.parse_args()
    
    if not args.input.exists():
        print(f"Results file not found: {args.input}")
        return
    
    analyze_results(args.input, args.output)


if __name__ == "__main__":
    main()
