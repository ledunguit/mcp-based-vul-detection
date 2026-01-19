"""Run experiments comparing vulnerability detection approaches.

This script runs three approaches on the dataset:
1. Static-only (Clang analyzer)
2. LLM-only (direct code analysis)
3. MCP-based (Orchestrator + Judge with tools)

Results are saved for analysis with enhanced metrics.
"""

import json
import time
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Optional

from src.schemas import Verdict, AnalysisResult
from src.pipeline import VulnerabilityPipeline
from src.baselines.static_only import analyze_static_only
from src.baselines.llm_only import analyze_llm_only


@dataclass
class SampleResult:
    """Result for a single sample with enhanced metrics."""
    sample_id: str
    function_name: str
    ground_truth: bool  # True = vulnerable
    predicted_verdict: str
    is_correct: bool
    approach: str
    duration_seconds: float
    evidence_count: int = 0
    reasoning: str = ""
    # Enhanced fields
    confidence: float = 0.0
    cwe_id: str = "CWE-120"
    sink_functions: list[str] = field(default_factory=list)
    tool_calls: int = 0
    evidence_quality: str = "unknown"  # strong, medium, weak
    hallucination_flags: list[str] = field(default_factory=list)


def run_experiment(
    dataset_path: Path,
    output_dir: Path,
    approaches: list[str] | None = None,
    verbose: bool = False,
    limit: Optional[int] = None,
) -> dict:
    """
    Run experiments on the dataset.
    
    Args:
        dataset_path: Path to the dataset JSON
        output_dir: Directory to save results
        approaches: List of approaches to run (default: all)
            - static_only: Clang analyzer only
            - llm_only: Direct LLM analysis without tools
            - mcp_based: Agentic approach (LLM decides tool calls)
            - mcp_batch: Batch approach (all tools at once, then synthesize)
        verbose: If True, print detailed output
        limit: Optional limit on number of samples to process
    """
    if approaches is None:
        approaches = ["static_only", "llm_only", "mcp_based"]
    
    # Load dataset
    with open(dataset_path, "r") as f:
        dataset = json.load(f)
    
    samples = dataset["samples"]
    
    # Apply limit if specified
    if limit and limit > 0:
        samples = samples[:limit]
    
    print(f"Loaded {len(samples)} samples")
    
    # Show dataset info
    metadata = dataset.get("metadata", {})
    print(f"Dataset: {metadata.get('source', 'Unknown')}")
    if "per_cwe_stats" in metadata:
        print("CWE Distribution:")
        for cwe, stats in metadata["per_cwe_stats"].items():
            print(f"  {cwe}: {stats.get('vulnerable', 0)} vuln, {stats.get('safe', 0)} safe")
    
    # Prepare output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    all_results = {}
    experiment_stats = {
        "start_time": datetime.now().isoformat(),
        "total_samples": len(samples),
        "approaches": approaches,
    }
    
    # Run each approach
    for approach in approaches:
        print(f"\n{'='*60}")
        print(f"Running: {approach.upper()}")
        print(f"{'='*60}")
        
        results = []
        approach_stats = {
            "total_time": 0.0,
            "successes": 0,
            "errors": 0,
        }
        
        # Initialize pipeline for MCP approaches
        pipeline = None
        if approach == "mcp_based":
            pipeline = VulnerabilityPipeline(mode="agentic")
        elif approach == "mcp_batch":
            pipeline = VulnerabilityPipeline(mode="batch")
        
        for i, sample in enumerate(samples):
            progress = f"[{i+1}/{len(samples)}]"
            func_name = sample['function_name'][:30]
            print(f"{progress} {func_name}...", end=" ", flush=True)
            
            start_time = time.time()
            
            try:
                if approach == "static_only":
                    result = analyze_static_only(
                        sample["source_code"],
                        sample["function_name"],
                    )
                elif approach == "llm_only":
                    result = analyze_llm_only(
                        sample["source_code"],
                        sample["function_name"],
                    )
                elif approach in ("mcp_based", "mcp_batch"):
                    result = pipeline.analyze(
                        sample["source_code"],
                        sample["function_name"],
                        sample["is_vulnerable"],
                        cwe_focus=sample.get("cwe_id"),
                    )
                else:
                    raise ValueError(f"Unknown approach: {approach}")
                
                duration = time.time() - start_time
                approach_stats["total_time"] += duration
                approach_stats["successes"] += 1
                
                # Determine correctness
                predicted = result.final_verdict
                ground_truth = sample["is_vulnerable"]
                
                if predicted == Verdict.VULNERABLE:
                    is_correct = ground_truth is True
                elif predicted == Verdict.SAFE:
                    is_correct = ground_truth is False
                else:  # NOT_ENOUGH_EVIDENCE
                    is_correct = False  # Count as incorrect for metrics
                
                # Extract evidence info
                evidence_count = 0
                reasoning = ""
                confidence = 0.5
                evidence_quality = "unknown"
                hallucination_flags = []
                tool_calls = 0
                
                if result.orchestrator_hypothesis:
                    evidence_count = len(result.orchestrator_hypothesis.evidence)
                    reasoning = result.orchestrator_hypothesis.reasoning[:500]
                    confidence = result.orchestrator_hypothesis.confidence
                
                if result.judge_verdict:
                    evidence_quality = getattr(result.judge_verdict, 'evidence_quality', 'unknown')
                    hallucination_flags = getattr(result.judge_verdict, 'hallucination_flags', [])
                    # Update confidence from judge if available
                    judge_confidence = getattr(result.judge_verdict, 'confidence', None)
                    if judge_confidence is not None:
                        confidence = judge_confidence
                
                sample_result = SampleResult(
                    sample_id=sample["id"],
                    function_name=sample["function_name"],
                    ground_truth=ground_truth,
                    predicted_verdict=predicted.value,
                    is_correct=is_correct,
                    approach=approach,
                    duration_seconds=duration,
                    evidence_count=evidence_count,
                    reasoning=reasoning,
                    confidence=confidence,
                    cwe_id=sample.get("cwe_id", "CWE-120"),
                    sink_functions=sample.get("sink_functions", []),
                    tool_calls=tool_calls,
                    evidence_quality=evidence_quality,
                    hallucination_flags=hallucination_flags,
                )
                
                # Print result
                status = '✓' if is_correct else '✗'
                conf_str = f"{confidence:.2f}" if approach in ("mcp_based", "mcp_batch") else ""
                print(f"{predicted.value} ({status}) [{duration:.1f}s] {conf_str}")
                
                if verbose and not is_correct:
                    print(f"    → Expected: {'VULNERABLE' if ground_truth else 'SAFE'}")
                    print(f"    → Reasoning: {reasoning[:100]}...")
                
            except Exception as e:
                duration = time.time() - start_time
                approach_stats["total_time"] += duration
                approach_stats["errors"] += 1
                
                sample_result = SampleResult(
                    sample_id=sample["id"],
                    function_name=sample["function_name"],
                    ground_truth=sample["is_vulnerable"],
                    predicted_verdict="ERROR",
                    is_correct=False,
                    approach=approach,
                    duration_seconds=duration,
                    reasoning=str(e)[:200],
                    cwe_id=sample.get("cwe_id", "CWE-120"),
                )
                print(f"ERROR: {str(e)[:50]}")
            
            results.append(sample_result)
        
        all_results[approach] = results
        
        # Print approach summary
        print(f"\n{approach} Summary:")
        correct = sum(1 for r in results if r.is_correct)
        print(f"  Accuracy: {correct}/{len(results)} ({100*correct/len(results):.1f}%)")
        print(f"  Total time: {approach_stats['total_time']:.1f}s")
        print(f"  Avg time per sample: {approach_stats['total_time']/len(results):.1f}s")
        
        # Save intermediate results
        results_file = output_dir / f"{approach}_{timestamp}.json"
        with open(results_file, "w") as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        print(f"  Results saved to {results_file}")
    
    # Save combined results
    combined_file = output_dir / f"combined_{timestamp}.json"
    combined_data = {
        "timestamp": timestamp,
        "dataset_info": dataset["metadata"],
        "experiment_stats": experiment_stats,
        "results": {k: [asdict(r) for r in v] for k, v in all_results.items()},
    }
    with open(combined_file, "w") as f:
        json.dump(combined_data, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"Combined results saved to {combined_file}")
    print(f"Run 'python experiments/analyze_results.py --input {combined_file}' for detailed analysis")
    
    return combined_data


def run_ablation_study(
    dataset_path: Path,
    output_dir: Path,
    limit: Optional[int] = None,
) -> dict:
    """
    Run ablation study to measure impact of each tool.
    
    This runs the MCP-based approach with different tool combinations
    to understand the contribution of each tool.
    """
    print("="*60)
    print("ABLATION STUDY")
    print("="*60)
    
    # This would require modifying the pipeline to disable specific tools
    # For now, just document the approach
    print("\nAblation configurations to test:")
    print("1. AST only")
    print("2. AST + CWE Knowledge")
    print("3. AST + Static Analysis")
    print("4. AST + Taint Analysis")
    print("5. All tools (baseline)")
    print("\nNote: Full ablation study requires pipeline modifications")
    
    # Run standard experiment for now
    return run_experiment(dataset_path, output_dir, ["mcp_based"], limit=limit)


def main():
    parser = argparse.ArgumentParser(
        description="Run vulnerability detection experiments"
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("data/juliet_samples/dataset.json"),
        help="Path to dataset JSON"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results"),
        help="Output directory for results"
    )
    parser.add_argument(
        "--approaches",
        nargs="+",
        choices=["static_only", "llm_only", "mcp_based", "mcp_batch"],
        default=None,
        help="Approaches to run: static_only, llm_only, mcp_based (agentic), mcp_batch (all tools at once)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed output for errors"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of samples to process (for testing)"
    )
    parser.add_argument(
        "--ablation",
        action="store_true",
        help="Run ablation study"
    )
    
    args = parser.parse_args()
    
    if not args.dataset.exists():
        print(f"Dataset not found: {args.dataset}")
        print("\nAvailable datasets:")
        data_dir = Path("data/juliet_samples")
        if data_dir.exists():
            for f in data_dir.glob("*.json"):
                print(f"  - {f}")
        print("\nRun one of these to create a dataset:")
        print("  python experiments/prepare_dataset.py --sample-only")
        print("  python experiments/extract_juliet.py --extended-samples")
        return
    
    if args.ablation:
        run_ablation_study(args.dataset, args.output, args.limit)
    else:
        run_experiment(args.dataset, args.output, args.approaches, args.verbose, args.limit)


if __name__ == "__main__":
    main()
