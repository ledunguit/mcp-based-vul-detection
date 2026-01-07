"""Run experiments comparing vulnerability detection approaches.

This script runs three approaches on the dataset:
1. Static-only (Clang analyzer)
2. LLM-only (direct code analysis)
3. MCP-based (Orchestrator + Judge with tools)

Results are saved for analysis.
"""

import json
import time
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict

from src.schemas import Verdict, AnalysisResult
from src.pipeline import VulnerabilityPipeline
from src.baselines.static_only import analyze_static_only
from src.baselines.llm_only import analyze_llm_only


@dataclass
class SampleResult:
    """Result for a single sample."""
    sample_id: str
    function_name: str
    ground_truth: bool  # True = vulnerable
    predicted_verdict: str
    is_correct: bool
    approach: str
    duration_seconds: float
    evidence_count: int = 0
    reasoning: str = ""


def run_experiment(
    dataset_path: Path,
    output_dir: Path,
    approaches: list[str] | None = None,
) -> dict:
    """
    Run experiments on the dataset.
    
    Args:
        dataset_path: Path to the dataset JSON
        output_dir: Directory to save results
        approaches: List of approaches to run (default: all)
    """
    if approaches is None:
        approaches = ["static_only", "llm_only", "mcp_based"]
    
    # Load dataset
    with open(dataset_path, "r") as f:
        dataset = json.load(f)
    
    samples = dataset["samples"]
    print(f"Loaded {len(samples)} samples")
    
    # Prepare output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    all_results = {}
    
    # Run each approach
    for approach in approaches:
        print(f"\n{'='*50}")
        print(f"Running: {approach}")
        print(f"{'='*50}")
        
        results = []
        
        # Initialize pipeline for MCP approach
        pipeline = None
        if approach == "mcp_based":
            pipeline = VulnerabilityPipeline()
        
        for i, sample in enumerate(samples):
            print(f"[{i+1}/{len(samples)}] {sample['function_name']}...", end=" ", flush=True)
            
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
                elif approach == "mcp_based":
                    result = pipeline.analyze(
                        sample["source_code"],
                        sample["function_name"],
                        sample["is_vulnerable"],
                    )
                else:
                    raise ValueError(f"Unknown approach: {approach}")
                
                duration = time.time() - start_time
                
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
                if result.orchestrator_hypothesis:
                    evidence_count = len(result.orchestrator_hypothesis.evidence)
                    reasoning = result.orchestrator_hypothesis.reasoning[:500]
                
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
                )
                
                print(f"{predicted.value} ({'✓' if is_correct else '✗'}) [{duration:.1f}s]")
                
            except Exception as e:
                duration = time.time() - start_time
                sample_result = SampleResult(
                    sample_id=sample["id"],
                    function_name=sample["function_name"],
                    ground_truth=sample["is_vulnerable"],
                    predicted_verdict="ERROR",
                    is_correct=False,
                    approach=approach,
                    duration_seconds=duration,
                    reasoning=str(e)[:200],
                )
                print(f"ERROR: {str(e)[:50]}")
            
            results.append(sample_result)
        
        all_results[approach] = results
        
        # Save intermediate results
        results_file = output_dir / f"{approach}_{timestamp}.json"
        with open(results_file, "w") as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        print(f"Results saved to {results_file}")
    
    # Save combined results
    combined_file = output_dir / f"combined_{timestamp}.json"
    combined_data = {
        "timestamp": timestamp,
        "dataset_info": dataset["metadata"],
        "results": {k: [asdict(r) for r in v] for k, v in all_results.items()},
    }
    with open(combined_file, "w") as f:
        json.dump(combined_data, f, indent=2)
    
    print(f"\nCombined results saved to {combined_file}")
    return combined_data


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
        choices=["static_only", "llm_only", "mcp_based"],
        default=None,
        help="Approaches to run (default: all)"
    )
    
    args = parser.parse_args()
    
    if not args.dataset.exists():
        print(f"Dataset not found: {args.dataset}")
        print("Run prepare_dataset.py first")
        return
    
    run_experiment(args.dataset, args.output, args.approaches)


if __name__ == "__main__":
    main()
