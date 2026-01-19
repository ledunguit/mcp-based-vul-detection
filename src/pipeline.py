"""Main analysis pipeline for MCP-Vul.

This module orchestrates the complete vulnerability detection workflow:
1. Orchestrator Agent analyzes code via MCP tools
2. Judge Agent validates the hypothesis
3. Final verdict is produced with evidence chain
"""

import json
from pathlib import Path
from typing import Optional

from src.schemas import (
    Verdict,
    AnalysisResult,
    ASTAnalysisOutput,
    StaticAnalysisOutput,
    CWEKnowledgeOutput,
)
from src.agents.orchestrator import OrchestratorAgent
from src.agents.judge import JudgeAgent


class VulnerabilityPipeline:
    """Main pipeline for vulnerability detection."""
    
    def __init__(self, mode: str = "agentic"):
        """
        Initialize the pipeline.
        
        Args:
            mode: "agentic" (LLM decides tool calls) or "batch" (all tools at once)
        """
        self.orchestrator = OrchestratorAgent()
        self.judge = JudgeAgent()
        self.mode = mode
    
    def analyze(
        self,
        source_code: str,
        function_name: Optional[str] = None,
        ground_truth: Optional[bool] = None,
        cwe_focus: Optional[str] = None,
    ) -> AnalysisResult:
        """
        Analyze a C function for vulnerabilities.
        
        Args:
            source_code: The C source code to analyze
            function_name: Optional name of the function
            ground_truth: Optional ground truth label (True=vulnerable)
            cwe_focus: Optional CWE to focus on (e.g., "CWE-121")
            
        Returns:
            AnalysisResult with complete analysis data
        """
        # Step 1: Orchestrator analyzes via MCP tools
        if self.mode == "batch":
            # Batch mode: call all tools at once, then synthesize
            hypothesis, tool_outputs = self.orchestrator.analyze_batch(source_code, cwe_focus)
        else:
            # Agentic mode: LLM decides which tools to call
            hypothesis, tool_outputs = self.orchestrator.analyze(source_code, cwe_focus)
        
        # Step 2: Judge validates the hypothesis
        verdict = self.judge.validate(hypothesis, tool_outputs, source_code)
        
        # Extract structured tool outputs
        ast_output = None
        static_output = None
        cwe_output = None
        
        if "ast_analyze" in tool_outputs:
            try:
                ast_output = ASTAnalysisOutput(**tool_outputs["ast_analyze"])
            except Exception:
                pass  # Skip if validation fails
        
        if "static_analyze" in tool_outputs:
            try:
                static_output = StaticAnalysisOutput(**tool_outputs["static_analyze"])
            except Exception:
                pass
        
        if "cwe_lookup" in tool_outputs:
            cwe_data = tool_outputs["cwe_lookup"]
            try:
                # Handle batch mode format (multiple sinks)
                if "sinks" in cwe_data and isinstance(cwe_data["sinks"], dict):
                    # Take the first sink for the structured output
                    first_sink = next(iter(cwe_data["sinks"].values()), {})
                    first_sink_name = next(iter(cwe_data["sinks"].keys()), "unknown")
                    cwe_output = CWEKnowledgeOutput(
                        sink_function=first_sink_name,
                        required_safety_checks=first_sink.get("safety_checks", []),
                        common_patterns=first_sink.get("vulnerability_patterns", []),
                        description=first_sink.get("description", ""),
                    )
                else:
                    # Standard format (single sink)
                    cwe_output = CWEKnowledgeOutput(**cwe_data)
            except Exception:
                pass
        
        # Determine function name
        if function_name is None and ast_output:
            function_name = ast_output.function_name or "unknown"
        elif function_name is None:
            function_name = "unknown"
        
        return AnalysisResult(
            function_name=function_name,
            source_code=source_code,
            ast_output=ast_output,
            static_output=static_output,
            cwe_output=cwe_output,
            orchestrator_hypothesis=hypothesis,
            judge_verdict=verdict,
            final_verdict=verdict.verdict,
            ground_truth=ground_truth,
        )


def analyze_file(file_path: str) -> AnalysisResult:
    """Analyze a C source file."""
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    source_code = path.read_text()
    
    pipeline = VulnerabilityPipeline()
    return pipeline.analyze(source_code, function_name=path.stem)


def analyze_code(source_code: str) -> AnalysisResult:
    """Analyze C source code directly."""
    pipeline = VulnerabilityPipeline()
    return pipeline.analyze(source_code)


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="MCP-Based Vulnerability Detection for C code"
    )
    parser.add_argument(
        "input",
        help="Path to C source file or '-' to read from stdin"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output"
    )
    
    args = parser.parse_args()
    
    # Read input
    if args.input == "-":
        import sys
        source_code = sys.stdin.read()
        result = analyze_code(source_code)
    else:
        result = analyze_file(args.input)
    
    # Format output
    output = {
        "function_name": result.function_name,
        "final_verdict": result.final_verdict.value,
    }
    
    if args.verbose:
        output["orchestrator_hypothesis"] = {
            "hypothesis": result.orchestrator_hypothesis.hypothesis.value,
            "confidence": result.orchestrator_hypothesis.confidence,
            "evidence": [e.model_dump() for e in result.orchestrator_hypothesis.evidence],
            "reasoning": result.orchestrator_hypothesis.reasoning,
        }
        output["judge_verdict"] = {
            "verdict": result.judge_verdict.verdict.value,
            "validation": result.judge_verdict.validation.model_dump(),
            "final_reasoning": result.judge_verdict.final_reasoning,
        }
    
    json_output = json.dumps(output, indent=2)
    
    if args.output:
        Path(args.output).write_text(json_output)
        print(f"Results written to {args.output}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
