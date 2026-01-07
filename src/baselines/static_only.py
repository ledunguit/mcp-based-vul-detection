"""Static-only baseline - Uses Clang Static Analyzer directly.

This baseline runs only the static analysis tool without LLM involvement.
The verdict is based solely on whether the analyzer reports any findings.
"""

from src.schemas import Verdict, AnalysisResult, StaticAnalysisOutput
from src.mcp_servers.static_analysis_server import static_analyze_tool


def analyze_static_only(source_code: str, function_name: str = "unknown") -> AnalysisResult:
    """
    Analyze code using only static analysis.
    
    Decision rule:
    - VULNERABLE: Any security-related finding is reported
    - SAFE: No findings
    """
    # Run static analysis
    result = static_analyze_tool(source_code)
    static_output = StaticAnalysisOutput(**result)
    
    # Determine verdict based on findings
    if not static_output.analysis_successful:
        verdict = Verdict.NOT_ENOUGH_EVIDENCE
    elif static_output.findings:
        # Any finding = vulnerable
        verdict = Verdict.VULNERABLE
    else:
        verdict = Verdict.SAFE
    
    return AnalysisResult(
        function_name=function_name,
        source_code=source_code,
        static_output=static_output,
        final_verdict=verdict,
    )
