"""LLM-only baseline - Direct code analysis without tools.

This baseline sends code directly to the LLM without any tool access.
This measures the benefit of MCP tools over pure LLM reasoning.
"""

import json

from src.llm_client import LLMClient
from src.schemas import Verdict, AnalysisResult, OrchestratorHypothesis, Evidence


LLM_ONLY_PROMPT_PREFIX = """You are a security analyst. Analyze this C code for CWE-120 (Buffer Copy without Checking Size of Input) vulnerabilities.

CWE-120 occurs when:
- A program copies data to a buffer without checking if the data fits
- Common risky functions: strcpy, memcpy, sprintf, gets, scanf without width specifier

=== CHAIN OF THOUGHT ANALYSIS ===
Before providing your verdict, think through these steps:

STEP 1 - IDENTIFY BUFFERS:
- What buffers exist in the code? (arrays, malloc'd memory)
- What are their sizes? (fixed, dynamic, unknown)

STEP 2 - IDENTIFY DATA SOURCES:
- Where does input data come from? (parameters, stdin, files, network)
- Is the input size bounded or unbounded?

STEP 3 - TRACE DATA FLOW:
- How does data move from source to buffer?
- Which functions perform the copy? (strcpy, memcpy, sprintf, etc.)

STEP 4 - CHECK FOR VALIDATION:
- Is there a size check before the copy?
- Are safe alternatives used? (strncpy with size, snprintf, fgets)
- Is null termination handled?

STEP 5 - DETERMINE VERDICT:
- If unbounded copy to fixed buffer → VULNERABLE
- If size-limited copy or validation present → SAFE
- If cannot determine sizes or flow → UNCERTAIN

=== INHERENTLY DANGEROUS (Always VULNERABLE) ===
- gets() - No size limit possible
- scanf("%s") without width - Unbounded
- sprintf with %s from external input - No bounds

Provide your analysis in JSON format:

{
  "chain_of_thought": {
    "step1_buffers": "buffers and their sizes",
    "step2_sources": "data sources identified",
    "step3_flow": "how data reaches buffers",
    "step4_validation": "what checks exist",
    "step5_verdict": "reasoning for verdict"
  },
  "verdict": "VULNERABLE|SAFE|UNCERTAIN",
  "confidence": 0.0-1.0,
  "reasoning": "summary of analysis"
}

Analyze this code:
"""

LLM_ONLY_PROMPT_SUFFIX = """

Your JSON response:"""


def analyze_llm_only(
    source_code: str,
    function_name: str = "unknown",
    provider: str | None = None,
) -> AnalysisResult:
    """
    Analyze code using only LLM without tools.
    
    Args:
        source_code: C source code to analyze
        function_name: Name of the function
        provider: LLM provider ("claude" or "local")
    
    Returns:
        AnalysisResult with the verdict
    """
    client = LLMClient(provider=provider)
    verdict = Verdict.NOT_ENOUGH_EVIDENCE
    hypothesis = None
    
    full_prompt = LLM_ONLY_PROMPT_PREFIX + source_code + LLM_ONLY_PROMPT_SUFFIX
    
    try:
        response = client.chat(
            messages=[{"role": "user", "content": full_prompt}],
            max_tokens=1024,
            temperature=0.0,
        )
        
        text_content = response.text.strip()
        
        # Clean up markdown code blocks if present
        if text_content.startswith("```"):
            lines = text_content.split("\n")
            text_content = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
        
        # Find JSON object
        start = text_content.find("{")
        end = text_content.rfind("}") + 1
        
        if start >= 0 and end > start:
            json_str = text_content[start:end]
            data = json.loads(json_str)
            
            verdict_str = str(data.get("verdict", "")).upper()
            if "VULN" in verdict_str:
                verdict = Verdict.VULNERABLE
            elif "SAFE" in verdict_str:
                verdict = Verdict.SAFE
            else:
                verdict = Verdict.NOT_ENOUGH_EVIDENCE
            
            reasoning = str(data.get("reasoning", text_content))
            confidence = float(data.get("confidence", 0.5))
            
            hypothesis = OrchestratorHypothesis(
                hypothesis=verdict,
                confidence=confidence,
                evidence=[Evidence(
                    tool="llm_direct",
                    finding="Direct LLM analysis",
                    citation=reasoning[:200],
                )],
                reasoning=reasoning,
            )
        else:
            # No JSON found, try text matching
            text_upper = text_content.upper()
            if "VULNERABLE" in text_upper:
                verdict = Verdict.VULNERABLE
            elif "SAFE" in text_upper:
                verdict = Verdict.SAFE
            
            hypothesis = OrchestratorHypothesis(
                hypothesis=verdict,
                confidence=0.5,
                evidence=[Evidence(
                    tool="llm_direct",
                    finding="Text fallback",
                    citation=text_content[:200],
                )],
                reasoning=text_content,
            )
            
    except json.JSONDecodeError as e:
        hypothesis = OrchestratorHypothesis(
            hypothesis=verdict,
            confidence=0.0,
            evidence=[],
            reasoning=f"JSON parse error: {e}",
        )
    except Exception as e:
        hypothesis = OrchestratorHypothesis(
            hypothesis=verdict,
            confidence=0.0,
            evidence=[],
            reasoning=f"Error: {type(e).__name__}: {e}",
        )
    
    if hypothesis is None:
        hypothesis = OrchestratorHypothesis(
            hypothesis=verdict,
            confidence=0.0,
            evidence=[],
            reasoning="No response",
        )
    
    return AnalysisResult(
        function_name=function_name,
        source_code=source_code,
        orchestrator_hypothesis=hypothesis,
        final_verdict=verdict,
    )
