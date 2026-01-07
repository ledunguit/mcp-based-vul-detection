"""Judge Agent - LLM-based verdict validator.

The Judge:
1. Receives the Orchestrator's hypothesis and evidence
2. Validates each claim against the evidence
3. Applies strict decision rules
4. Produces the final verdict

Key Rule: The Judge MUST reject any claim not supported by tool evidence.
"""

import json

from src.config import MAX_TOKENS, TEMPERATURE
from src.llm_client import LLMClient
from src.schemas import (
    Verdict,
    OrchestratorHypothesis,
    JudgeVerdict,
    JudgeValidation,
    ValidationCheck,
)


JUDGE_SYSTEM_PROMPT = """You are a security validation judge. Your role is to verify a security hypothesis against provided evidence from multiple tools.

AVAILABLE EVIDENCE SOURCES:
1. AST_ANALYZE: Identifies code structure, risky function calls (sinks), parameters, local variables
2. STATIC_ANALYZE: Clang static analyzer findings (may be empty for small code snippets)
3. CWE_LOOKUP: CWE-120 rules, required safety checks for specific functions

DECISION CRITERIA for CWE-120 (Buffer Overflow):
A VULNERABLE verdict requires evidence for ALL of these conditions:

1. DANGEROUS SINK EXISTS
   - Evidence: AST shows risky_sinks (strcpy, memcpy, gets, sprintf, etc)

2. DATA FLOW TO SINK
   - Evidence: AST shows function parameters or external input reaching the sink
   - Can infer from: parameter types (char*), sink arguments matching parameter names

3. MISSING SAFETY CHECKS
   - PRIMARY: Static analyzer reports security findings
   - ALTERNATIVE (if static analyzer is empty): 
     * AST shows no bounds checking before sink call
     * CWE_LOOKUP specifies required checks that are absent in AST
     * Example: strcpy without prior strlen() or size comparison

IMPORTANT: Static analyzer may not find issues in small code snippets. 
Use AST + CWE knowledge as alternative evidence when static_analyze findings are empty.

FINAL VERDICT RULES:
- VULNERABLE: All 3 conditions have supporting evidence (from any tool combination)
- SAFE: Evidence shows proper bounds checking exists (strncpy with size, if-check before copy, etc)
- NOT_ENOUGH_EVIDENCE: Cannot determine one or more conditions

OUTPUT FORMAT (JSON):
{
  "verdict": "VULNERABLE" | "SAFE" | "NOT_ENOUGH_EVIDENCE",
  "validation": {
    "dangerous_sink": {"present": true/false, "citation": "evidence quote"},
    "data_flow": {"present": true/false, "citation": "evidence quote"},
    "missing_checks": {"present": true/false, "citation": "evidence quote"}
  },
  "final_reasoning": "explanation citing specific tool outputs"
}"""


class JudgeAgent:
    """LLM-based judge for validating vulnerability hypotheses."""
    
    def __init__(self, provider: str | None = None):
        self.client = LLMClient(provider=provider)
    
    def validate(
        self,
        hypothesis: OrchestratorHypothesis,
        tool_outputs: dict,
        source_code: str,
    ) -> JudgeVerdict:
        """
        Validate the orchestrator's hypothesis against the evidence.
        
        Args:
            hypothesis: The orchestrator's hypothesis
            tool_outputs: Raw outputs from MCP tools
            source_code: The original source code (for reference only)
            
        Returns:
            JudgeVerdict with validation results
        """
        evidence_text = self._format_evidence(hypothesis, tool_outputs)
        
        messages = [
            {
                "role": "user",
                "content": f"""Validate the following security hypothesis against the provided evidence.

HYPOTHESIS:
- Verdict: {hypothesis.hypothesis.value}
- Confidence: {hypothesis.confidence}
- Reasoning: {hypothesis.reasoning}

EVIDENCE FROM TOOLS:
{evidence_text}

CLAIMED EVIDENCE CHAIN:
{self._format_evidence_chain(hypothesis.evidence)}

Validate each required condition and provide your verdict in the specified JSON format.
Remember: You can ONLY use the tool evidence above. Do NOT analyze the code yourself."""
            }
        ]
        
        response = self.client.chat(
            messages=messages,
            system=JUDGE_SYSTEM_PROMPT,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        
        return self._extract_verdict(response.text)
    
    def _format_evidence(
        self,
        hypothesis: OrchestratorHypothesis,
        tool_outputs: dict,
    ) -> str:
        """Format tool outputs for the judge."""
        parts = []
        
        for tool_name, output in tool_outputs.items():
            parts.append(f"=== {tool_name.upper()} OUTPUT ===")
            parts.append(json.dumps(output, indent=2))
            parts.append("")
        
        return "\n".join(parts)
    
    def _format_evidence_chain(self, evidence: list) -> str:
        """Format the orchestrator's evidence chain."""
        if not evidence:
            return "No evidence provided."
        
        parts = []
        for i, e in enumerate(evidence, 1):
            parts.append(f"{i}. [{e.tool}] {e.finding}")
            parts.append(f"   Citation: {e.citation}")
        
        return "\n".join(parts)
    
    def _extract_verdict(self, text: str) -> JudgeVerdict:
        """Extract the verdict from LLM response text."""
        try:
            json_start = text.find("{")
            json_end = text.rfind("}") + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = text[json_start:json_end]
                data = json.loads(json_str)
                
                verdict_str = data.get("verdict", "NOT_ENOUGH_EVIDENCE").upper()
                if verdict_str not in ["VULNERABLE", "SAFE", "NOT_ENOUGH_EVIDENCE"]:
                    verdict_str = "NOT_ENOUGH_EVIDENCE"
                
                validation_data = data.get("validation", {})
                
                def parse_check(check_data: dict) -> ValidationCheck:
                    return ValidationCheck(
                        present=check_data.get("present", False),
                        citation=check_data.get("citation", "No citation provided"),
                    )
                
                validation = JudgeValidation(
                    dangerous_sink=parse_check(
                        validation_data.get("dangerous_sink", {})
                    ),
                    data_flow=parse_check(
                        validation_data.get("data_flow", {})
                    ),
                    missing_checks=parse_check(
                        validation_data.get("missing_checks", {})
                    ),
                )
                
                return JudgeVerdict(
                    verdict=Verdict(verdict_str),
                    validation=validation,
                    final_reasoning=data.get("final_reasoning", text),
                )
        except (json.JSONDecodeError, ValueError, KeyError):
            pass
        
        return JudgeVerdict(
            verdict=Verdict.NOT_ENOUGH_EVIDENCE,
            validation=JudgeValidation(
                dangerous_sink=ValidationCheck(
                    present=False,
                    citation="Failed to parse judge response",
                ),
                data_flow=ValidationCheck(
                    present=False,
                    citation="Failed to parse judge response",
                ),
                missing_checks=ValidationCheck(
                    present=False,
                    citation="Failed to parse judge response",
                ),
            ),
            final_reasoning=f"Failed to parse response: {text[:500]}",
        )
