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
3. CWE_LOOKUP: CWE rules, required safety checks for specific functions
4. TAINT_ANALYZE: Data flow tracking from sources to sinks (if available)

SUPPORTED CWE TYPES:
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow
- CWE-787: Out-of-bounds Write
- CWE-125: Out-of-bounds Read

DECISION CRITERIA (Buffer Overflow Family):
A VULNERABLE verdict requires evidence for ALL of these conditions:

1. DANGEROUS SINK EXISTS
   - Evidence: AST shows risky_sinks (strcpy, memcpy, gets, sprintf, scanf, recv, etc)
   - Citation must include: function name, line number, arguments

2. DATA FLOW TO SINK
   - Evidence: AST shows function parameters or external input reaching the sink
   - Can infer from: parameter types (char*, size_t), sink arguments matching parameter names
   - Taint analysis (if available) provides definitive evidence

3. MISSING SAFETY CHECKS
   - PRIMARY: Static analyzer reports security findings
   - ALTERNATIVE (if static analyzer is empty):
     * AST shows no bounds checking before sink call (no if-statements comparing sizes)
     * CWE_LOOKUP specifies required checks that are absent
     * Example: strcpy without prior strlen() or size comparison

IMPORTANT RULES:
- Static analyzer may not find issues in small code snippets - use AST + CWE as alternative
- NEVER make assumptions about code not shown in evidence
- Citation MUST quote actual tool output, not paraphrased versions

FINAL VERDICT RULES:
- VULNERABLE: All 3 conditions confirmed by tool evidence
- SAFE: Evidence shows proper bounds checking (strncpy with correct size, if-check before copy, size validation)
- NOT_ENOUGH_EVIDENCE: Cannot confirm one or more conditions from tool outputs

=== SAFE PATTERNS (DO NOT FLAG AS VULNERABLE) ===
These are SAFE usage patterns - do not classify as VULNERABLE:

1. strncpy(dest, src, sizeof(dest)-1) + null termination → SAFE
   - Size is bounded to dest buffer
   - Explicit null termination ensures string safety

2. memcpy(dest, src, len) with if (len <= sizeof(dest)) check → SAFE
   - Length is validated before copy

3. snprintf(buf, sizeof(buf), ...) → SAFE
   - snprintf always bounds output to given size

4. fgets(buf, sizeof(buf), stream) → SAFE
   - fgets limits input to given size

5. scanf("%31s", buf) with width specifier → SAFE
   - Width specifier limits input (31 for 32-byte buffer)

When AST shows these patterns, conclude SAFE even if the function is listed as "risky sink".

CONFIDENCE CALIBRATION:
When validating, also assess evidence quality:
- Strong: Multiple independent tools confirm the finding
- Medium: Single tool with clear, unambiguous evidence
- Weak: Evidence requires inference or is circumstantial

OUTPUT FORMAT (JSON):
{
  "verdict": "VULNERABLE" | "SAFE" | "NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "validation": {
    "dangerous_sink": {"present": true/false, "citation": "exact tool output quote", "confidence": "strong/medium/weak"},
    "data_flow": {"present": true/false, "citation": "exact tool output quote", "confidence": "strong/medium/weak"},
    "missing_checks": {"present": true/false, "citation": "exact tool output quote", "confidence": "strong/medium/weak"}
  },
  "final_reasoning": "explanation citing specific tool outputs",
  "evidence_quality": "strong/medium/weak",
  "hallucination_flags": ["list any claims from hypothesis not supported by evidence"]
}

=== FEW-SHOT EXAMPLES ===

EXAMPLE 1: VALIDATING VULNERABLE HYPOTHESIS
Hypothesis claims: VULNERABLE with evidence about strcpy
Tool outputs show: risky_sinks: [strcpy], parameters: [char* input], no bounds checks

Validation:
{
  "verdict": "VULNERABLE",
  "confidence": 0.92,
  "validation": {
    "dangerous_sink": {"present": true, "citation": "risky_sinks: [{function: strcpy, line: 3}]", "confidence": "strong"},
    "data_flow": {"present": true, "citation": "parameters: [{name: input, type: char *}], arguments: [buffer, input]", "confidence": "strong"},
    "missing_checks": {"present": true, "citation": "function_calls shows no strlen/sizeof before strcpy", "confidence": "medium"}
  },
  "final_reasoning": "AST confirms strcpy sink at line 3 receiving unbounded input parameter. No bounds checking functions called before the sink.",
  "evidence_quality": "strong",
  "hallucination_flags": []
}

EXAMPLE 2: OVERRIDING ORCHESTRATOR (False Positive Detection)
Hypothesis claims: VULNERABLE but misinterprets evidence
Tool outputs show: strncpy with sizeof(buffer)-1, explicit null termination

Validation:
{
  "verdict": "SAFE",
  "confidence": 0.88,
  "validation": {
    "dangerous_sink": {"present": true, "citation": "risky_sinks: [{function: strncpy}]", "confidence": "strong"},
    "data_flow": {"present": true, "citation": "input parameter flows to strncpy", "confidence": "strong"},
    "missing_checks": {"present": false, "citation": "strncpy uses sizeof(buf)-1, null termination at buf[31]=0", "confidence": "strong"}
  },
  "final_reasoning": "Although strncpy is flagged as risky, the code properly limits copy size and ensures null termination. CWE safety requirements are met.",
  "evidence_quality": "strong",
  "hallucination_flags": ["Orchestrator claimed missing checks but evidence shows proper bounds"]
}

=== END EXAMPLES ===
"""


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
                
                def parse_check(check_data) -> ValidationCheck:
                    # Handle case where model returns bool instead of dict
                    if isinstance(check_data, bool):
                        return ValidationCheck(
                            present=check_data,
                            citation="No citation",
                            confidence="low",
                        )
                    if not isinstance(check_data, dict):
                        return ValidationCheck(
                            present=False,
                            citation="Invalid data format",
                            confidence="low",
                        )
                    return ValidationCheck(
                        present=check_data.get("present", False),
                        citation=check_data.get("citation", "No citation provided"),
                        confidence=check_data.get("confidence", "medium"),
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
                
                # Extract confidence score
                confidence = float(data.get("confidence", 0.5))
                confidence = max(0.0, min(1.0, confidence))
                
                # Extract hallucination flags
                hallucination_flags = data.get("hallucination_flags", [])
                
                # Extract evidence quality
                evidence_quality = data.get("evidence_quality", "medium")
                
                return JudgeVerdict(
                    verdict=Verdict(verdict_str),
                    validation=validation,
                    final_reasoning=data.get("final_reasoning", text),
                    confidence=confidence,
                    evidence_quality=evidence_quality,
                    hallucination_flags=hallucination_flags,
                )
        except (json.JSONDecodeError, ValueError, KeyError):
            pass
        
        # Fallback: try to detect verdict from text
        text_upper = text.upper()
        if "VULNERABLE" in text_upper:
            detected_verdict = Verdict.VULNERABLE
        elif "SAFE" in text_upper:
            detected_verdict = Verdict.SAFE
        else:
            detected_verdict = Verdict.NOT_ENOUGH_EVIDENCE
        
        return JudgeVerdict(
            verdict=detected_verdict,
            validation=JudgeValidation(
                dangerous_sink=ValidationCheck(
                    present=False,
                    citation="Failed to parse judge response",
                    confidence="weak",
                ),
                data_flow=ValidationCheck(
                    present=False,
                    citation="Failed to parse judge response",
                    confidence="weak",
                ),
                missing_checks=ValidationCheck(
                    present=False,
                    citation="Failed to parse judge response",
                    confidence="weak",
                ),
            ),
            final_reasoning=f"Failed to parse response: {text[:500]}",
            confidence=0.3,
            evidence_quality="weak",
            hallucination_flags=["Response parsing failed"],
        )
