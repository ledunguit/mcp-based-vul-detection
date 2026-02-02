"""Judge Agent - LLM-based verdict validator.

The Judge:
1. Receives the Orchestrator's hypothesis and evidence
2. Validates each claim against the evidence
3. Applies strict decision rules
4. Produces the final verdict

Key Rule: The Judge MUST reject any claim not supported by tool evidence.
"""

import json
import re
from typing import Optional

from src.config import MAX_TOKENS, TEMPERATURE
from src.llm_client import LLMClient
from src.schemas import (
    Verdict,
    OrchestratorHypothesis,
    JudgeVerdict,
    JudgeValidation,
    ValidationCheck,
)


JUDGE_SYSTEM_PROMPT = """You are a security validation judge. Verify hypotheses against tool evidence only.

DECISION CRITERIA (All 3 required for VULNERABLE):
1. DANGEROUS SINK - AST shows risky function (strcpy, memcpy, gets, sprintf, scanf, recv)
2. DATA FLOW - External input reaches the sink (parameter, stdin, network)
3. MISSING CHECKS - No bounds validation before sink call

SAFE PATTERNS (Do NOT flag as VULNERABLE):
| Pattern | Why Safe |
|---------|----------|
| strncpy(dest, src, sizeof(dest)-1) + null term | Bounded copy |
| snprintf(buf, sizeof(buf), ...) | Always bounds output |
| fgets(buf, sizeof(buf), stream) | Limits input size |
| scanf("%31s", buf) | Width specifier limits input |
| memcpy with if(len <= sizeof(dest)) | Pre-validated length |

VERDICT RULES:
- VULNERABLE: All 3 conditions confirmed by evidence
- SAFE: Evidence shows proper bounds checking
- NOT_ENOUGH_EVIDENCE: Cannot confirm conditions

EVIDENCE QUALITY:
- Strong: Multiple tools confirm
- Medium: Single tool, clear evidence
- Weak: Requires inference

=== CHAIN OF THOUGHT REASONING ===
Before providing your verdict, reason through each condition step by step:

STEP 1 - DANGEROUS SINK CHECK:
- What does ast_analyze show in risky_sinks?
- Quote the exact function name, line, and arguments
- Is this an inherently dangerous function (gets, unbounded scanf)?

STEP 2 - DATA FLOW CHECK:
- What are the taint sources in the evidence?
- Does taint_analyze show a path from source to sink?
- Which sink arguments receive external data?

STEP 3 - MISSING CHECKS EVALUATION:
- What safety checks does cwe_lookup require?
- Are any of these checks present in the code?
- Did static_analyze flag any issues?

STEP 4 - VERDICT DETERMINATION:
- Are ALL 3 conditions met with evidence?
- Does the orchestrator's hypothesis match the evidence?
- Are there any hallucinations (claims without evidence)?

After reasoning through these steps, provide your final verdict.
=== END CHAIN OF THOUGHT ===

OUTPUT FORMAT:
```json
{
  "chain_of_thought": {
    "step1_sink": "What sink evidence shows",
    "step2_flow": "What data flow evidence shows",
    "step3_checks": "What safety check evidence shows",
    "step4_verdict": "How evidence supports verdict"
  },
  "verdict": "VULNERABLE|SAFE|NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "validation": {
    "dangerous_sink": {"present": bool, "citation": "tool output", "confidence": "strong|medium|weak"},
    "data_flow": {"present": bool, "citation": "tool output", "confidence": "strong|medium|weak"},
    "missing_checks": {"present": bool, "citation": "tool output", "confidence": "strong|medium|weak"}
  },
  "final_reasoning": "explanation with tool citations",
  "evidence_quality": "strong|medium|weak",
  "hallucination_flags": ["claims not supported by evidence"]
}
```

EXAMPLE with Chain of Thought:

Hypothesis: VULNERABLE (strcpy without bounds)
Evidence: risky_sinks:[{function:strcpy,args:[buffer,input]}], parameters:[{name:input,type:char*}]

Chain of Thought:
- Step 1: AST shows strcpy at risky_sinks with args [buffer, input]. Not inherently dangerous but risky.
- Step 2: input is char* parameter = taint source. Flows directly to strcpy second arg.
- Step 3: cwe_lookup requires strlen check. No strlen in function_calls before strcpy.
- Step 4: All 3 conditions met. Hypothesis matches evidence. No hallucinations.

Output: {"chain_of_thought":{"step1_sink":"strcpy found in risky_sinks","step2_flow":"input parameter flows to strcpy","step3_checks":"No strlen check before strcpy","step4_verdict":"All conditions met, VULNERABLE confirmed"},"verdict":"VULNERABLE","confidence":0.92,"validation":{"dangerous_sink":{"present":true,"citation":"risky_sinks:[strcpy]","confidence":"strong"},"data_flow":{"present":true,"citation":"parameters:[input:char*]","confidence":"strong"},"missing_checks":{"present":true,"citation":"no strlen before strcpy","confidence":"medium"}},"final_reasoning":"strcpy receives unbounded input without length check","evidence_quality":"strong","hallucination_flags":[]}
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
    
    def _extract_json_robust(self, text: str) -> Optional[dict]:
        """Extract JSON from LLM response with multiple strategies."""

        # Strategy 1: Look for markdown code blocks
        code_block_pattern = r"```(?:json)?\s*(\{[\s\S]*?\})\s*```"
        matches = re.findall(code_block_pattern, text)
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue

        # Strategy 2: Find balanced braces
        def find_balanced_json(s: str) -> Optional[str]:
            depth = 0
            start = None
            for i, c in enumerate(s):
                if c == '{':
                    if depth == 0:
                        start = i
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0 and start is not None:
                        return s[start:i+1]
            return None

        json_str = find_balanced_json(text)
        if json_str:
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

            # Strategy 3: Try to fix common issues
            # Remove trailing commas, fix quotes
            fixed = re.sub(r',\s*}', '}', json_str)
            fixed = re.sub(r',\s*]', ']', fixed)
            try:
                return json.loads(fixed)
            except json.JSONDecodeError:
                pass

        return None

    def _extract_verdict(self, text: str) -> JudgeVerdict:
        """Extract the verdict from LLM response text."""
        try:
            # Use robust JSON extraction
            data = self._extract_json_robust(text)

            if data:
                
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
