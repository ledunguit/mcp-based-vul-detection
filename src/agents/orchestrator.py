"""Orchestrator Agent - LLM-based analysis coordinator.

The Orchestrator:
1. Receives source code input
2. Calls MCP tools to gather evidence
3. Aggregates findings into a hypothesis
4. Passes hypothesis + evidence to the Judge

Key Rule: The LLM MUST NOT analyze code directly.
All conclusions must be based on tool outputs.
"""

import json
from typing import Any

from src.config import MAX_TOKENS, TEMPERATURE
from src.llm_client import LLMClient
from src.schemas import (
    Verdict,
    Evidence,
    OrchestratorHypothesis,
)
from src.mcp_servers.ast_server import ast_analyze_tool
from src.mcp_servers.static_analysis_server import static_analyze_tool
from src.mcp_servers.cwe_knowledge_server import cwe_lookup_tool


ORCHESTRATOR_SYSTEM_PROMPT = """You are a security analysis orchestrator. Your role is to coordinate vulnerability analysis using specialized tools.

CRITICAL RULES:
1. You MUST NOT analyze code directly - you can only see tool outputs
2. Every conclusion MUST cite a specific tool output
3. If tools provide insufficient evidence, say so honestly

AVAILABLE TOOLS:
- ast_analyze: Parse C code, identify risky function calls (sinks)
- static_analyze: Run Clang static analyzer for security issues
- cwe_lookup: Get CWE-120 rules and required safety checks for specific functions

WORKFLOW:
1. First, call ast_analyze to identify the code structure and risky sinks
2. If risky sinks are found, call static_analyze for deeper analysis
3. For each risky sink, call cwe_lookup to get required safety checks
4. Aggregate all findings with explicit tool citations

OUTPUT FORMAT (JSON):
{
  "hypothesis": "VULNERABLE" | "SAFE" | "NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "evidence": [
    {"tool": "tool_name", "finding": "what was found", "citation": "exact quote from tool output"}
  ],
  "reasoning": "explanation citing tool outputs"
}"""


# Define tools for LLM
TOOLS = [
    {
        "name": "ast_analyze",
        "description": "Parse C source code and extract structural information including function calls, parameters, local variables, and risky sinks (memcpy, strcpy, etc).",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "The C source code to analyze"
                }
            },
            "required": ["source_code"]
        }
    },
    {
        "name": "static_analyze",
        "description": "Run Clang Static Analyzer on C code to detect security issues including buffer overflows, insecure API usage, and taint propagation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "The C source code to analyze"
                },
                "context": {
                    "type": "string",
                    "description": "Optional surrounding code for context"
                }
            },
            "required": ["source_code"]
        }
    },
    {
        "name": "cwe_lookup",
        "description": "Look up CWE-120 (Buffer Overflow) knowledge for a specific sink function. Returns required safety checks, common vulnerability patterns, and examples.",
        "input_schema": {
            "type": "object",
            "properties": {
                "sink_function": {
                    "type": "string",
                    "description": "Name of the sink function to look up (e.g., memcpy, strcpy)"
                },
                "query_type": {
                    "type": "string",
                    "enum": ["safety_checks", "vulnerability_pattern", "description"],
                    "description": "Type of information to retrieve"
                }
            },
            "required": ["sink_function"]
        }
    }
]


def _execute_tool(tool_name: str, tool_input: dict) -> dict:
    """Execute an MCP tool and return the result."""
    if tool_name == "ast_analyze":
        return ast_analyze_tool(tool_input["source_code"])
    elif tool_name == "static_analyze":
        return static_analyze_tool(
            tool_input["source_code"],
            tool_input.get("context"),
        )
    elif tool_name == "cwe_lookup":
        return cwe_lookup_tool(
            tool_input["sink_function"],
            tool_input.get("query_type", "safety_checks"),
        )
    else:
        return {"error": f"Unknown tool: {tool_name}"}


class OrchestratorAgent:
    """LLM-based orchestrator for vulnerability analysis."""
    
    def __init__(self, provider: str | None = None):
        self.client = LLMClient(provider=provider)
        self.tool_calls: list[dict] = []
        self.tool_results: dict[str, Any] = {}
    
    def analyze(self, source_code: str) -> tuple[OrchestratorHypothesis, dict]:
        """
        Analyze source code using MCP tools and produce a hypothesis.
        
        Args:
            source_code: C source code to analyze
            
        Returns:
            Tuple of (hypothesis, tool_outputs dict)
        """
        self.tool_calls = []
        self.tool_results = {}
        
        messages = [
            {
                "role": "user",
                "content": f"""Analyze the following C function for CWE-120 (Buffer Overflow) vulnerabilities.

Use the available tools to gather evidence. Do NOT try to analyze the code directly.

SOURCE CODE:
```c
{source_code}
```

After using tools, provide your hypothesis in the specified JSON format."""
            }
        ]
        
        # Run the agentic loop
        max_iterations = 10
        for _ in range(max_iterations):
            response = self.client.chat(
                messages=messages,
                system=ORCHESTRATOR_SYSTEM_PROMPT,
                tools=TOOLS,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
            )
            
            if response.has_tool_calls:
                # Process each tool call
                tool_results_for_message = []
                
                for tc in response.tool_calls:
                    tool_name = tc["name"]
                    tool_input = tc["arguments"]
                    tool_id = tc["id"]
                    
                    # Execute the tool
                    result = _execute_tool(tool_name, tool_input)
                    
                    # Track the call
                    self.tool_calls.append({
                        "tool": tool_name,
                        "input": tool_input,
                        "output": result,
                    })
                    self.tool_results[tool_name] = result
                    
                    tool_results_for_message.append({
                        "tool_id": tool_id,
                        "name": tool_name,
                        "content": json.dumps(result, indent=2),
                    })
                
                # Add tool results to conversation
                messages = self.client.add_tool_results(
                    messages,
                    response.raw_response.content if hasattr(response.raw_response, 'content') else None,
                    tool_results_for_message,
                )
            else:
                # Response is complete, extract the hypothesis
                hypothesis = self._extract_hypothesis(response.text)
                return hypothesis, self.tool_results
        
        # Fallback if max iterations reached
        return OrchestratorHypothesis(
            hypothesis=Verdict.NOT_ENOUGH_EVIDENCE,
            confidence=0.0,
            evidence=[],
            reasoning="Max iterations reached without completing analysis",
        ), self.tool_results
    
    def _extract_hypothesis(self, text: str) -> OrchestratorHypothesis:
        """Extract the hypothesis from LLM response text."""
        try:
            json_start = text.find("{")
            json_end = text.rfind("}") + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = text[json_start:json_end]
                data = json.loads(json_str)
                
                verdict_str = data.get("hypothesis", "NOT_ENOUGH_EVIDENCE").upper()
                if verdict_str not in ["VULNERABLE", "SAFE", "NOT_ENOUGH_EVIDENCE"]:
                    verdict_str = "NOT_ENOUGH_EVIDENCE"
                
                evidence = []
                for e in data.get("evidence", []):
                    evidence.append(Evidence(
                        tool=e.get("tool", "unknown"),
                        finding=e.get("finding", ""),
                        citation=e.get("citation", ""),
                    ))
                
                return OrchestratorHypothesis(
                    hypothesis=Verdict(verdict_str),
                    confidence=float(data.get("confidence", 0.5)),
                    evidence=evidence,
                    reasoning=data.get("reasoning", text),
                )
        except (json.JSONDecodeError, ValueError, KeyError):
            pass
        
        return OrchestratorHypothesis(
            hypothesis=Verdict.NOT_ENOUGH_EVIDENCE,
            confidence=0.0,
            evidence=[],
            reasoning=f"Failed to parse response: {text[:500]}",
        )
    
    def get_tool_calls(self) -> list[dict]:
        """Get the list of tool calls made during analysis."""
        return self.tool_calls
