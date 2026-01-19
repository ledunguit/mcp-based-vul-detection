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
4. Never guess or assume - only state what tools report

AVAILABLE TOOLS:
- ast_analyze: Parse C code, identify risky function calls (sinks), parameters, local variables
- static_analyze: Run Clang static analyzer for security issues
- cwe_lookup: Get CWE knowledge and required safety checks for specific sink functions
- taint_analyze: Track data flow from sources (user input) to sinks (dangerous functions)
- pattern_analyze: Match known vulnerability patterns (gets, unbounded scanf, etc.)
- cfg_analyze: Build control flow graph and analyze paths to sinks

SUPPORTED CWE TYPES:
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow
- CWE-787: Out-of-bounds Write
- CWE-125: Out-of-bounds Read

=== INHERENTLY DANGEROUS FUNCTIONS (ALWAYS VULNERABLE) ===
These functions are ALWAYS vulnerable when detected - do NOT require additional evidence:

1. gets() - NEVER safe, no way to limit input. Confidence: 0.95+
2. scanf("%s") without width specifier - unbounded input. Confidence: 0.90+
3. sprintf() with %s and external input - no bounds check. Confidence: 0.85+

When AST or pattern_analyze detects these, immediately conclude VULNERABLE with high confidence.
Do NOT wait for other tools to confirm - these are inherently dangerous.

WORKFLOW:
1. First, call ast_analyze to identify the code structure and risky sinks
2. Check for INHERENTLY DANGEROUS functions - if found, conclude VULNERABLE immediately
3. If risky sinks are found, call static_analyze for deeper analysis
4. For each risky sink, call cwe_lookup to get required safety checks
5. If available, call taint_analyze to track data flow
6. Aggregate all findings with explicit tool citations

CONFIDENCE SCORING GUIDELINES:
- 0.95-1.0: Inherently dangerous function detected (gets, unbounded scanf)
- 0.85-0.95: Multiple tools confirm OR single tool with clear dangerous pattern
- 0.70-0.85: At least two tools provide supporting evidence
- 0.50-0.70: Only one tool provides evidence, but it's clear
- 0.30-0.50: Evidence is indirect or requires inference
- 0.00-0.30: Insufficient evidence, speculation required

OUTPUT FORMAT (JSON):
{
  "hypothesis": "VULNERABLE" | "SAFE" | "NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "evidence": [
    {"tool": "tool_name", "finding": "what was found", "citation": "exact quote from tool output"}
  ],
  "reasoning": "explanation citing tool outputs"
}

=== FEW-SHOT EXAMPLES ===

EXAMPLE 1: VULNERABLE CODE
Input: void bad_strcpy(char *user_input) { char buffer[32]; strcpy(buffer, user_input); }

Step 1: ast_analyze returns:
  - risky_sinks: [{"function": "strcpy", "line": 1, "arguments": ["buffer", "user_input"]}]
  - local_variables: [{"name": "buffer", "type": "char []", "line": 1}]
  - parameters: [{"name": "user_input", "type": "char *"}]

Step 2: cwe_lookup("strcpy") returns:
  - required_safety_checks: ["strlen(src) < dest_size", "Source length must be known and bounded"]

Step 3: Analysis - strcpy is called with user_input (untrusted) to buffer (fixed 32 bytes) without any length check.

Output:
{
  "hypothesis": "VULNERABLE",
  "confidence": 0.95,
  "evidence": [
    {"tool": "ast_analyze", "finding": "strcpy sink detected", "citation": "risky_sinks: [{function: strcpy, arguments: [buffer, user_input]}]"},
    {"tool": "cwe_lookup", "finding": "Missing required check", "citation": "required: strlen(src) < dest_size - not present in code"}
  ],
  "reasoning": "AST shows strcpy(buffer, user_input) where buffer is 32 bytes and user_input is unbounded. CWE-120 rules require strlen check before strcpy, which is absent."
}

EXAMPLE 2: SAFE CODE
Input: void good_strncpy(char *src) { char buf[32]; strncpy(buf, src, sizeof(buf)-1); buf[31] = '\\0'; }

Step 1: ast_analyze returns:
  - risky_sinks: [{"function": "strncpy", "line": 1, "arguments": ["buf", "src", "sizeof(buf)-1"]}]
  - local_variables: [{"name": "buf", "type": "char []", "line": 1}]

Step 2: cwe_lookup("strncpy") returns:
  - required_safety_checks: ["Size parameter must be <= destination buffer size", "Null-termination must be ensured"]

Step 3: Analysis - strncpy limits copy to sizeof(buf)-1, and null termination is explicitly added.

Output:
{
  "hypothesis": "SAFE",
  "confidence": 0.90,
  "evidence": [
    {"tool": "ast_analyze", "finding": "strncpy with bounded size", "citation": "arguments: [buf, src, sizeof(buf)-1]"},
    {"tool": "cwe_lookup", "finding": "Safety checks satisfied", "citation": "Size parameter (31) <= buffer size (32), null termination present"}
  ],
  "reasoning": "strncpy is called with sizeof(buf)-1 limiting the copy, and explicit null termination at buf[31]. Both CWE-120 safety requirements are met."
}

EXAMPLE 3: INHERENTLY DANGEROUS - gets()
Input: void bad_gets() { char buffer[256]; gets(buffer); process(buffer); }

Step 1: ast_analyze returns:
  - risky_sinks: [{"function": "gets", "line": 1, "arguments": ["buffer"]}]
  - local_variables: [{"name": "buffer", "type": "char []", "size": 256}]

Step 2: pattern_analyze returns:
  - matches: [{"pattern_id": "BOF-002", "severity": "critical", "message": "gets() is inherently unsafe"}]

CRITICAL: gets() is INHERENTLY DANGEROUS - no safe way to use it. Conclude VULNERABLE immediately.

Output:
{
  "hypothesis": "VULNERABLE",
  "confidence": 0.98,
  "evidence": [
    {"tool": "ast_analyze", "finding": "gets() detected - inherently dangerous", "citation": "risky_sinks: [{function: gets}]"},
    {"tool": "pattern_analyze", "finding": "Critical pattern matched", "citation": "BOF-002: gets() is inherently unsafe"}
  ],
  "reasoning": "gets() is detected in the code. This function is INHERENTLY DANGEROUS and cannot be used safely regardless of buffer size. It has no way to limit input length. CWE-120 classifies this as always vulnerable."
}

EXAMPLE 4: INHERENTLY DANGEROUS - scanf without width
Input: void bad_scanf() { char name[32]; scanf("%s", name); }

Step 1: ast_analyze returns:
  - risky_sinks: [{"function": "scanf", "line": 1, "arguments": ["\"%s\"", "name"]}]

Step 2: pattern_analyze returns:
  - matches: [{"pattern_id": "BOF-004", "severity": "high", "message": "scanf() with %s without width limit"}]

Step 3: cwe_lookup("scanf") returns:
  - required_safety_checks: ["use width specifier: %31s"]
  - risky_pattern: "%s"

CRITICAL: scanf("%s") without width is INHERENTLY DANGEROUS.

Output:
{
  "hypothesis": "VULNERABLE",
  "confidence": 0.95,
  "evidence": [
    {"tool": "ast_analyze", "finding": "scanf with %s detected", "citation": "risky_sinks: [{function: scanf, arguments: [\"%s\", name]}]"},
    {"tool": "pattern_analyze", "finding": "Unbounded scanf pattern", "citation": "BOF-004: scanf with %s without width limit"},
    {"tool": "cwe_lookup", "finding": "Missing required width specifier", "citation": "risky_pattern: %s, required: %31s"}
  ],
  "reasoning": "scanf() is called with '%s' format without width specifier. This is inherently dangerous as input is unbounded. CWE-120 requires width specifier like '%31s' for 32-byte buffer."
}

EXAMPLE 5: INSUFFICIENT EVIDENCE
Input: void process(char *data) { handle(data); }

Step 1: ast_analyze returns:
  - risky_sinks: []
  - function_calls: [{"name": "handle", "arguments": ["data"]}]

Output:
{
  "hypothesis": "NOT_ENOUGH_EVIDENCE",
  "confidence": 0.2,
  "evidence": [
    {"tool": "ast_analyze", "finding": "No risky sinks detected", "citation": "risky_sinks: []"}
  ],
  "reasoning": "No buffer-related dangerous functions detected. Cannot determine if handle() is safe without its implementation."
}

=== END EXAMPLES ===
"""


# Define tools for LLM
TOOLS = [
    {
        "name": "ast_analyze",
        "description": "Parse C source code and extract structural information including function calls, parameters, local variables, and risky sinks (memcpy, strcpy, sprintf, gets, scanf, etc). Returns the AST structure of the code.",
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
        "description": "Run Clang Static Analyzer on C code to detect security issues including buffer overflows, insecure API usage, and taint propagation. May return empty findings for small snippets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "The C source code to analyze"
                },
                "context": {
                    "type": "string",
                    "description": "Optional surrounding code for context (e.g., struct definitions, includes)"
                }
            },
            "required": ["source_code"]
        }
    },
    {
        "name": "cwe_lookup",
        "description": "Look up CWE knowledge (CWE-120 family: Buffer Overflow) for a specific sink function. Returns required safety checks, common vulnerability patterns, and safe/unsafe examples.",
        "input_schema": {
            "type": "object",
            "properties": {
                "sink_function": {
                    "type": "string",
                    "description": "Name of the sink function to look up (e.g., memcpy, strcpy, sprintf, gets, scanf, recv)"
                },
                "query_type": {
                    "type": "string",
                    "enum": ["safety_checks", "vulnerability_pattern", "description"],
                    "description": "Type of information to retrieve. Default: safety_checks"
                }
            },
            "required": ["sink_function"]
        }
    },
    {
        "name": "taint_analyze",
        "description": "Track data flow from taint sources (user input, external data) to sinks (dangerous functions). Identifies if untrusted data reaches dangerous operations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "The C source code to analyze for taint propagation"
                }
            },
            "required": ["source_code"]
        }
    },
    {
        "name": "pattern_analyze",
        "description": "Match known vulnerability patterns in code using regex rules. Detects common insecure patterns like strcpy without bounds, gets usage, sprintf without limits, unbounded scanf, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "The C source code to analyze for vulnerability patterns"
                },
                "cwe_filter": {
                    "type": "string",
                    "description": "Optional CWE ID to filter patterns (e.g., CWE-120, CWE-121)"
                }
            },
            "required": ["source_code"]
        }
    },
    {
        "name": "cfg_analyze",
        "description": "Build control flow graph and analyze paths to dangerous sinks. Returns basic blocks, edges, cyclomatic complexity, and whether validation checks exist on paths to sinks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "The C source code to analyze"
                },
                "risky_sinks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of sink function names to trace paths to (e.g., ['strcpy', 'memcpy'])"
                }
            },
            "required": ["source_code"]
        }
    }
]


def _execute_tool(tool_name: str, tool_input: dict) -> dict:
    """Execute an MCP tool and return the result."""
    try:
        if tool_name == "ast_analyze":
            if "source_code" not in tool_input:
                return {"error": "Missing required parameter: source_code", "risky_sinks": []}
            return ast_analyze_tool(tool_input["source_code"])
        
        elif tool_name == "static_analyze":
            if "source_code" not in tool_input:
                return {"error": "Missing required parameter: source_code", "findings": []}
            return static_analyze_tool(
                tool_input["source_code"],
                tool_input.get("context"),
            )
        
        elif tool_name == "cwe_lookup":
            if "sink_function" not in tool_input:
                return {"error": "Missing required parameter: sink_function", "safety_checks": []}
            return cwe_lookup_tool(
                tool_input["sink_function"],
                tool_input.get("query_type", "safety_checks"),
            )
        
        elif tool_name == "taint_analyze":
            if "source_code" not in tool_input:
                return {"error": "Missing required parameter: source_code", "taint_paths": []}
            try:
                from src.mcp_servers.taint_server import taint_analyze_tool
                return taint_analyze_tool(tool_input["source_code"])
            except ImportError:
                return {"error": "Taint analysis tool not available", "taint_paths": []}
        
        elif tool_name == "pattern_analyze":
            if "source_code" not in tool_input:
                return {"error": "Missing required parameter: source_code", "matches": []}
            try:
                from src.mcp_servers.pattern_server import pattern_analyze_tool
                return pattern_analyze_tool(
                    tool_input["source_code"],
                    tool_input.get("cwe_filter"),
                )
            except ImportError:
                return {"error": "Pattern analysis tool not available", "matches": []}
        
        elif tool_name == "cfg_analyze":
            if "source_code" not in tool_input:
                return {"error": "Missing required parameter: source_code", "nodes": [], "edges": []}
            try:
                from src.mcp_servers.cfg_server import cfg_analyze_tool
                return cfg_analyze_tool(
                    tool_input["source_code"],
                    tool_input.get("risky_sinks", []),
                )
            except ImportError:
                return {"error": "CFG analysis tool not available", "nodes": [], "edges": []}
        
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    
    except Exception as e:
        return {"error": f"Tool execution error: {str(e)}"}


class OrchestratorAgent:
    """LLM-based orchestrator for vulnerability analysis."""
    
    def __init__(self, provider: str | None = None):
        self.client = LLMClient(provider=provider)
        self.tool_calls: list[dict] = []
        self.tool_results: dict[str, Any] = {}
    
    def analyze(
        self,
        source_code: str,
        cwe_focus: str | None = None,
    ) -> tuple[OrchestratorHypothesis, dict]:
        """
        Analyze source code using MCP tools and produce a hypothesis.
        
        Args:
            source_code: C source code to analyze
            cwe_focus: Optional specific CWE to focus on (e.g., "CWE-121")
            
        Returns:
            Tuple of (hypothesis, tool_outputs dict)
        """
        self.tool_calls = []
        self.tool_results = {}
        
        cwe_context = ""
        if cwe_focus:
            cwe_context = f"\nFocus especially on {cwe_focus} vulnerabilities."
        
        messages = [
            {
                "role": "user",
                "content": f"""Analyze the following C function for buffer overflow vulnerabilities (CWE-120 family).{cwe_context}

Use the available tools to gather evidence. Do NOT try to analyze the code directly - only use tool outputs.

SOURCE CODE:
```c
{source_code}
```

INSTRUCTIONS:
1. Start with ast_analyze to understand code structure
2. Use cwe_lookup for each risky sink found
3. Use static_analyze for additional verification
4. Provide your hypothesis with evidence citations

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
            # Try to find JSON in the response
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
                
                # Validate confidence range
                confidence = float(data.get("confidence", 0.5))
                confidence = max(0.0, min(1.0, confidence))
                
                return OrchestratorHypothesis(
                    hypothesis=Verdict(verdict_str),
                    confidence=confidence,
                    evidence=evidence,
                    reasoning=data.get("reasoning", text),
                )
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            pass
        
        # Fallback: try to detect verdict from text
        text_upper = text.upper()
        if "VULNERABLE" in text_upper and "NOT" not in text_upper[:text_upper.find("VULNERABLE")]:
            return OrchestratorHypothesis(
                hypothesis=Verdict.VULNERABLE,
                confidence=0.5,
                evidence=[],
                reasoning=f"Extracted from text (no JSON found): {text[:500]}",
            )
        elif "SAFE" in text_upper:
            return OrchestratorHypothesis(
                hypothesis=Verdict.SAFE,
                confidence=0.5,
                evidence=[],
                reasoning=f"Extracted from text (no JSON found): {text[:500]}",
            )
        
        return OrchestratorHypothesis(
            hypothesis=Verdict.NOT_ENOUGH_EVIDENCE,
            confidence=0.0,
            evidence=[],
            reasoning=f"Failed to parse response: {text[:500]}",
        )
    
    def get_tool_calls(self) -> list[dict]:
        """Get the list of tool calls made during analysis."""
        return self.tool_calls
    
    def get_tool_coverage(self) -> dict:
        """Get statistics about which tools were used."""
        tool_names = [tc["tool"] for tc in self.tool_calls]
        return {
            "total_calls": len(self.tool_calls),
            "unique_tools": list(set(tool_names)),
            "tool_call_counts": {tool: tool_names.count(tool) for tool in set(tool_names)},
        }
    
    def analyze_batch(
        self,
        source_code: str,
        cwe_focus: str | None = None,
    ) -> tuple[OrchestratorHypothesis, dict]:
        """
        Batch analysis: Call all tools at once, then synthesize with ONE LLM call.
        
        This is faster and cheaper than the agentic approach but less flexible.
        
        Args:
            source_code: C source code to analyze
            cwe_focus: Optional specific CWE to focus on
            
        Returns:
            Tuple of (hypothesis, tool_outputs dict)
        """
        self.tool_calls = []
        self.tool_results = {}
        
        # Step 1: Call all tools in parallel (deterministic)
        ast_result = _execute_tool("ast_analyze", {"source_code": source_code})
        self.tool_results["ast_analyze"] = ast_result
        self.tool_calls.append({"tool": "ast_analyze", "input": {"source_code": "..."}, "output": ast_result})
        
        static_result = _execute_tool("static_analyze", {"source_code": source_code})
        self.tool_results["static_analyze"] = static_result
        self.tool_calls.append({"tool": "static_analyze", "input": {"source_code": "..."}, "output": static_result})
        
        taint_result = _execute_tool("taint_analyze", {"source_code": source_code})
        self.tool_results["taint_analyze"] = taint_result
        self.tool_calls.append({"tool": "taint_analyze", "input": {"source_code": "..."}, "output": taint_result})
        
        pattern_result = _execute_tool("pattern_analyze", {"source_code": source_code, "cwe_filter": cwe_focus})
        self.tool_results["pattern_analyze"] = pattern_result
        self.tool_calls.append({"tool": "pattern_analyze", "input": {"source_code": "..."}, "output": pattern_result})
        
        # Get risky sinks from AST for CFG analysis
        risky_sinks = [s.get("function", "") for s in ast_result.get("risky_sinks", [])]
        cfg_result = _execute_tool("cfg_analyze", {"source_code": source_code, "risky_sinks": risky_sinks})
        self.tool_results["cfg_analyze"] = cfg_result
        self.tool_calls.append({"tool": "cfg_analyze", "input": {"source_code": "...", "risky_sinks": risky_sinks}, "output": cfg_result})
        
        # Call CWE lookup for each risky sink
        cwe_results = {}
        for sink in ast_result.get("risky_sinks", []):
            func_name = sink.get("function", "")
            if func_name and func_name not in cwe_results:
                cwe_result = _execute_tool("cwe_lookup", {"sink_function": func_name})
                cwe_results[func_name] = cwe_result
                self.tool_calls.append({"tool": "cwe_lookup", "input": {"sink_function": func_name}, "output": cwe_result})
        
        if cwe_results:
            # Combine all CWE results
            self.tool_results["cwe_lookup"] = {
                "sinks": cwe_results,
                "summary": f"Looked up {len(cwe_results)} sink functions"
            }
        
        # Step 2: Synthesize with ONE LLM call
        cwe_context = f"\nFocus especially on {cwe_focus} vulnerabilities." if cwe_focus else ""
        
        tool_outputs_text = self._format_tool_outputs_for_synthesis()
        
        synthesis_prompt = f"""Based on the following tool analysis results, provide your vulnerability hypothesis.

SOURCE CODE:
```c
{source_code}
```
{cwe_context}

TOOL ANALYSIS RESULTS:
{tool_outputs_text}

=== INHERENTLY DANGEROUS FUNCTIONS (ALWAYS VULNERABLE) ===
If ANY of these are detected, conclude VULNERABLE immediately with HIGH confidence:
- gets() → ALWAYS vulnerable, no safe usage possible. Confidence: 0.95+
- scanf("%s") without width → unbounded input. Confidence: 0.90+  
- sprintf() with %s from external input → no bounds check. Confidence: 0.85+

These do NOT require multiple tools to confirm - single detection is sufficient evidence.

Based on ALL the tool outputs above, provide your hypothesis in JSON format:
{{
  "hypothesis": "VULNERABLE" | "SAFE" | "NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "evidence": [
    {{"tool": "tool_name", "finding": "what was found", "citation": "exact quote from tool output"}}
  ],
  "reasoning": "detailed explanation citing specific tool outputs"
}}

IMPORTANT:
- Base your conclusion ONLY on the tool outputs provided
- Cite specific findings from each relevant tool
- IMMEDIATELY conclude VULNERABLE for inherently dangerous functions (gets, unbounded scanf)
- Confidence should reflect evidence strength:
  - 0.95+: Inherently dangerous function detected (gets, unbounded scanf)
  - 0.85-0.95: Multiple tools confirm OR clear dangerous pattern
  - 0.70-0.85: Strong evidence from 2+ tools
  - 0.50-0.70: Single tool with clear evidence
  - <0.50: Conflicting or insufficient evidence"""

        messages = [{"role": "user", "content": synthesis_prompt}]
        
        response = self.client.chat(
            messages=messages,
            system=ORCHESTRATOR_SYSTEM_PROMPT,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        
        hypothesis = self._extract_hypothesis(response.text)
        return hypothesis, self.tool_results
    
    def _format_tool_outputs_for_synthesis(self) -> str:
        """Format all tool outputs for the synthesis prompt."""
        parts = []
        
        # AST Analysis
        if "ast_analyze" in self.tool_results:
            ast = self.tool_results["ast_analyze"]
            parts.append("=== AST ANALYSIS ===")
            parts.append(f"Function: {ast.get('function_name', 'unknown')}")
            parts.append(f"Parameters: {json.dumps(ast.get('parameters', []))}")
            parts.append(f"Local Variables: {json.dumps(ast.get('local_variables', []))}")
            parts.append(f"Risky Sinks: {json.dumps(ast.get('risky_sinks', []))}")
            parts.append(f"Function Calls: {json.dumps(ast.get('function_calls', []))}")
            parts.append("")
        
        # Static Analysis
        if "static_analyze" in self.tool_results:
            static = self.tool_results["static_analyze"]
            parts.append("=== STATIC ANALYSIS (Clang) ===")
            findings = static.get("findings", [])
            if findings:
                for f in findings:
                    parts.append(f"- [{f.get('severity', 'unknown')}] {f.get('message', '')} (line {f.get('line', '?')})")
            else:
                parts.append("No security issues detected by Clang")
            parts.append("")
        
        # Taint Analysis
        if "taint_analyze" in self.tool_results:
            taint = self.tool_results["taint_analyze"]
            parts.append("=== TAINT ANALYSIS ===")
            paths = taint.get("taint_paths", [])
            if paths:
                for p in paths:
                    source = p.get("source", {})
                    sink = p.get("sink", {})
                    parts.append(f"- Taint flow: {source.get('name', '?')} ({source.get('type', '?')}) -> {sink.get('function', '?')} at line {sink.get('line', '?')}")
                    parts.append(f"  Is tainted: {p.get('is_tainted', False)}")
            else:
                parts.append("No taint paths detected")
            parts.append("")
        
        # Pattern Analysis
        if "pattern_analyze" in self.tool_results:
            pattern = self.tool_results["pattern_analyze"]
            parts.append("=== PATTERN MATCHING ===")
            matches = pattern.get("matches", [])
            if matches:
                for m in matches:
                    parts.append(f"- [{m.get('severity', 'unknown')}] {m.get('pattern_id', '')}: {m.get('description', '')} (line {m.get('line', '?')})")
            else:
                parts.append("No vulnerability patterns matched")
            parts.append("")
        
        # CFG Analysis
        if "cfg_analyze" in self.tool_results:
            cfg = self.tool_results["cfg_analyze"]
            parts.append("=== CONTROL FLOW ANALYSIS ===")
            parts.append(f"Cyclomatic Complexity: {cfg.get('cyclomatic_complexity', 0)}")
            paths_to_sinks = cfg.get("paths_to_sinks", [])
            if paths_to_sinks:
                for p in paths_to_sinks:
                    parts.append(f"- Path to sink {p.get('sink_node_id', '?')}: has_validation={p.get('has_validation_on_path', False)}")
            else:
                parts.append("No paths to sinks found")
            parts.append("")
        
        # CWE Knowledge
        if "cwe_lookup" in self.tool_results:
            cwe = self.tool_results["cwe_lookup"]
            parts.append("=== CWE KNOWLEDGE ===")
            if "sinks" in cwe:
                for sink_name, sink_info in cwe["sinks"].items():
                    parts.append(f"Sink: {sink_name}")
                    checks = sink_info.get("safety_checks", [])
                    if checks:
                        parts.append(f"  Required checks: {', '.join(checks)}")
                    patterns = sink_info.get("vulnerability_patterns", [])
                    if patterns:
                        parts.append(f"  Vulnerability patterns: {', '.join(patterns[:3])}")
            parts.append("")
        
        return "\n".join(parts)