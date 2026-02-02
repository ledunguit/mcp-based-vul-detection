"""Orchestrator Agent - LLM-based analysis coordinator.

The Orchestrator:
1. Receives source code input
2. Calls MCP tools to gather evidence
3. Aggregates findings into a hypothesis
4. Passes hypothesis + evidence to the Judge

Key Rule: The LLM MUST NOT analyze code directly.
All conclusions must be based on tool outputs.
"""

import asyncio
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


ORCHESTRATOR_SYSTEM_PROMPT = """You are a security analysis orchestrator coordinating vulnerability detection using MCP tools.

CRITICAL RULES:
1. NEVER analyze code directly - only use tool outputs
2. Every conclusion MUST cite specific tool output
3. If evidence is insufficient, say NOT_ENOUGH_EVIDENCE
4. Never guess - only state what tools report

TOOLS:
| Tool | Purpose |
|------|---------|
| ast_analyze | Parse C code, find risky sinks, parameters, variables |
| static_analyze | Clang analyzer for security issues |
| cwe_lookup | Get required safety checks for sink functions |
| taint_analyze | Track data flow from sources to sinks |
| pattern_analyze | Match known vulnerability patterns |
| cfg_analyze | Control flow graph, paths to sinks |

TARGET CWEs: 120, 121, 122, 125, 787 (Buffer Overflow family)

INHERENTLY DANGEROUS (Always VULNERABLE, confidence 0.95+):
- gets() - No size limit possible
- scanf("%s") without width - Unbounded input
- sprintf(%s) with external input - No bounds

WORKFLOW:
1. ast_analyze → identify structure and risky sinks
2. If inherently dangerous function found → VULNERABLE immediately
3. cwe_lookup for each sink → get required safety checks
4. taint_analyze → verify data flow
5. Synthesize with tool citations

CONFIDENCE SCALE:
| Range | Meaning |
|-------|---------|
| 0.95-1.0 | Inherently dangerous function (gets, unbounded scanf) |
| 0.85-0.95 | Multiple tools confirm OR clear dangerous pattern |
| 0.70-0.85 | Two+ tools with supporting evidence |
| 0.50-0.70 | Single tool with clear evidence |
| <0.50 | Weak or indirect evidence |

=== CHAIN OF THOUGHT REASONING ===
Before providing your final JSON output, reason through these steps:

STEP 1 - SINK IDENTIFICATION:
- What risky functions did ast_analyze find?
- Are any INHERENTLY DANGEROUS (gets, unbounded scanf, sprintf %s)?

STEP 2 - DATA FLOW ANALYSIS:
- What are the taint sources (parameters, stdin, network)?
- Does taint_analyze show flow from source to sink?
- Which sink arguments receive tainted data?

STEP 3 - SAFETY CHECK EVALUATION:
- What checks does cwe_lookup require for each sink?
- Are these checks present in the code (from ast_analyze)?
- Did static_analyze or pattern_analyze flag issues?

STEP 4 - EVIDENCE SYNTHESIS:
- Do multiple tools agree or conflict?
- What is the strongest evidence for/against vulnerability?
- What confidence level matches the evidence strength?

After reasoning through these steps, provide your final answer.
=== END CHAIN OF THOUGHT ===

OUTPUT FORMAT:
```json
{
  "chain_of_thought": {
    "step1_sinks": "What risky sinks were found",
    "step2_data_flow": "How data flows from source to sink",
    "step3_safety_checks": "What checks are present/missing",
    "step4_synthesis": "How evidence supports conclusion"
  },
  "hypothesis": "VULNERABLE|SAFE|NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "evidence": [{"tool": "name", "finding": "what", "citation": "exact output"}],
  "reasoning": "final explanation citing tools"
}
```

EXAMPLE with Chain of Thought:

Tool outputs: ast_analyze shows strcpy(buffer, user_input), buffer is char[32], user_input is parameter

Chain of Thought:
- Step 1: ast_analyze found strcpy sink with args [buffer, user_input]. strcpy is risky but not inherently dangerous.
- Step 2: user_input is a char* parameter (taint source). It flows directly to strcpy's second argument.
- Step 3: cwe_lookup requires strlen(src) < dest_size check. No such check in function_calls.
- Step 4: AST confirms sink + flow + missing check. High confidence vulnerability.

Output: {"chain_of_thought":{"step1_sinks":"strcpy found, risky but needs analysis","step2_data_flow":"user_input (parameter) flows to strcpy arg2","step3_safety_checks":"No strlen check before strcpy","step4_synthesis":"All 3 conditions met with strong evidence"},"hypothesis":"VULNERABLE","confidence":0.92,"evidence":[{"tool":"ast_analyze","finding":"strcpy sink","citation":"risky_sinks:[{function:strcpy,args:[buffer,user_input]}]"}],"reasoning":"strcpy copies unbounded user_input to 32-byte buffer without length check"}
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


async def _execute_tool_async(tool_name: str, tool_input: dict) -> dict:
    """Execute an MCP tool asynchronously."""
    # Run the synchronous tool in a thread pool to avoid blocking
    return await asyncio.to_thread(_execute_tool, tool_name, tool_input)


async def _execute_tools_parallel(calls: list[tuple[str, dict]]) -> list[dict]:
    """Execute multiple tools in parallel."""
    tasks = [_execute_tool_async(name, args) for name, args in calls]
    return await asyncio.gather(*tasks)


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
        Batch analysis: Call all tools in parallel, then synthesize with ONE LLM call.

        This is faster and cheaper than the agentic approach but less flexible.

        Args:
            source_code: C source code to analyze
            cwe_focus: Optional specific CWE to focus on

        Returns:
            Tuple of (hypothesis, tool_outputs dict)
        """
        return asyncio.run(self.analyze_batch_async(source_code, cwe_focus))

    async def analyze_batch_async(
        self,
        source_code: str,
        cwe_focus: str | None = None,
    ) -> tuple[OrchestratorHypothesis, dict]:
        """
        Async batch analysis: Call all tools in parallel waves, then synthesize.

        Wave 1 (parallel): ast_analyze, static_analyze, taint_analyze, pattern_analyze
        Wave 2 (parallel, depends on Wave 1): cfg_analyze, cwe_lookup calls

        Args:
            source_code: C source code to analyze
            cwe_focus: Optional specific CWE to focus on

        Returns:
            Tuple of (hypothesis, tool_outputs dict)
        """
        self.tool_calls = []
        self.tool_results = {}

        # Wave 1: Independent tools (no dependencies) - run in parallel
        wave1_calls = [
            ("ast_analyze", {"source_code": source_code}),
            ("static_analyze", {"source_code": source_code}),
            ("taint_analyze", {"source_code": source_code}),
            ("pattern_analyze", {"source_code": source_code, "cwe_filter": cwe_focus}),
        ]

        wave1_results = await _execute_tools_parallel(wave1_calls)

        ast_result, static_result, taint_result, pattern_result = wave1_results

        # Store Wave 1 results
        self.tool_results["ast_analyze"] = ast_result
        self.tool_calls.append({"tool": "ast_analyze", "input": {"source_code": "..."}, "output": ast_result})

        self.tool_results["static_analyze"] = static_result
        self.tool_calls.append({"tool": "static_analyze", "input": {"source_code": "..."}, "output": static_result})

        self.tool_results["taint_analyze"] = taint_result
        self.tool_calls.append({"tool": "taint_analyze", "input": {"source_code": "..."}, "output": taint_result})

        self.tool_results["pattern_analyze"] = pattern_result
        self.tool_calls.append({"tool": "pattern_analyze", "input": {"source_code": "..."}, "output": pattern_result})

        # Extract risky sinks from AST for Wave 2
        risky_sinks = [s.get("function", "") for s in ast_result.get("risky_sinks", [])]
        unique_sinks = list(set(s for s in risky_sinks if s))

        # Wave 2: Dependent tools - run in parallel
        wave2_calls = [
            ("cfg_analyze", {"source_code": source_code, "risky_sinks": risky_sinks}),
        ]
        # Add CWE lookup for each unique sink
        for sink in unique_sinks:
            wave2_calls.append(("cwe_lookup", {"sink_function": sink}))

        wave2_results = await _execute_tools_parallel(wave2_calls)

        # Store Wave 2 results
        cfg_result = wave2_results[0]
        self.tool_results["cfg_analyze"] = cfg_result
        self.tool_calls.append({"tool": "cfg_analyze", "input": {"source_code": "...", "risky_sinks": risky_sinks}, "output": cfg_result})

        # Store CWE lookup results
        cwe_results = {}
        for i, sink in enumerate(unique_sinks):
            cwe_result = wave2_results[i + 1]  # +1 because cfg_analyze is first
            cwe_results[sink] = cwe_result
            self.tool_calls.append({"tool": "cwe_lookup", "input": {"sink_function": sink}, "output": cwe_result})

        if cwe_results:
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

=== CHAIN OF THOUGHT REASONING ===
Before providing your final answer, think through these steps:

STEP 1 - SINK IDENTIFICATION:
- What risky functions are in the AST results?
- Are any INHERENTLY DANGEROUS (gets, unbounded scanf, sprintf %s)?

STEP 2 - DATA FLOW ANALYSIS:
- What taint sources exist (parameters, stdin, network)?
- Does data flow from sources to sinks?

STEP 3 - SAFETY CHECK EVALUATION:
- What safety checks does CWE knowledge require?
- Are these checks present in the code?

STEP 4 - EVIDENCE SYNTHESIS:
- Do multiple tools agree?
- What is the overall evidence strength?

=== INHERENTLY DANGEROUS FUNCTIONS ===
If ANY detected, conclude VULNERABLE immediately (confidence 0.95+):
- gets() → No safe usage possible
- scanf("%s") without width → Unbounded input
- sprintf() with %s from external input → No bounds

Provide your answer in JSON format:
{{
  "chain_of_thought": {{
    "step1_sinks": "risky sinks found",
    "step2_data_flow": "source to sink flow",
    "step3_safety_checks": "checks present/missing",
    "step4_synthesis": "evidence summary"
  }},
  "hypothesis": "VULNERABLE" | "SAFE" | "NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "evidence": [
    {{"tool": "tool_name", "finding": "what was found", "citation": "exact quote"}}
  ],
  "reasoning": "final explanation citing tool outputs"
}}"""

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