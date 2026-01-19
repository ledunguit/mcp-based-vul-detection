"""MCP Tool Servers for vulnerability detection.

Available tools:
- ast_server: Parse C code and extract AST information
- static_analysis_server: Run Clang static analyzer
- cwe_knowledge_server: Look up CWE knowledge and safety rules
- taint_server: Track data flow from sources to sinks
- pattern_server: Match code against vulnerability patterns
- cfg_server: Extract control flow graph
"""

from src.mcp_servers.ast_server import ast_analyze_tool
from src.mcp_servers.static_analysis_server import static_analyze_tool
from src.mcp_servers.cwe_knowledge_server import cwe_lookup_tool, get_cwe_info_tool
from src.mcp_servers.taint_server import taint_analyze_tool
from src.mcp_servers.pattern_server import pattern_match_tool, get_all_patterns_tool
from src.mcp_servers.cfg_server import cfg_analyze_tool

__all__ = [
    "ast_analyze_tool",
    "static_analyze_tool",
    "cwe_lookup_tool",
    "get_cwe_info_tool",
    "taint_analyze_tool",
    "pattern_match_tool",
    "get_all_patterns_tool",
    "cfg_analyze_tool",
]
