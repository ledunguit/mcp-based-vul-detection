"""
Tool Registry - Phase 1.2

Provides a registry for managing MCP tools and servers.
Allows dynamic tool discovery and configuration.
"""

from typing import Any, Callable, Optional
from dataclasses import dataclass, field

from src.mcp_protocol.client import MCPClient

from .base_server import MCPServer, ToolWrapper


@dataclass
class ToolInfo:
    """Information about a registered tool."""
    name: str
    description: str
    server_name: str
    input_schema: dict
    handler: Optional[Callable] = None


class ToolRegistry:
    """
    Registry for MCP tools and servers.
    
    Provides a central place to:
    - Register tools and servers
    - Discover available tools
    - Get tool metadata
    - Create configured MCP clients
    
    Example:
        registry = ToolRegistry()
        
        # Register existing tools
        registry.register_legacy_tool(
            "ast_analyze",
            ast_analyze_tool,
            description="Analyze C code AST",
        )
        
        # Get a configured client
        client = registry.create_client()
        result = client.call_tool("ast_analyze", {...})
    """
    
    def __init__(self):
        self._servers: dict[str, MCPServer] = {}
        self._tool_info: dict[str, ToolInfo] = {}
        self._default_wrapper: Optional[ToolWrapper] = None
    
    def register_server(self, name: str, server: MCPServer) -> None:
        """
        Register an MCP server with the registry.
        
        Args:
            name: Unique server name
            server: MCPServer instance
        """
        self._servers[name] = server
        
        # Index tools from this server
        for tool_name, tool_def in server.tools.items():
            self._tool_info[tool_name] = ToolInfo(
                name=tool_name,
                description=tool_def.description,
                server_name=name,
                input_schema=tool_def.input_schema,
                handler=tool_def.handler,
            )
    
    def register_legacy_tool(
        self,
        name: str,
        handler: Callable,
        description: Optional[str] = None,
        input_schema: Optional[dict] = None,
    ) -> None:
        """
        Register an existing function as an MCP tool.
        
        This allows gradual migration from direct function calls to MCP.
        
        Args:
            name: Tool name
            handler: The function to wrap
            description: Tool description (defaults to docstring)
            input_schema: JSON schema for inputs
        """
        if self._default_wrapper is None:
            self._default_wrapper = ToolWrapper("legacy_tools")
            self._servers["legacy_tools"] = self._default_wrapper
        
        self._default_wrapper.wrap_function(
            handler,
            name=name,
            description=description,
            input_schema=input_schema,
        )
        
        tool_def = self._default_wrapper.tools[name]
        self._tool_info[name] = ToolInfo(
            name=name,
            description=tool_def.description,
            server_name="legacy_tools",
            input_schema=tool_def.input_schema,
            handler=tool_def.handler,
        )
    
    def list_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self._tool_info.keys())
    
    def list_servers(self) -> list[str]:
        """List all registered server names."""
        return list(self._servers.keys())
    
    def get_tool_info(self, name: str) -> Optional[ToolInfo]:
        """Get information about a specific tool."""
        return self._tool_info.get(name)
    
    def get_server(self, name: str) -> Optional[MCPServer]:
        """Get a server by name."""
        return self._servers.get(name)
    
    def get_tools_for_llm(self) -> list[dict]:
        """
        Get tool definitions formatted for LLM function calling.
        
        Returns:
            List of tool definitions in Claude/OpenAI format
        """
        tools = []
        for info in self._tool_info.values():
            tools.append({
                "type": "function",
                "function": {
                    "name": info.name,
                    "description": info.description,
                    "parameters": info.input_schema,
                }
            })
        return tools
    
    def create_client(self, protocol_mode: bool = False) -> MCPClient:
        """
        Create an MCP client with all registered servers.
        
        Args:
            protocol_mode: If True, use MCP protocol for calls
        
        Returns:
            Configured MCPClient instance
        """
        from .client import MCPClient
        
        client = MCPClient(protocol_mode=protocol_mode)
        for name, server in self._servers.items():
            client.register_server(name, server)
        
        return client


# Global registry instance
_global_registry: Optional[ToolRegistry] = None


def get_global_registry() -> ToolRegistry:
    """Get or create the global tool registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry


def register_default_tools() -> ToolRegistry:
    """
    Register all default MCP tools with the global registry.
    
    This imports and registers all the standard vulnerability detection tools.
    """
    from src.mcp_servers import (
        ast_analyze_tool,
        static_analyze_tool,
        cwe_lookup_tool,
        taint_analyze_tool,
        pattern_match_tool,
        cfg_analyze_tool,
    )
    
    registry = get_global_registry()
    
    # Register legacy tools
    registry.register_legacy_tool(
        "ast_analyze",
        ast_analyze_tool,
        description="Parse C code and extract AST information including function definitions, parameters, variables, and risky function calls.",
        input_schema={
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "C source code to analyze",
                },
            },
            "required": ["source_code"],
        },
    )
    
    registry.register_legacy_tool(
        "static_analyze",
        static_analyze_tool,
        description="Run Clang static analyzer on C code to detect potential vulnerabilities.",
        input_schema={
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "C source code to analyze",
                },
            },
            "required": ["source_code"],
        },
    )
    
    registry.register_legacy_tool(
        "cwe_lookup",
        cwe_lookup_tool,
        description="Look up CWE knowledge including safety rules and remediation guidance.",
        input_schema={
            "type": "object",
            "properties": {
                "cwe_id": {
                    "type": "string",
                    "description": "CWE identifier (e.g., CWE-120)",
                },
                "sink_function": {
                    "type": "string",
                    "description": "Optional sink function to get specific rules for",
                },
            },
            "required": ["cwe_id"],
        },
    )
    
    registry.register_legacy_tool(
        "taint_analyze",
        taint_analyze_tool,
        description="Track data flow from sources to sinks to detect tainted data usage.",
        input_schema={
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "C source code to analyze",
                },
            },
            "required": ["source_code"],
        },
    )
    
    registry.register_legacy_tool(
        "pattern_analyze",
        pattern_match_tool,
        description="Match code against known vulnerability patterns.",
        input_schema={
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "C source code to analyze",
                },
            },
            "required": ["source_code"],
        },
    )
    
    registry.register_legacy_tool(
        "cfg_analyze",
        cfg_analyze_tool,
        description="Extract control flow graph from C code for analysis.",
        input_schema={
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "C source code to analyze",
                },
            },
            "required": ["source_code"],
        },
    )
    
    return registry
