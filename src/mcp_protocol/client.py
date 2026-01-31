"""
MCP Client Implementation - Phase 1.2

Provides a client for communicating with MCP servers.
Supports both direct in-process calls and stdio-based protocol communication.
"""

import json
import asyncio
import subprocess
from dataclasses import dataclass
from typing import Any, Optional
import uuid

from .base_server import MCPRequest, MCPResponse, MCPServer


@dataclass
class MCPToolCall:
    """Record of a tool call made through MCP."""
    tool_name: str
    arguments: dict
    result: Optional[Any] = None
    error: Optional[str] = None
    duration_ms: float = 0.0


class MCPClient:
    """
    Client for interacting with MCP servers.
    
    Supports two modes:
    1. Direct mode: Calls tool handlers directly (for testing/development)
    2. Protocol mode: Communicates via MCP protocol (for production)
    
    Example:
        # Direct mode with in-process servers
        client = MCPClient()
        client.register_server("ast", ast_server)
        result = client.call_tool("ast_analyze", {"source_code": "..."})
        
        # Protocol mode with subprocess
        client = MCPClient(protocol_mode=True)
        client.connect_subprocess("ast", ["python", "-m", "mcp_servers.ast"])
        result = await client.call_tool_async("ast_analyze", {"source_code": "..."})
    """
    
    def __init__(self, protocol_mode: bool = False):
        """
        Initialize MCP client.
        
        Args:
            protocol_mode: If True, communicate via MCP protocol.
                          If False, call handlers directly.
        """
        self.protocol_mode = protocol_mode
        self.servers: dict[str, MCPServer] = {}
        self.tool_to_server: dict[str, str] = {}
        self.processes: dict[str, subprocess.Popen] = {}
        self.call_history: list[MCPToolCall] = []
    
    def register_server(self, name: str, server: MCPServer) -> None:
        """
        Register an MCP server for direct calls.
        
        Args:
            name: Server name
            server: MCPServer instance
        """
        self.servers[name] = server
        for tool_name in server.tools:
            self.tool_to_server[tool_name] = name
    
    def connect_subprocess(
        self, 
        name: str, 
        command: list[str],
        env: Optional[dict] = None,
    ) -> None:
        """
        Connect to an MCP server running as a subprocess.
        
        Args:
            name: Server name
            command: Command to start the server
            env: Optional environment variables
        """
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        self.processes[name] = proc
    
    def list_tools(self) -> list[dict]:
        """List all available tools across all registered servers."""
        all_tools = []
        for server in self.servers.values():
            all_tools.extend(server.list_tools())
        return all_tools
    
    def list_tools_for_llm(self) -> list[dict]:
        """
        List tools in a format suitable for LLM function calling.
        
        Returns tools in the format expected by Claude/OpenAI APIs.
        """
        tools = []
        for tool_info in self.list_tools():
            tools.append({
                "type": "function",
                "function": {
                    "name": tool_info["name"],
                    "description": tool_info["description"],
                    "parameters": tool_info["inputSchema"],
                }
            })
        return tools
    
    def call_tool(self, tool_name: str, arguments: dict) -> Any:
        """
        Call a tool synchronously.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
        
        Returns:
            Tool result
        """
        import time
        start = time.time()
        
        call = MCPToolCall(tool_name=tool_name, arguments=arguments)
        
        try:
            if self.protocol_mode:
                result = self._call_protocol(tool_name, arguments)
            else:
                result = self._call_direct(tool_name, arguments)
            
            call.result = result
            call.duration_ms = (time.time() - start) * 1000
            
        except Exception as e:
            call.error = str(e)
            call.duration_ms = (time.time() - start) * 1000
            raise
        finally:
            self.call_history.append(call)
        
        return result
    
    async def call_tool_async(self, tool_name: str, arguments: dict) -> Any:
        """
        Call a tool asynchronously.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
        
        Returns:
            Tool result
        """
        import time
        start = time.time()
        
        call = MCPToolCall(tool_name=tool_name, arguments=arguments)
        
        try:
            if self.protocol_mode:
                result = await self._call_protocol_async(tool_name, arguments)
            else:
                result = await self._call_direct_async(tool_name, arguments)
            
            call.result = result
            call.duration_ms = (time.time() - start) * 1000
            
        except Exception as e:
            call.error = str(e)
            call.duration_ms = (time.time() - start) * 1000
            raise
        finally:
            self.call_history.append(call)
        
        return result
    
    def call_multiple(self, calls: list[tuple[str, dict]]) -> list[Any]:
        """
        Call multiple tools in parallel.
        
        Args:
            calls: List of (tool_name, arguments) tuples
        
        Returns:
            List of results
        """
        return asyncio.run(self.call_multiple_async(calls))
    
    async def call_multiple_async(self, calls: list[tuple[str, dict]]) -> list[Any]:
        """
        Call multiple tools in parallel asynchronously.
        
        Args:
            calls: List of (tool_name, arguments) tuples
        
        Returns:
            List of results
        """
        tasks = [
            self.call_tool_async(tool_name, args)
            for tool_name, args in calls
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def _call_direct(self, tool_name: str, arguments: dict) -> Any:
        """Call tool directly via handler."""
        if tool_name not in self.tool_to_server:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        server_name = self.tool_to_server[tool_name]
        server = self.servers[server_name]
        return server.call_tool(tool_name, arguments)
    
    async def _call_direct_async(self, tool_name: str, arguments: dict) -> Any:
        """Call tool directly via handler asynchronously."""
        if tool_name not in self.tool_to_server:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        server_name = self.tool_to_server[tool_name]
        server = self.servers[server_name]
        return await server.call_tool_async(tool_name, arguments)
    
    def _call_protocol(self, tool_name: str, arguments: dict) -> Any:
        """Call tool via MCP protocol."""
        # For now, fall back to direct call if not using subprocesses
        if tool_name in self.tool_to_server:
            return self._call_direct(tool_name, arguments)
        
        # TODO: Implement subprocess protocol communication
        raise NotImplementedError("Protocol mode with subprocesses not yet implemented")
    
    async def _call_protocol_async(self, tool_name: str, arguments: dict) -> Any:
        """Call tool via MCP protocol asynchronously."""
        # For now, fall back to direct call
        if tool_name in self.tool_to_server:
            return await self._call_direct_async(tool_name, arguments)
        
        # TODO: Implement subprocess protocol communication
        raise NotImplementedError("Protocol mode with subprocesses not yet implemented")
    
    def get_call_history(self) -> list[MCPToolCall]:
        """Get the history of all tool calls."""
        return self.call_history.copy()
    
    def clear_history(self) -> None:
        """Clear the call history."""
        self.call_history.clear()
    
    def get_statistics(self) -> dict:
        """Get statistics about tool calls."""
        if not self.call_history:
            return {}
        
        tool_stats = {}
        for call in self.call_history:
            if call.tool_name not in tool_stats:
                tool_stats[call.tool_name] = {
                    "calls": 0,
                    "errors": 0,
                    "total_duration_ms": 0,
                }
            
            stats = tool_stats[call.tool_name]
            stats["calls"] += 1
            stats["total_duration_ms"] += call.duration_ms
            if call.error:
                stats["errors"] += 1
        
        # Compute averages
        for tool, stats in tool_stats.items():
            stats["avg_duration_ms"] = stats["total_duration_ms"] / stats["calls"]
            stats["error_rate"] = stats["errors"] / stats["calls"]
        
        return tool_stats
    
    def close(self) -> None:
        """Close all subprocess connections."""
        for proc in self.processes.values():
            proc.terminate()
        self.processes.clear()
