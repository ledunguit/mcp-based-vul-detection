"""
MCP Client Implementation - Phase 1.2

Provides a client for communicating with MCP servers.
Supports both direct in-process calls and stdio-based protocol communication.
"""

import json
import asyncio
import subprocess
import threading
from dataclasses import dataclass
from typing import Any, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request
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
        self.process_locks: dict[str, threading.Lock] = {}
        self.http_endpoints: dict[str, str] = {}
        self.remote_server_tools: dict[str, list[dict]] = {}
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
        cwd: Optional[str] = None,
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
            cwd=cwd,
            text=True,
            bufsize=1,
        )
        self.processes[name] = proc
        self.process_locks[name] = threading.Lock()

        if self.protocol_mode:
            self._initialize_remote_server(name)
            self._refresh_remote_tools(name)

    def connect_http(self, name: str, endpoint_url: str) -> None:
        """
        Connect to an MCP server exposed over HTTP.

        Args:
            name: Server name
            endpoint_url: Full MCP endpoint URL, e.g. http://host:port/mcp
        """
        self.http_endpoints[name] = endpoint_url.rstrip("/")

        if self.protocol_mode:
            self._initialize_remote_server(name)
            self._refresh_remote_tools(name)
    
    def list_tools(self) -> list[dict]:
        """List all available tools across all registered servers."""
        all_tools = []
        for server in self.servers.values():
            all_tools.extend(server.list_tools())
        for tools in self.remote_server_tools.values():
            all_tools.extend(tools)
        return all_tools

    def has_tool(self, tool_name: str) -> bool:
        """Return whether a tool is currently available."""
        if tool_name in self.tool_to_server:
            return True
        if self.protocol_mode:
            self._refresh_all_remote_tools()
        return tool_name in self.tool_to_server
    
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
        if tool_name in self.tool_to_server:
            server_name = self.tool_to_server[tool_name]
            if server_name in self.servers:
                return self._call_direct(tool_name, arguments)
            if server_name in self.processes or server_name in self.http_endpoints:
                result = self._protocol_request(
                    server_name,
                    "tools/call",
                    {"name": tool_name, "arguments": arguments},
                )
                return self._extract_tool_result(result)

        self._refresh_all_remote_tools()
        if tool_name in self.tool_to_server:
            return self._call_protocol(tool_name, arguments)

        raise ValueError(f"Unknown tool: {tool_name}")
    
    async def _call_protocol_async(self, tool_name: str, arguments: dict) -> Any:
        """Call tool via MCP protocol asynchronously."""
        return await asyncio.to_thread(self._call_protocol, tool_name, arguments)

    def _initialize_remote_server(self, server_name: str) -> None:
        try:
            self._protocol_request(
                server_name,
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mcp-vul",
                        "version": "0.1.0",
                    },
                },
            )
        except Exception:
            # Some legacy servers may not implement initialize; tolerate that.
            return

    def _refresh_remote_tools(self, server_name: str) -> None:
        result = self._protocol_request(server_name, "tools/list", {})
        tools = result.get("tools", [])
        self.remote_server_tools[server_name] = tools
        for tool in tools:
            tool_name = tool.get("name")
            if tool_name:
                self.tool_to_server[tool_name] = server_name

    def _refresh_all_remote_tools(self) -> None:
        for server_name in list(self.processes) + list(self.http_endpoints):
            self._refresh_remote_tools(server_name)

    def _protocol_request(self, server_name: str, method: str, params: dict) -> Any:
        if server_name in self.http_endpoints:
            return self._protocol_request_http(server_name, method, params)
        return self._protocol_request_stdio(server_name, method, params)

    def _protocol_request_stdio(self, server_name: str, method: str, params: dict) -> Any:
        if server_name not in self.processes:
            raise ValueError(f"Unknown remote server: {server_name}")

        proc = self.processes[server_name]
        lock = self.process_locks[server_name]
        if proc.stdin is None or proc.stdout is None:
            raise RuntimeError(f"Server {server_name} is missing stdio pipes")

        request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params,
        }

        with lock:
            proc.stdin.write(json.dumps(request) + "\n")
            proc.stdin.flush()

            response_line = proc.stdout.readline()
            if not response_line:
                stderr_output = ""
                if proc.stderr is not None:
                    try:
                        stderr_output = proc.stderr.read()
                    except Exception:
                        stderr_output = ""
                raise RuntimeError(
                    f"No response from server {server_name}. stderr: {stderr_output[:500]}"
                )

        response = json.loads(response_line)
        if "error" in response and response["error"] is not None:
            message = response["error"].get("message", "Unknown MCP protocol error")
            raise RuntimeError(message)
        return response.get("result", {})

    def _protocol_request_http(self, server_name: str, method: str, params: dict) -> Any:
        if server_name not in self.http_endpoints:
            raise ValueError(f"Unknown HTTP server: {server_name}")

        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": method,
                "params": params,
            }
        ).encode("utf-8")

        req = urllib_request.Request(
            self.http_endpoints[server_name],
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib_request.urlopen(req, timeout=30) as response:
                raw_body = response.read().decode("utf-8")
        except urllib_error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(
                f"HTTP MCP request failed for {server_name}: {exc.code} {body[:500]}"
            ) from exc
        except urllib_error.URLError as exc:
            raise RuntimeError(f"Failed to reach HTTP MCP server {server_name}: {exc}") from exc

        if not raw_body:
            return {}

        response = json.loads(raw_body)
        if "error" in response and response["error"] is not None:
            message = response["error"].get("message", "Unknown MCP protocol error")
            raise RuntimeError(message)
        return response.get("result", {})

    def _extract_tool_result(self, result: Any) -> Any:
        if isinstance(result, dict):
            content = result.get("content")
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and first.get("type") == "text":
                    text = first.get("text", "")
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        return {"raw_text": text}
        return result
    
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
        self.process_locks.clear()
        self.http_endpoints.clear()
        self.remote_server_tools.clear()
