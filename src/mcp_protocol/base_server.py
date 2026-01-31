"""
Base MCP Server Implementation - Phase 1.2

Provides an abstract base class for MCP-compliant tool servers.
Each tool server can expose multiple tools and handle calls via the MCP protocol.

Based on the Model Context Protocol specification:
https://modelcontextprotocol.io/
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
import json
import asyncio
from enum import Enum


class MCPMessageType(Enum):
    """MCP message types."""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


@dataclass
class MCPToolDefinition:
    """Definition of a tool exposed by an MCP server."""
    name: str
    description: str
    input_schema: dict  # JSON Schema for parameters
    handler: Optional[Callable] = None
    
    def to_dict(self) -> dict:
        """Convert to MCP-compatible dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass
class MCPRequest:
    """MCP request message."""
    id: str
    method: str
    params: dict = field(default_factory=dict)
    
    def to_json(self) -> str:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": self.id,
            "method": self.method,
            "params": self.params,
        })
    
    @classmethod
    def from_json(cls, data: str) -> "MCPRequest":
        parsed = json.loads(data)
        return cls(
            id=parsed.get("id", ""),
            method=parsed.get("method", ""),
            params=parsed.get("params", {}),
        )


@dataclass
class MCPResponse:
    """MCP response message."""
    id: str
    result: Any = None
    error: Optional[dict] = None
    
    def to_json(self) -> str:
        response = {
            "jsonrpc": "2.0",
            "id": self.id,
        }
        if self.error:
            response["error"] = self.error
        else:
            response["result"] = self.result
        return json.dumps(response, default=str)
    
    @classmethod
    def from_json(cls, data: str) -> "MCPResponse":
        parsed = json.loads(data)
        return cls(
            id=parsed.get("id", ""),
            result=parsed.get("result"),
            error=parsed.get("error"),
        )


class MCPServer(ABC):
    """
    Abstract base class for MCP-compliant tool servers.
    
    Subclasses should:
    1. Define tools in the __init__ method using register_tool()
    2. Implement tool handlers as methods
    
    Example:
        class ASTServer(MCPServer):
            def __init__(self):
                super().__init__("ast_server")
                self.register_tool(
                    name="ast_analyze",
                    description="Analyze C code AST",
                    input_schema={...},
                    handler=self.analyze
                )
            
            def analyze(self, source_code: str) -> dict:
                ...
    """
    
    def __init__(self, server_name: str):
        self.server_name = server_name
        self.tools: dict[str, MCPToolDefinition] = {}
        self._running = False
    
    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: dict,
        handler: Callable,
    ) -> None:
        """Register a tool with this server."""
        self.tools[name] = MCPToolDefinition(
            name=name,
            description=description,
            input_schema=input_schema,
            handler=handler,
        )
    
    def list_tools(self) -> list[dict]:
        """List all tools provided by this server."""
        return [tool.to_dict() for tool in self.tools.values()]
    
    def call_tool(self, tool_name: str, arguments: dict) -> Any:
        """
        Call a tool by name with given arguments.
        
        This is the synchronous interface for direct tool calls.
        """
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        tool = self.tools[tool_name]
        if tool.handler is None:
            raise ValueError(f"Tool {tool_name} has no handler")
        
        return tool.handler(**arguments)
    
    async def call_tool_async(self, tool_name: str, arguments: dict) -> Any:
        """
        Asynchronously call a tool.
        
        Wraps synchronous handlers in asyncio.to_thread for non-blocking execution.
        """
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        tool = self.tools[tool_name]
        if tool.handler is None:
            raise ValueError(f"Tool {tool_name} has no handler")
        
        # Run in thread pool if handler is sync
        if asyncio.iscoroutinefunction(tool.handler):
            return await tool.handler(**arguments)
        else:
            return await asyncio.to_thread(tool.handler, **arguments)
    
    def handle_request(self, request: MCPRequest) -> MCPResponse:
        """
        Handle an MCP request message.
        
        Supports the following methods:
        - tools/list: List available tools
        - tools/call: Call a specific tool
        """
        try:
            if request.method == "tools/list":
                return MCPResponse(
                    id=request.id,
                    result={"tools": self.list_tools()},
                )
            
            elif request.method == "tools/call":
                tool_name = request.params.get("name", "")
                arguments = request.params.get("arguments", {})
                
                result = self.call_tool(tool_name, arguments)
                
                return MCPResponse(
                    id=request.id,
                    result={"content": [{"type": "text", "text": json.dumps(result, default=str)}]},
                )
            
            else:
                return MCPResponse(
                    id=request.id,
                    error={"code": -32601, "message": f"Unknown method: {request.method}"},
                )
        
        except Exception as e:
            return MCPResponse(
                id=request.id,
                error={"code": -32603, "message": str(e)},
            )
    
    async def handle_request_async(self, request: MCPRequest) -> MCPResponse:
        """Asynchronously handle an MCP request."""
        try:
            if request.method == "tools/list":
                return MCPResponse(
                    id=request.id,
                    result={"tools": self.list_tools()},
                )
            
            elif request.method == "tools/call":
                tool_name = request.params.get("name", "")
                arguments = request.params.get("arguments", {})
                
                result = await self.call_tool_async(tool_name, arguments)
                
                return MCPResponse(
                    id=request.id,
                    result={"content": [{"type": "text", "text": json.dumps(result, default=str)}]},
                )
            
            else:
                return MCPResponse(
                    id=request.id,
                    error={"code": -32601, "message": f"Unknown method: {request.method}"},
                )
        
        except Exception as e:
            return MCPResponse(
                id=request.id,
                error={"code": -32603, "message": str(e)},
            )
    
    def serve_stdio(self) -> None:
        """
        Serve this MCP server over stdio.
        
        Reads JSON-RPC requests from stdin and writes responses to stdout.
        This is the standard transport for MCP servers.
        """
        import sys
        
        self._running = True
        while self._running:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                
                request = MCPRequest.from_json(line.strip())
                response = self.handle_request(request)
                
                sys.stdout.write(response.to_json() + "\n")
                sys.stdout.flush()
                
            except json.JSONDecodeError:
                # Invalid JSON, skip
                continue
            except KeyboardInterrupt:
                break
    
    def stop(self) -> None:
        """Stop the server."""
        self._running = False


class ToolWrapper(MCPServer):
    """
    Wrapper to convert existing tool functions into an MCP server.
    
    This allows gradual migration from direct function calls to MCP protocol.
    """
    
    def __init__(self, server_name: str = "wrapped_tools"):
        super().__init__(server_name)
    
    def wrap_function(
        self,
        func: Callable,
        name: Optional[str] = None,
        description: Optional[str] = None,
        input_schema: Optional[dict] = None,
    ) -> None:
        """
        Wrap an existing function as an MCP tool.
        
        Args:
            func: The function to wrap
            name: Optional tool name (defaults to function name)
            description: Optional description (defaults to docstring)
            input_schema: Optional JSON schema (generates basic one if not provided)
        """
        tool_name = name or func.__name__
        tool_description = description or (func.__doc__ or "")
        
        # Generate basic input schema if not provided
        if input_schema is None:
            import inspect
            sig = inspect.signature(func)
            properties = {}
            required = []
            
            for param_name, param in sig.parameters.items():
                if param_name in ("self", "cls"):
                    continue
                
                prop = {"type": "string"}  # Default type
                if param.annotation != inspect.Parameter.empty:
                    if param.annotation == str:
                        prop["type"] = "string"
                    elif param.annotation == int:
                        prop["type"] = "integer"
                    elif param.annotation == float:
                        prop["type"] = "number"
                    elif param.annotation == bool:
                        prop["type"] = "boolean"
                
                properties[param_name] = prop
                
                if param.default == inspect.Parameter.empty:
                    required.append(param_name)
            
            input_schema = {
                "type": "object",
                "properties": properties,
                "required": required,
            }
        
        self.register_tool(
            name=tool_name,
            description=tool_description,
            input_schema=input_schema,
            handler=func,
        )
