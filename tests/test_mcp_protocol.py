"""Tests for Phase 1.2 MCP Protocol Implementation."""

import pytest
import asyncio
import json
from src.mcp_protocol.base_server import (
    MCPServer,
    MCPRequest,
    MCPResponse,
    MCPToolDefinition,
    ToolWrapper,
)
from src.mcp_protocol.client import MCPClient, MCPToolCall


class _FakeHTTPResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


class TestMCPToolDefinition:
    """Tests for MCPToolDefinition."""
    
    def test_to_dict(self):
        """Test conversion to MCP-compatible dict."""
        tool = MCPToolDefinition(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object", "properties": {"x": {"type": "string"}}},
        )
        result = tool.to_dict()
        
        assert result["name"] == "test_tool"
        assert result["description"] == "A test tool"
        assert "inputSchema" in result


class TestMCPRequest:
    """Tests for MCPRequest."""
    
    def test_to_json(self):
        """Test JSON serialization."""
        request = MCPRequest(id="123", method="tools/list", params={})
        json_str = request.to_json()
        
        assert "jsonrpc" in json_str
        assert "2.0" in json_str
        assert "tools/list" in json_str
    
    def test_from_json(self):
        """Test JSON deserialization."""
        json_str = '{"jsonrpc": "2.0", "id": "456", "method": "tools/call", "params": {"name": "test"}}'
        request = MCPRequest.from_json(json_str)
        
        assert request.id == "456"
        assert request.method == "tools/call"
        assert request.params["name"] == "test"


class TestMCPResponse:
    """Tests for MCPResponse."""
    
    def test_success_response(self):
        """Test success response serialization."""
        response = MCPResponse(id="123", result={"data": "test"})
        json_str = response.to_json()
        
        assert '"result"' in json_str
        assert "error" not in json_str or '"error": null' in json_str
    
    def test_error_response(self):
        """Test error response serialization."""
        response = MCPResponse(id="123", error={"code": -1, "message": "Error"})
        json_str = response.to_json()
        
        assert '"error"' in json_str


class TestToolWrapper:
    """Tests for ToolWrapper class."""
    
    def test_wrap_function(self):
        """Test wrapping a simple function."""
        wrapper = ToolWrapper("test_server")
        
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b
        
        wrapper.wrap_function(add)
        
        assert "add" in wrapper.tools
        assert wrapper.tools["add"].description == "Add two numbers."
    
    def test_call_wrapped_function(self):
        """Test calling a wrapped function."""
        wrapper = ToolWrapper("test_server")
        
        def multiply(x: int, y: int) -> int:
            return x * y
        
        wrapper.wrap_function(multiply)
        result = wrapper.call_tool("multiply", {"x": 3, "y": 4})
        
        assert result == 12


class TestMCPClient:
    """Tests for MCPClient."""
    
    def test_register_server(self):
        """Test registering a server."""
        client = MCPClient()
        wrapper = ToolWrapper("test")
        wrapper.wrap_function(lambda x: x * 2, name="double")
        
        client.register_server("test", wrapper)
        
        assert "double" in client.tool_to_server
    
    def test_call_tool(self):
        """Test calling a tool."""
        client = MCPClient()
        wrapper = ToolWrapper("test")
        wrapper.wrap_function(lambda x: x.upper(), name="uppercase")
        client.register_server("test", wrapper)
        
        result = client.call_tool("uppercase", {"x": "hello"})
        
        assert result == "HELLO"
    
    def test_call_history(self):
        """Test that call history is recorded."""
        client = MCPClient()
        wrapper = ToolWrapper("test")
        wrapper.wrap_function(lambda x: x, name="identity")
        client.register_server("test", wrapper)
        
        client.call_tool("identity", {"x": "test"})
        
        history = client.get_call_history()
        assert len(history) == 1
        assert history[0].tool_name == "identity"
    
    def test_unknown_tool_raises(self):
        """Test that calling unknown tool raises error."""
        client = MCPClient()
        
        with pytest.raises(ValueError, match="Unknown tool"):
            client.call_tool("nonexistent", {})
    
    def test_statistics(self):
        """Test statistics collection."""
        client = MCPClient()
        wrapper = ToolWrapper("test")
        wrapper.wrap_function(lambda x: x, name="passthrough")
        client.register_server("test", wrapper)
        
        client.call_tool("passthrough", {"x": 1})
        client.call_tool("passthrough", {"x": 2})
        
        stats = client.get_statistics()
        assert "passthrough" in stats
        assert stats["passthrough"]["calls"] == 2

    def test_connect_http_and_call_tool(self):
        """Test calling a tool through an HTTP MCP endpoint."""
        responses = [
            {
                "jsonrpc": "2.0",
                "id": "init",
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "test-http-mcp", "version": "0.1.0"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": "list",
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Echo a value",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"value": {"type": "string"}},
                                "required": ["value"],
                            },
                        }
                    ]
                },
            },
            {
                "jsonrpc": "2.0",
                "id": "call",
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"echoed": "hello"})}]
                },
            },
        ]

        def fake_urlopen(req, timeout=30):  # noqa: ARG001
            return _FakeHTTPResponse(responses.pop(0))

        client = MCPClient(protocol_mode=True)

        from src.mcp_protocol import client as client_module

        original_urlopen = client_module.urllib_request.urlopen
        client_module.urllib_request.urlopen = fake_urlopen
        try:
            client.connect_http("http-test", "http://test-server/mcp")

            assert client.has_tool("echo")
            result = client.call_tool("echo", {"value": "hello"})

            assert result == {"echoed": "hello"}
        finally:
            client_module.urllib_request.urlopen = original_urlopen


class TestIntegration:
    """Integration tests for MCP protocol."""
    
    def test_full_workflow(self):
        """Test complete workflow from direct server registration to tool call."""
        client = MCPClient()
        wrapper = ToolWrapper("test")
        wrapper.wrap_function(lambda text: len(text), name="count_chars")
        client.register_server("test", wrapper)

        result = client.call_tool("count_chars", {"text": "hello world"})
        
        assert result == 11
    
    def test_mcp_request_response_cycle(self):
        """Test MCP request/response handling."""
        wrapper = ToolWrapper("test")
        wrapper.wrap_function(lambda n: n * 2, name="double_it")
        
        # Create request
        request = MCPRequest(
            id="test-1",
            method="tools/call",
            params={"name": "double_it", "arguments": {"n": 5}},
        )
        
        # Handle request
        response = wrapper.handle_request(request)
        
        assert response.id == "test-1"
        assert response.error is None
        assert response.result is not None
    
    def test_tools_list_request(self):
        """Test tools/list MCP request."""
        wrapper = ToolWrapper("test")
        wrapper.wrap_function(lambda: None, name="tool1")
        wrapper.wrap_function(lambda: None, name="tool2")
        
        request = MCPRequest(id="list-1", method="tools/list", params={})
        response = wrapper.handle_request(request)
        
        assert response.error is None
        assert "tools" in response.result
        assert len(response.result["tools"]) == 2


class TestAsyncOperations:
    """Tests for async operations."""
    
    @pytest.mark.asyncio
    async def test_async_tool_call(self):
        """Test async tool call."""
        client = MCPClient()
        wrapper = ToolWrapper("test")
        wrapper.wrap_function(lambda x: x.strip(), name="strip")
        client.register_server("test", wrapper)
        
        result = await client.call_tool_async("strip", {"x": "  hello  "})
        
        assert result == "hello"
    
    @pytest.mark.asyncio
    async def test_multiple_async_calls(self):
        """Test parallel async calls."""
        client = MCPClient()
        wrapper = ToolWrapper("test")
        wrapper.wrap_function(lambda x: x * 2, name="double")
        client.register_server("test", wrapper)
        
        results = await client.call_multiple_async([
            ("double", {"x": 1}),
            ("double", {"x": 2}),
            ("double", {"x": 3}),
        ])
        
        assert results == [2, 4, 6]
