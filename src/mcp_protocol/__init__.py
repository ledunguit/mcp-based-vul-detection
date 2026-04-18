"""
MCP Protocol Implementation - Phase 1.2

This module provides the base classes and utilities for implementing
a true MCP (Model Context Protocol) server-client architecture.

The implementation allows tools to be called either:
1. Directly as Python functions (legacy mode - for testing/development)
2. Via MCP protocol (production mode - for full protocol compliance)
"""

from .base_server import MCPServer, MCPToolDefinition
from .client import MCPClient

__all__ = [
    "MCPServer",
    "MCPToolDefinition",
    "MCPClient",
]
