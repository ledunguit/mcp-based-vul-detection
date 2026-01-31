"""
CWE Handlers Module - Phase 3.1

Provides CWE-specific handlers for multi-vulnerability detection.
Each handler defines sources, sinks, and safety checks for a vulnerability type.

Supported CWEs:
- Buffer Overflow: CWE-120, 121, 122, 125, 787
- SQL Injection: CWE-89
- Command Injection: CWE-78
- XSS: CWE-79
- Path Traversal: CWE-22, 23, 36
"""

from .base import (
    CWEHandler,
    CWECategory,
    CWEDefinition,
    CWERegistry,
    SourceInfo,
    SinkInfo,
    SafetyCheck,
    get_registry,
    register_handler,
)

# Import handlers to trigger auto-registration
from . import buffer_overflow
from . import sql_injection
from . import command_injection
from . import xss
from . import path_traversal

# Convenience imports
from .buffer_overflow import BufferOverflowHandler
from .sql_injection import SQLInjectionHandler
from .command_injection import CommandInjectionHandler
from .xss import XSSHandler
from .path_traversal import PathTraversalHandler


__all__ = [
    # Base classes
    "CWEHandler",
    "CWECategory",
    "CWEDefinition",
    "CWERegistry",
    "SourceInfo",
    "SinkInfo",
    "SafetyCheck",
    # Registry
    "get_registry",
    "register_handler",
    # Handlers
    "BufferOverflowHandler",
    "SQLInjectionHandler",
    "CommandInjectionHandler",
    "XSSHandler",
    "PathTraversalHandler",
]


def get_handler_for_cwe(cwe_id: int) -> CWEHandler:
    """Get handler for a specific CWE ID."""
    return get_registry().get_handler(cwe_id)


def list_supported_cwes() -> list[int]:
    """List all supported CWE IDs."""
    return get_registry().list_supported_cwes()


def get_all_sources() -> dict[int, list[SourceInfo]]:
    """Get all sources grouped by CWE."""
    return get_registry().get_all_sources()


def get_all_sinks() -> dict[int, list[SinkInfo]]:
    """Get all sinks grouped by CWE."""
    return get_registry().get_all_sinks()
