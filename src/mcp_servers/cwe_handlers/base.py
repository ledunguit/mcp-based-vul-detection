"""
CWE Handler Base - Phase 3.1

Abstract base class for CWE-specific handlers.
Each handler defines sources, sinks, and safety checks for a vulnerability type.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class CWECategory(Enum):
    """Categories of vulnerabilities."""
    MEMORY = "memory"           # Buffer overflow, use-after-free
    INJECTION = "injection"     # SQL, Command, XSS
    TRAVERSAL = "traversal"     # Path traversal
    CRYPTO = "crypto"           # Cryptographic issues
    AUTH = "auth"               # Authentication/Authorization


@dataclass
class SourceInfo:
    """Information about a taint source."""
    name: str
    pattern: str  # Regex or exact match
    source_type: str  # e.g., "user_input", "file", "network"
    description: str = ""


@dataclass
class SinkInfo:
    """Information about a dangerous sink."""
    name: str
    pattern: str
    vulnerable_params: list[int] = field(default_factory=list)  # Which params are vulnerable
    risk_level: str = "high"  # high, medium, low
    description: str = ""


@dataclass
class SafetyCheck:
    """A safety check that mitigates the vulnerability."""
    name: str
    pattern: str
    check_type: str  # "sanitize", "validate", "encode", "escape"
    description: str = ""


@dataclass
class CWEDefinition:
    """Complete definition of a CWE."""
    cwe_id: int
    name: str
    category: CWECategory
    description: str
    sources: list[SourceInfo]
    sinks: list[SinkInfo]
    safety_checks: list[SafetyCheck]
    related_cwes: list[int] = field(default_factory=list)
    mitre_url: str = ""


class CWEHandler(ABC):
    """
    Abstract base class for CWE-specific handlers.
    
    Each handler provides:
    - Get sources: Where untrusted data enters
    - Get sinks: Where untrusted data is dangerous
    - Get safety checks: What mitigations are expected
    - Validate: Check if code is vulnerable
    """
    
    @property
    @abstractmethod
    def cwe_ids(self) -> list[int]:
        """List of CWE IDs this handler covers."""
        pass
    
    @property
    @abstractmethod
    def category(self) -> CWECategory:
        """Category of this vulnerability."""
        pass
    
    @abstractmethod
    def get_sources(self) -> list[SourceInfo]:
        """Get all taint sources for this CWE."""
        pass
    
    @abstractmethod
    def get_sinks(self) -> list[SinkInfo]:
        """Get all dangerous sinks for this CWE."""
        pass
    
    @abstractmethod
    def get_safety_checks(self, sink_name: str = None) -> list[SafetyCheck]:
        """
        Get safety checks for this CWE.
        
        Args:
            sink_name: Optional sink to get specific checks for
        
        Returns:
            List of safety checks
        """
        pass
    
    @abstractmethod
    def get_definition(self) -> CWEDefinition:
        """Get complete CWE definition."""
        pass
    
    def get_source_names(self) -> list[str]:
        """Get list of source names."""
        return [s.name for s in self.get_sources()]
    
    def get_sink_names(self) -> list[str]:
        """Get list of sink names."""
        return [s.name for s in self.get_sinks()]
    
    def is_source(self, name: str) -> bool:
        """Check if a name is a source."""
        return name in self.get_source_names()
    
    def is_sink(self, name: str) -> bool:
        """Check if a name is a sink."""
        return name in self.get_sink_names()


class CWERegistry:
    """Registry for all CWE handlers."""
    
    def __init__(self):
        self._handlers: dict[int, CWEHandler] = {}
        self._category_handlers: dict[CWECategory, list[CWEHandler]] = {}
    
    def register(self, handler: CWEHandler) -> None:
        """Register a CWE handler."""
        for cwe_id in handler.cwe_ids:
            self._handlers[cwe_id] = handler
        
        if handler.category not in self._category_handlers:
            self._category_handlers[handler.category] = []
        self._category_handlers[handler.category].append(handler)
    
    def get_handler(self, cwe_id: int) -> Optional[CWEHandler]:
        """Get handler for a specific CWE."""
        return self._handlers.get(cwe_id)
    
    def get_handlers_by_category(self, category: CWECategory) -> list[CWEHandler]:
        """Get all handlers for a category."""
        return self._category_handlers.get(category, [])
    
    def get_all_sources(self) -> dict[int, list[SourceInfo]]:
        """Get all sources grouped by CWE."""
        return {
            cwe_id: handler.get_sources()
            for cwe_id, handler in self._handlers.items()
        }
    
    def get_all_sinks(self) -> dict[int, list[SinkInfo]]:
        """Get all sinks grouped by CWE."""
        return {
            cwe_id: handler.get_sinks()
            for cwe_id, handler in self._handlers.items()
        }
    
    def list_supported_cwes(self) -> list[int]:
        """List all supported CWE IDs."""
        return list(self._handlers.keys())


# Global registry
_global_registry = CWERegistry()


def get_registry() -> CWERegistry:
    """Get the global CWE registry."""
    return _global_registry


def register_handler(handler: CWEHandler) -> None:
    """Register a handler with the global registry."""
    _global_registry.register(handler)
