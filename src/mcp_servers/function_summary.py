"""
Function Summary Module - Phase 2.1

Provides data structures and utilities for summarizing function
taint behavior for inter-procedural analysis.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class TaintEffect(Enum):
    """Effect of a function on taint propagation."""
    PROPAGATES = "propagates"      # Taint from input flows to output
    SANITIZES = "sanitizes"        # Function sanitizes/validates input
    SINK = "sink"                  # Function is a security sink
    SOURCE = "source"              # Function is a taint source
    NEUTRAL = "neutral"            # No effect on taint


@dataclass
class ParameterTaint:
    """Taint information for a single parameter."""
    index: int
    name: str
    is_source: bool = False           # Parameter receives external input
    is_sink: bool = False             # Parameter used in dangerous operation
    propagates_to_return: bool = False  # Taint flows to return value
    propagates_to_params: list[int] = field(default_factory=list)  # Indices of output params


@dataclass
class FunctionSummary:
    """
    Summary of a function's taint behavior for inter-procedural analysis.
    
    This captures:
    - Which parameters are taint sources (receive external input)
    - Which parameters are taint sinks (used dangerously)
    - How taint propagates through the function
    - What validation the function performs
    
    Example:
        For: void copy_data(char *dest, char *src, size_t len)
        
        FunctionSummary(
            name="copy_data",
            parameters=[
                ParameterTaint(0, "dest", is_sink=True),
                ParameterTaint(1, "src", propagates_to_params=[0]),
                ParameterTaint(2, "len"),
            ],
            returns_tainted=False,
            validates_bounds=True,
        )
    """
    name: str
    file_path: Optional[str] = None
    
    # Parameter taint information
    parameters: list[ParameterTaint] = field(default_factory=list)
    
    # Return value taint
    returns_tainted: bool = False
    return_tainted_from_params: list[int] = field(default_factory=list)
    
    # Validation behavior
    validates_bounds: bool = False  # Checks array/buffer bounds
    validates_null: bool = False    # Checks for NULL
    validates_format: bool = False  # Validates format strings
    sanitizes_input: bool = False   # Sanitizes/escapes input
    
    # Called functions (for call graph)
    calls: list[str] = field(default_factory=list)
    
    # Risk assessment
    is_external: bool = False       # External library function
    is_wrapper: bool = False        # Thin wrapper around risky function
    risk_level: str = "low"         # low, medium, high
    
    def get_sink_params(self) -> list[int]:
        """Get indices of parameters that are sinks."""
        return [p.index for p in self.parameters if p.is_sink]
    
    def get_source_params(self) -> list[int]:
        """Get indices of parameters that are sources."""
        return [p.index for p in self.parameters if p.is_source]
    
    def get_taint_propagation(self) -> dict[int, list[int]]:
        """
        Get taint propagation map.
        
        Returns:
            Dict mapping source param indices to list of tainted outputs.
            Output indices: -1 for return value, >=0 for parameter indices.
        """
        propagation = {}
        for p in self.parameters:
            outputs = list(p.propagates_to_params)
            if p.propagates_to_return:
                outputs.append(-1)
            if outputs:
                propagation[p.index] = outputs
        return propagation
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "file_path": self.file_path,
            "parameters": [
                {
                    "index": p.index,
                    "name": p.name,
                    "is_source": p.is_source,
                    "is_sink": p.is_sink,
                    "propagates_to_return": p.propagates_to_return,
                    "propagates_to_params": p.propagates_to_params,
                }
                for p in self.parameters
            ],
            "returns_tainted": self.returns_tainted,
            "return_tainted_from_params": self.return_tainted_from_params,
            "validates_bounds": self.validates_bounds,
            "validates_null": self.validates_null,
            "sanitizes_input": self.sanitizes_input,
            "calls": self.calls,
            "is_external": self.is_external,
            "risk_level": self.risk_level,
        }


# Built-in function summaries for common C library functions
BUILTIN_SUMMARIES: dict[str, FunctionSummary] = {}


def _init_builtin_summaries():
    """Initialize built-in function summaries."""
    global BUILTIN_SUMMARIES
    
    # Dangerous string functions (CWE-120 related)
    BUILTIN_SUMMARIES["strcpy"] = FunctionSummary(
        name="strcpy",
        is_external=True,
        risk_level="high",
        parameters=[
            ParameterTaint(0, "dest", is_sink=True),
            ParameterTaint(1, "src", propagates_to_params=[0]),
        ],
        returns_tainted=True,
        return_tainted_from_params=[1],
    )
    
    BUILTIN_SUMMARIES["strncpy"] = FunctionSummary(
        name="strncpy",
        is_external=True,
        risk_level="medium",
        validates_bounds=True,
        parameters=[
            ParameterTaint(0, "dest", is_sink=True),
            ParameterTaint(1, "src", propagates_to_params=[0]),
            ParameterTaint(2, "n"),
        ],
        returns_tainted=True,
        return_tainted_from_params=[1],
    )
    
    BUILTIN_SUMMARIES["memcpy"] = FunctionSummary(
        name="memcpy",
        is_external=True,
        risk_level="medium",
        parameters=[
            ParameterTaint(0, "dest", is_sink=True),
            ParameterTaint(1, "src", propagates_to_params=[0]),
            ParameterTaint(2, "n"),
        ],
        returns_tainted=True,
        return_tainted_from_params=[1],
    )
    
    BUILTIN_SUMMARIES["sprintf"] = FunctionSummary(
        name="sprintf",
        is_external=True,
        risk_level="high",
        parameters=[
            ParameterTaint(0, "str", is_sink=True),
            ParameterTaint(1, "format"),
            # Variadic args would propagate to str
        ],
        returns_tainted=False,
    )
    
    BUILTIN_SUMMARIES["snprintf"] = FunctionSummary(
        name="snprintf",
        is_external=True,
        risk_level="low",
        validates_bounds=True,
        parameters=[
            ParameterTaint(0, "str", is_sink=True),
            ParameterTaint(1, "size"),
            ParameterTaint(2, "format"),
        ],
        returns_tainted=False,
    )
    
    BUILTIN_SUMMARIES["gets"] = FunctionSummary(
        name="gets",
        is_external=True,
        risk_level="high",
        parameters=[
            ParameterTaint(0, "s", is_source=True, is_sink=True),
        ],
        returns_tainted=True,
        return_tainted_from_params=[0],
    )
    
    BUILTIN_SUMMARIES["fgets"] = FunctionSummary(
        name="fgets",
        is_external=True,
        risk_level="low",
        validates_bounds=True,
        parameters=[
            ParameterTaint(0, "s", is_source=True),
            ParameterTaint(1, "size"),
            ParameterTaint(2, "stream"),
        ],
        returns_tainted=True,
        return_tainted_from_params=[0],
    )
    
    # Input functions (sources)
    BUILTIN_SUMMARIES["scanf"] = FunctionSummary(
        name="scanf",
        is_external=True,
        risk_level="high",
        parameters=[
            ParameterTaint(0, "format"),
            # Variadic args are sources
        ],
        returns_tainted=False,
    )
    
    BUILTIN_SUMMARIES["read"] = FunctionSummary(
        name="read",
        is_external=True,
        risk_level="medium",
        parameters=[
            ParameterTaint(0, "fd"),
            ParameterTaint(1, "buf", is_source=True),
            ParameterTaint(2, "count"),
        ],
        returns_tainted=False,
    )
    
    # Memory allocation
    BUILTIN_SUMMARIES["malloc"] = FunctionSummary(
        name="malloc",
        is_external=True,
        risk_level="low",
        parameters=[
            ParameterTaint(0, "size"),
        ],
        returns_tainted=False,
    )
    
    # String length functions (neutral)
    BUILTIN_SUMMARIES["strlen"] = FunctionSummary(
        name="strlen",
        is_external=True,
        risk_level="low",
        parameters=[
            ParameterTaint(0, "s"),
        ],
        returns_tainted=False,
    )
    
    # Sanitization functions
    BUILTIN_SUMMARIES["strnlen"] = FunctionSummary(
        name="strnlen",
        is_external=True,
        risk_level="low",
        validates_bounds=True,
        parameters=[
            ParameterTaint(0, "s"),
            ParameterTaint(1, "maxlen"),
        ],
        returns_tainted=False,
    )


# Initialize on import
_init_builtin_summaries()


def get_builtin_summary(func_name: str) -> Optional[FunctionSummary]:
    """Get summary for a built-in C library function."""
    return BUILTIN_SUMMARIES.get(func_name)


def is_sink_function(func_name: str) -> bool:
    """Check if a function is a known sink."""
    summary = get_builtin_summary(func_name)
    if summary:
        return any(p.is_sink for p in summary.parameters)
    return False


def is_source_function(func_name: str) -> bool:
    """Check if a function is a known source."""
    summary = get_builtin_summary(func_name)
    if summary:
        return any(p.is_source for p in summary.parameters)
    return False
