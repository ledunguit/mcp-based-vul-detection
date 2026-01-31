"""
Buffer Overflow Handler - CWE-120, 121, 122, 125, 787

Handles buffer overflow family vulnerabilities in C/C++ code.
"""

from .base import (
    CWEHandler,
    CWECategory,
    CWEDefinition,
    SourceInfo,
    SinkInfo,
    SafetyCheck,
    register_handler,
)


class BufferOverflowHandler(CWEHandler):
    """Handler for buffer overflow vulnerabilities."""
    
    @property
    def cwe_ids(self) -> list[int]:
        return [120, 121, 122, 125, 787]
    
    @property
    def category(self) -> CWECategory:
        return CWECategory.MEMORY
    
    def get_sources(self) -> list[SourceInfo]:
        return [
            SourceInfo("gets", "gets", "stdin", "Reads unbounded input from stdin"),
            SourceInfo("fgets", "fgets", "file_input", "Reads from file/stdin"),
            SourceInfo("scanf", "scanf", "stdin", "Formatted stdin input"),
            SourceInfo("fscanf", "fscanf", "file_input", "Formatted file input"),
            SourceInfo("read", "read", "file_descriptor", "Low-level file read"),
            SourceInfo("recv", "recv", "network", "Network socket receive"),
            SourceInfo("recvfrom", "recvfrom", "network", "UDP receive"),
            SourceInfo("getenv", "getenv", "environment", "Environment variable"),
            SourceInfo("argv", "argv", "command_line", "Command line arguments"),
            SourceInfo("fread", "fread", "file_input", "Binary file read"),
        ]
    
    def get_sinks(self) -> list[SinkInfo]:
        return [
            SinkInfo("strcpy", "strcpy", [0], "high", "Unbounded string copy"),
            SinkInfo("strcat", "strcat", [0], "high", "Unbounded string concatenation"),
            SinkInfo("sprintf", "sprintf", [0], "high", "Unbounded formatted string"),
            SinkInfo("vsprintf", "vsprintf", [0], "high", "Unbounded variadic sprintf"),
            SinkInfo("gets", "gets", [0], "high", "Unbounded stdin read"),
            SinkInfo("memcpy", "memcpy", [0], "medium", "Memory copy (size param exists)"),
            SinkInfo("memmove", "memmove", [0], "medium", "Memory move"),
            SinkInfo("strncpy", "strncpy", [0], "low", "Bounded copy (if used correctly)"),
            SinkInfo("strncat", "strncat", [0], "low", "Bounded concat"),
            SinkInfo("snprintf", "snprintf", [0], "low", "Bounded sprintf"),
            SinkInfo("scanf", "scanf", [], "medium", "May overflow if no width specifier"),
        ]
    
    def get_safety_checks(self, sink_name: str = None) -> list[SafetyCheck]:
        checks = [
            SafetyCheck("strlen_check", r"strlen\s*\([^)]+\)", "validate", "Check string length"),
            SafetyCheck("sizeof_check", r"sizeof\s*\([^)]+\)", "validate", "Check buffer size"),
            SafetyCheck("bounds_compare", r"[<>]=?\s*\d+", "validate", "Numeric bounds check"),
            SafetyCheck("null_check", r"!=\s*NULL|==\s*NULL", "validate", "Null pointer check"),
        ]
        
        if sink_name == "strcpy":
            checks.append(SafetyCheck("use_strncpy", "strncpy", "sanitize", "Use bounded strncpy"))
        elif sink_name == "sprintf":
            checks.append(SafetyCheck("use_snprintf", "snprintf", "sanitize", "Use bounded snprintf"))
        elif sink_name == "scanf":
            checks.append(SafetyCheck("width_specifier", r"%\d+s", "validate", "Use width specifier"))
        
        return checks
    
    def get_definition(self) -> CWEDefinition:
        return CWEDefinition(
            cwe_id=120,
            name="Buffer Copy without Checking Size of Input",
            category=self.category,
            description="The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.",
            sources=self.get_sources(),
            sinks=self.get_sinks(),
            safety_checks=self.get_safety_checks(),
            related_cwes=[121, 122, 125, 787],
            mitre_url="https://cwe.mitre.org/data/definitions/120.html",
        )


# Auto-register on import
_handler = BufferOverflowHandler()
register_handler(_handler)
