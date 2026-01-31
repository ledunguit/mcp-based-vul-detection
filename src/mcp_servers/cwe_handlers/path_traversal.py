"""
Path Traversal Handler - CWE-22

Handles Path Traversal vulnerabilities.
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


class PathTraversalHandler(CWEHandler):
    """Handler for Path Traversal vulnerabilities."""
    
    @property
    def cwe_ids(self) -> list[int]:
        return [22, 23, 36]  # Path traversal variants
    
    @property
    def category(self) -> CWECategory:
        return CWECategory.TRAVERSAL
    
    def get_sources(self) -> list[SourceInfo]:
        return [
            # User input
            SourceInfo("request.GET", r"request\.GET", "user_input", "HTTP GET"),
            SourceInfo("request.POST", r"request\.POST", "user_input", "HTTP POST"),
            SourceInfo("request.params", r"request\.params", "user_input", "Request params"),
            SourceInfo("request.query", r"request\.query", "user_input", "Query string"),
            # System sources
            SourceInfo("argv", "argv", "command_line", "Command line"),
            SourceInfo("getenv", "getenv", "environment", "Environment variable"),
            SourceInfo("fgets", "fgets", "file_input", "File input"),
            SourceInfo("scanf", "scanf", "stdin", "Standard input"),
        ]
    
    def get_sinks(self) -> list[SinkInfo]:
        return [
            # File operations
            SinkInfo("fopen", "fopen", [0], "high", "File open"),
            SinkInfo("open", "open", [0], "high", "POSIX open"),
            SinkInfo("fread", "fread", [3], "medium", "File read"),
            SinkInfo("fwrite", "fwrite", [3], "high", "File write"),
            SinkInfo("remove", "remove", [0], "high", "File delete"),
            SinkInfo("unlink", "unlink", [0], "high", "File unlink"),
            SinkInfo("rename", "rename", [0, 1], "high", "File rename"),
            SinkInfo("mkdir", "mkdir", [0], "medium", "Create directory"),
            SinkInfo("rmdir", "rmdir", [0], "high", "Remove directory"),
            # Include/require
            SinkInfo("include", "include", [0], "high", "File include"),
            SinkInfo("require", "require", [0], "high", "File require"),
            # System specific
            SinkInfo("CreateFile", "CreateFileA?W?", [0], "high", "Windows file create"),
            SinkInfo("ReadFile", "ReadFile", [0], "medium", "Windows file read"),
        ]
    
    def get_safety_checks(self, sink_name: str = None) -> list[SafetyCheck]:
        return [
            SafetyCheck("realpath", "realpath", "validate", "Canonicalize path"),
            SafetyCheck("basename", "basename", "sanitize", "Extract basename"),
            SafetyCheck("no_dotdot", r"\.\.\/|\.\.", "validate", "Block parent directory"),
            SafetyCheck("chroot", "chroot", "validate", "Chroot jail"),
            SafetyCheck("whitelist", r"strcmp|strncmp", "validate", "Path whitelist"),
            SafetyCheck("startswith", r"startswith|strncmp|^\/allowed", "validate", "Path prefix check"),
            SafetyCheck("access_check", "access", "validate", "Access permission check"),
        ]
    
    def get_definition(self) -> CWEDefinition:
        return CWEDefinition(
            cwe_id=22,
            name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            category=self.category,
            description="The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.",
            sources=self.get_sources(),
            sinks=self.get_sinks(),
            safety_checks=self.get_safety_checks(),
            related_cwes=[23, 36, 73],
            mitre_url="https://cwe.mitre.org/data/definitions/22.html",
        )


# Auto-register on import
_handler = PathTraversalHandler()
register_handler(_handler)
