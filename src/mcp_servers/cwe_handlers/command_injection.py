"""
Command Injection Handler - CWE-78

Handles OS Command Injection vulnerabilities.
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


class CommandInjectionHandler(CWEHandler):
    """Handler for OS Command Injection vulnerabilities."""
    
    @property
    def cwe_ids(self) -> list[int]:
        return [78]
    
    @property
    def category(self) -> CWECategory:
        return CWECategory.INJECTION
    
    def get_sources(self) -> list[SourceInfo]:
        return [
            # Web input sources
            SourceInfo("request.GET", r"request\.GET", "user_input", "HTTP GET parameters"),
            SourceInfo("request.POST", r"request\.POST", "user_input", "HTTP POST data"),
            SourceInfo("request.params", r"request\.params", "user_input", "Request parameters"),
            # System input
            SourceInfo("argv", "argv", "command_line", "Command line arguments"),
            SourceInfo("getenv", "getenv", "environment", "Environment variable"),
            SourceInfo("fgets", "fgets", "file_input", "File/stdin input"),
            SourceInfo("scanf", "scanf", "stdin", "Standard input"),
            SourceInfo("read", "read", "file_descriptor", "Low-level read"),
            # Network
            SourceInfo("recv", "recv", "network", "Network receive"),
        ]
    
    def get_sinks(self) -> list[SinkInfo]:
        return [
            # C/C++ command execution
            SinkInfo("system", "system", [0], "high", "System shell command"),
            SinkInfo("popen", "popen", [0], "high", "Pipe open with shell"),
            SinkInfo("exec", r"exec[lv]?[pe]?", [0], "high", "Exec family"),
            SinkInfo("execl", "execl", [0], "high", "Execute with list args"),
            SinkInfo("execv", "execv", [0], "high", "Execute with vector args"),
            SinkInfo("execlp", "execlp", [0], "high", "Execute with PATH search"),
            SinkInfo("execvp", "execvp", [0], "high", "Execute with PATH search"),
            SinkInfo("spawn", r"spawn[lv]?[pe]?", [0], "high", "Spawn process"),
            SinkInfo("ShellExecute", "ShellExecute", [2], "high", "Windows shell execute"),
            SinkInfo("CreateProcess", "CreateProcess", [1], "high", "Windows create process"),
            # Shell command building
            SinkInfo("sprintf", "sprintf", [0], "medium", "Format for shell command"),
        ]
    
    def get_safety_checks(self, sink_name: str = None) -> list[SafetyCheck]:
        return [
            SafetyCheck("whitelist", r"strcmp|strncmp|==", "validate", "String comparison whitelist"),
            SafetyCheck("shell_escape", r"escapeshell|quote", "escape", "Shell escaping"),
            SafetyCheck("no_shell_chars", r"[^\w\-\./]", "validate", "Block shell metacharacters"),
            SafetyCheck("regex_validate", r"regcomp|regex|match", "validate", "Regex validation"),
            SafetyCheck("array_exec", r"execv\w*", "sanitize", "Use array-based exec"),
            SafetyCheck("path_check", r"realpath|access", "validate", "Path validation"),
        ]
    
    def get_definition(self) -> CWEDefinition:
        return CWEDefinition(
            cwe_id=78,
            name="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            category=self.category,
            description="The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
            sources=self.get_sources(),
            sinks=self.get_sinks(),
            safety_checks=self.get_safety_checks(),
            related_cwes=[77, 88],  # Command injection, argument injection
            mitre_url="https://cwe.mitre.org/data/definitions/78.html",
        )


# Auto-register on import
_handler = CommandInjectionHandler()
register_handler(_handler)
