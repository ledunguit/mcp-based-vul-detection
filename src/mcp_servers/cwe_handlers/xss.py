"""
XSS Handler - CWE-79

Handles Cross-site Scripting vulnerabilities.
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


class XSSHandler(CWEHandler):
    """Handler for Cross-site Scripting vulnerabilities."""
    
    @property
    def cwe_ids(self) -> list[int]:
        return [79]
    
    @property
    def category(self) -> CWECategory:
        return CWECategory.INJECTION
    
    def get_sources(self) -> list[SourceInfo]:
        return [
            # User input sources
            SourceInfo("request.GET", r"request\.GET", "user_input", "HTTP GET parameters"),
            SourceInfo("request.POST", r"request\.POST", "user_input", "HTTP POST data"),
            SourceInfo("request.params", r"request\.params", "user_input", "Request parameters"),
            SourceInfo("request.query", r"request\.query", "user_input", "Query string"),
            SourceInfo("request.body", r"request\.body", "user_input", "Request body"),
            SourceInfo("request.cookies", r"request\.cookies", "user_input", "Cookies"),
            SourceInfo("request.headers", r"request\.headers", "user_input", "Request headers"),
            # URL sources
            SourceInfo("location", r"location\.", "url", "URL location"),
            SourceInfo("document.URL", r"document\.URL", "url", "Document URL"),
            SourceInfo("document.referrer", r"document\.referrer", "url", "Referrer"),
            # DOM sources
            SourceInfo("innerHTML", r"\.innerHTML", "dom", "Inner HTML"),
            SourceInfo("localStorage", r"localStorage", "storage", "Local storage"),
            # Database (stored XSS)
            SourceInfo("fetch", r"fetch\w*|SELECT", "database", "Database content"),
        ]
    
    def get_sinks(self) -> list[SinkInfo]:
        return [
            # DOM manipulation
            SinkInfo("innerHTML", r"\.innerHTML\s*=", [0], "high", "HTML injection"),
            SinkInfo("outerHTML", r"\.outerHTML\s*=", [0], "high", "HTML injection"),
            SinkInfo("document.write", r"document\.write", [0], "high", "Document write"),
            SinkInfo("document.writeln", r"document\.writeln", [0], "high", "Document writeln"),
            # JavaScript execution
            SinkInfo("eval", "eval", [0], "high", "JavaScript eval"),
            SinkInfo("setTimeout", "setTimeout", [0], "high", "Timeout eval"),
            SinkInfo("setInterval", "setInterval", [0], "high", "Interval eval"),
            SinkInfo("Function", "Function", [0], "high", "Function constructor"),
            # Server-side rendering
            SinkInfo("render", r"\.render\s*\(", [0], "medium", "Template render"),
            SinkInfo("printf", "printf", [0], "medium", "Unescaped output"),
            SinkInfo("echo", "echo", [0], "medium", "Direct output"),
            # Response writing
            SinkInfo("response.write", r"response\.write", [0], "high", "Response write"),
            SinkInfo("send", r"\.send\s*\(", [0], "medium", "Send response"),
        ]
    
    def get_safety_checks(self, sink_name: str = None) -> list[SafetyCheck]:
        return [
            SafetyCheck("html_encode", r"htmlEncode|escapeHtml|htmlspecialchars", "encode", "HTML encoding"),
            SafetyCheck("html_escape", r"escape|sanitize", "escape", "HTML escaping"),
            SafetyCheck("text_content", r"textContent|innerText", "sanitize", "Use text content"),
            SafetyCheck("dompurify", r"DOMPurify|purify", "sanitize", "DOM sanitization"),
            SafetyCheck("csp", r"Content-Security-Policy", "validate", "Content Security Policy"),
            SafetyCheck("template_auto", r"{{|{%|<%", "escape", "Template auto-escaping"),
            SafetyCheck("encode_uri", r"encodeURI|encodeURIComponent", "encode", "URL encoding"),
        ]
    
    def get_definition(self) -> CWEDefinition:
        return CWEDefinition(
            cwe_id=79,
            name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            category=self.category,
            description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
            sources=self.get_sources(),
            sinks=self.get_sinks(),
            safety_checks=self.get_safety_checks(),
            related_cwes=[80, 81, 83],  # XSS variants
            mitre_url="https://cwe.mitre.org/data/definitions/79.html",
        )


# Auto-register on import
_handler = XSSHandler()
register_handler(_handler)
