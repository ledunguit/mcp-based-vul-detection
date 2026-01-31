"""
SQL Injection Handler - CWE-89

Handles SQL Injection vulnerabilities.
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


class SQLInjectionHandler(CWEHandler):
    """Handler for SQL Injection vulnerabilities."""
    
    @property
    def cwe_ids(self) -> list[int]:
        return [89]
    
    @property
    def category(self) -> CWECategory:
        return CWECategory.INJECTION
    
    def get_sources(self) -> list[SourceInfo]:
        return [
            # Web input sources
            SourceInfo("request.GET", r"request\.GET", "user_input", "HTTP GET parameters"),
            SourceInfo("request.POST", r"request\.POST", "user_input", "HTTP POST data"),
            SourceInfo("request.params", r"request\.params", "user_input", "Request parameters"),
            SourceInfo("request.form", r"request\.form", "user_input", "Form data"),
            SourceInfo("request.args", r"request\.args", "user_input", "URL arguments"),
            SourceInfo("request.query", r"request\.query", "user_input", "Query string"),
            # C/C++ specific
            SourceInfo("argv", "argv", "command_line", "Command line arguments"),
            SourceInfo("getenv", "getenv", "environment", "Environment variable"),
            SourceInfo("fgets", "fgets", "file_input", "File input"),
            SourceInfo("scanf", "scanf", "stdin", "Standard input"),
            # Database result as source for second-order
            SourceInfo("fetch", r"fetch\w*", "database", "Database fetch (second-order)"),
        ]
    
    def get_sinks(self) -> list[SinkInfo]:
        return [
            # Raw SQL execution
            SinkInfo("execute", r"\.execute\s*\(", [0], "high", "SQL execute"),
            SinkInfo("executemany", r"\.executemany\s*\(", [0], "high", "SQL execute many"),
            SinkInfo("raw", r"\.raw\s*\(", [0], "high", "Raw SQL query"),
            SinkInfo("query", r"\.query\s*\(", [0], "high", "Direct SQL query"),
            # C/C++ database APIs
            SinkInfo("mysql_query", "mysql_query", [1], "high", "MySQL query"),
            SinkInfo("sqlite3_exec", "sqlite3_exec", [1], "high", "SQLite execute"),
            SinkInfo("PQexec", "PQexec", [1], "high", "PostgreSQL execute"),
            # String concatenation building SQL
            SinkInfo("sprintf", "sprintf", [0], "medium", "String format (SQL building)"),
            SinkInfo("strcat", "strcat", [0], "medium", "String concat (SQL building)"),
        ]
    
    def get_safety_checks(self, sink_name: str = None) -> list[SafetyCheck]:
        return [
            SafetyCheck("parameterized", r"\?|%s|\$\d+|:\w+", "sanitize", "Parameterized query"),
            SafetyCheck("prepared_stmt", r"prepare|PreparedStatement", "sanitize", "Prepared statement"),
            SafetyCheck("escape_string", r"escape|quote|sanitize", "escape", "String escaping"),
            SafetyCheck("orm_filter", r"\.filter\s*\(|\.where\s*\(", "sanitize", "ORM filtering"),
            SafetyCheck("whitelist", r"in\s*\[|in\s*\(", "validate", "Whitelist validation"),
            SafetyCheck("mysql_escape", "mysql_real_escape_string", "escape", "MySQL escape"),
            SafetyCheck("sqlite_bind", "sqlite3_bind", "sanitize", "SQLite parameter binding"),
        ]
    
    def get_definition(self) -> CWEDefinition:
        return CWEDefinition(
            cwe_id=89,
            name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            category=self.category,
            description="The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
            sources=self.get_sources(),
            sinks=self.get_sinks(),
            safety_checks=self.get_safety_checks(),
            related_cwes=[564, 943],  # Hibernate injection, LDAP injection
            mitre_url="https://cwe.mitre.org/data/definitions/89.html",
        )


# Auto-register on import
_handler = SQLInjectionHandler()
register_handler(_handler)
