"""Tests for Phase 3.1 Multi-CWE Support."""

import pytest
from src.mcp_servers.cwe_handlers import (
    CWEHandler,
    CWECategory,
    CWERegistry,
    get_registry,
    list_supported_cwes,
    get_handler_for_cwe,
    get_all_sources,
    get_all_sinks,
    BufferOverflowHandler,
    SQLInjectionHandler,
    CommandInjectionHandler,
    XSSHandler,
    PathTraversalHandler,
)


class TestCWERegistry:
    """Tests for CWE Registry."""
    
    def test_registry_has_handlers(self):
        """Registry should have registered handlers."""
        registry = get_registry()
        assert len(registry.list_supported_cwes()) > 0
    
    def test_list_supported_cwes(self):
        """Should list all supported CWEs."""
        cwes = list_supported_cwes()
        # Should have at least buffer overflow + injection types
        assert 120 in cwes  # Buffer overflow
        assert 89 in cwes   # SQL injection
        assert 78 in cwes   # Command injection
        assert 79 in cwes   # XSS
        assert 22 in cwes   # Path traversal
    
    def test_get_handler_for_cwe(self):
        """Should get correct handler for CWE."""
        handler = get_handler_for_cwe(120)
        assert handler is not None
        assert 120 in handler.cwe_ids
    
    def test_get_all_sources(self):
        """Should get sources for all CWEs."""
        sources = get_all_sources()
        assert len(sources) > 0
        # Buffer overflow should have stdin sources
        assert 120 in sources
        source_names = [s.name for s in sources[120]]
        assert "gets" in source_names
    
    def test_get_all_sinks(self):
        """Should get sinks for all CWEs."""
        sinks = get_all_sinks()
        assert len(sinks) > 0
        # Buffer overflow should have strcpy sink
        assert 120 in sinks
        sink_names = [s.name for s in sinks[120]]
        assert "strcpy" in sink_names


class TestBufferOverflowHandler:
    """Tests for Buffer Overflow Handler."""
    
    def test_cwe_ids(self):
        """Should handle multiple buffer overflow CWEs."""
        handler = BufferOverflowHandler()
        assert 120 in handler.cwe_ids
        assert 121 in handler.cwe_ids
        assert 787 in handler.cwe_ids
    
    def test_category(self):
        """Should be memory category."""
        handler = BufferOverflowHandler()
        assert handler.category == CWECategory.MEMORY
    
    def test_sources(self):
        """Should have stdin and network sources."""
        handler = BufferOverflowHandler()
        sources = handler.get_sources()
        source_names = handler.get_source_names()
        
        assert "gets" in source_names
        assert "recv" in source_names
        assert "argv" in source_names
    
    def test_sinks(self):
        """Should have dangerous string functions."""
        handler = BufferOverflowHandler()
        sinks = handler.get_sinks()
        sink_names = handler.get_sink_names()
        
        assert "strcpy" in sink_names
        assert "sprintf" in sink_names
        assert handler.is_sink("strcpy")
    
    def test_safety_checks(self):
        """Should have bounds checking patterns."""
        handler = BufferOverflowHandler()
        checks = handler.get_safety_checks()
        check_names = [c.name for c in checks]
        
        assert "strlen_check" in check_names
        assert "sizeof_check" in check_names
    
    def test_definition(self):
        """Should have complete CWE definition."""
        handler = BufferOverflowHandler()
        defn = handler.get_definition()
        
        assert defn.cwe_id == 120
        assert "Buffer" in defn.name
        assert len(defn.sources) > 0
        assert len(defn.sinks) > 0


class TestSQLInjectionHandler:
    """Tests for SQL Injection Handler."""
    
    def test_cwe_ids(self):
        """Should handle CWE-89."""
        handler = SQLInjectionHandler()
        assert 89 in handler.cwe_ids
    
    def test_category(self):
        """Should be injection category."""
        handler = SQLInjectionHandler()
        assert handler.category == CWECategory.INJECTION
    
    def test_sources(self):
        """Should have web input sources."""
        handler = SQLInjectionHandler()
        source_names = handler.get_source_names()
        
        assert "request.GET" in source_names
        assert "request.POST" in source_names
    
    def test_sinks(self):
        """Should have SQL execution sinks."""
        handler = SQLInjectionHandler()
        sink_names = handler.get_sink_names()
        
        assert "execute" in sink_names
        assert "mysql_query" in sink_names
    
    def test_safety_checks(self):
        """Should have parameterized query check."""
        handler = SQLInjectionHandler()
        checks = handler.get_safety_checks()
        check_names = [c.name for c in checks]
        
        assert "parameterized" in check_names
        assert "prepared_stmt" in check_names


class TestCommandInjectionHandler:
    """Tests for Command Injection Handler."""
    
    def test_cwe_ids(self):
        """Should handle CWE-78."""
        handler = CommandInjectionHandler()
        assert 78 in handler.cwe_ids
    
    def test_sinks(self):
        """Should have system/exec sinks."""
        handler = CommandInjectionHandler()
        sink_names = handler.get_sink_names()
        
        assert "system" in sink_names
        assert "popen" in sink_names
        assert "exec" in sink_names
    
    def test_safety_checks(self):
        """Should have shell escape checks."""
        handler = CommandInjectionHandler()
        checks = handler.get_safety_checks()
        check_names = [c.name for c in checks]
        
        assert "shell_escape" in check_names
        assert "whitelist" in check_names


class TestXSSHandler:
    """Tests for XSS Handler."""
    
    def test_cwe_ids(self):
        """Should handle CWE-79."""
        handler = XSSHandler()
        assert 79 in handler.cwe_ids
    
    def test_sources(self):
        """Should have DOM and request sources."""
        handler = XSSHandler()
        source_names = handler.get_source_names()
        
        assert "request.GET" in source_names
        assert "innerHTML" in source_names
        assert "location" in source_names
    
    def test_sinks(self):
        """Should have DOM manipulation sinks."""
        handler = XSSHandler()
        sink_names = handler.get_sink_names()
        
        assert "innerHTML" in sink_names
        assert "document.write" in sink_names
        assert "eval" in sink_names
    
    def test_safety_checks(self):
        """Should have encoding checks."""
        handler = XSSHandler()
        checks = handler.get_safety_checks()
        check_names = [c.name for c in checks]
        
        assert "html_encode" in check_names
        assert "dompurify" in check_names


class TestPathTraversalHandler:
    """Tests for Path Traversal Handler."""
    
    def test_cwe_ids(self):
        """Should handle CWE-22 and variants."""
        handler = PathTraversalHandler()
        assert 22 in handler.cwe_ids
        assert 23 in handler.cwe_ids
    
    def test_sinks(self):
        """Should have file operation sinks."""
        handler = PathTraversalHandler()
        sink_names = handler.get_sink_names()
        
        assert "fopen" in sink_names
        assert "open" in sink_names
        assert "remove" in sink_names
    
    def test_safety_checks(self):
        """Should have path validation checks."""
        handler = PathTraversalHandler()
        checks = handler.get_safety_checks()
        check_names = [c.name for c in checks]
        
        assert "realpath" in check_names
        assert "basename" in check_names
        assert "no_dotdot" in check_names


class TestIntegration:
    """Integration tests for CWE handlers."""
    
    def test_all_handlers_have_definition(self):
        """All handlers should have complete definitions."""
        handlers = [
            BufferOverflowHandler(),
            SQLInjectionHandler(),
            CommandInjectionHandler(),
            XSSHandler(),
            PathTraversalHandler(),
        ]
        
        for handler in handlers:
            defn = handler.get_definition()
            assert defn.cwe_id > 0
            assert len(defn.name) > 0
            assert len(defn.sources) > 0
            assert len(defn.sinks) > 0
    
    def test_category_handlers(self):
        """Should get handlers by category."""
        registry = get_registry()
        
        memory_handlers = registry.get_handlers_by_category(CWECategory.MEMORY)
        assert len(memory_handlers) >= 1
        
        injection_handlers = registry.get_handlers_by_category(CWECategory.INJECTION)
        assert len(injection_handlers) >= 3  # SQL, Command, XSS
    
    def test_is_source_and_sink_methods(self):
        """Handler helper methods should work."""
        handler = BufferOverflowHandler()
        
        assert handler.is_source("gets")
        assert not handler.is_source("unknown_func")
        
        assert handler.is_sink("strcpy")
        assert not handler.is_sink("unknown_func")
