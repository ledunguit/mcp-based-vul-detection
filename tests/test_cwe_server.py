"""Tests for the CWE Knowledge Server."""

import pytest

from src.mcp_servers.cwe_knowledge_server import cwe_lookup_tool, get_all_risky_sinks


class TestCWEKnowledgeServer:
    """Test cases for CWE knowledge lookup."""
    
    def test_strcpy_knowledge(self):
        """Test knowledge lookup for strcpy."""
        result = cwe_lookup_tool("strcpy")
        
        assert result["cwe_id"] == "CWE-120"
        assert result["sink_function"] == "strcpy"
        assert len(result["required_safety_checks"]) > 0
    
    def test_memcpy_knowledge(self):
        """Test knowledge lookup for memcpy."""
        result = cwe_lookup_tool("memcpy")
        
        assert "size" in str(result["required_safety_checks"]).lower() or \
               "buffer" in str(result["required_safety_checks"]).lower()
    
    def test_unknown_function(self):
        """Test lookup for unknown function."""
        result = cwe_lookup_tool("unknown_func")
        
        # Should return generic CWE-120 info
        assert result["cwe_id"] == "CWE-120"
        assert len(result["required_safety_checks"]) > 0
    
    def test_gets_always_vulnerable(self):
        """Test that gets() knowledge indicates it's always vulnerable."""
        result = cwe_lookup_tool("gets")
        
        checks = " ".join(result["required_safety_checks"]).lower()
        assert "never" in checks or "always" in checks
    
    def test_get_all_sinks(self):
        """Test getting list of all risky sinks."""
        sinks = get_all_risky_sinks()
        
        assert "strcpy" in sinks
        assert "memcpy" in sinks
        assert "sprintf" in sinks
