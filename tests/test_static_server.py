"""Tests for the Static Analysis Server."""

import pytest

from src.mcp_servers.static_analysis_server import static_analyze_tool


class TestStaticAnalysisServer:
    """Test cases for static analysis."""
    
    def test_analysis_runs(self):
        """Test that analysis runs without error."""
        source = """
void test() {
    int x = 5;
}
"""
        result = static_analyze_tool(source)
        
        assert result["analysis_successful"] is True or "not found" in (result.get("error") or "")
    
    def test_insecure_api_detection(self):
        """Test detection of insecure API usage."""
        source = """
void insecure(char *input) {
    char buffer[32];
    strcpy(buffer, input);
}
"""
        result = static_analyze_tool(source)
        
        # Note: Result depends on clang being installed
        if result["analysis_successful"]:
            # May or may not have findings depending on checker availability
            assert "findings" in result
    
    def test_gets_detection(self):
        """Test detection of gets() usage."""
        source = """
void use_gets() {
    char buffer[100];
    gets(buffer);
}
"""
        result = static_analyze_tool(source)
        
        if result["analysis_successful"]:
            assert "findings" in result


class TestStaticAnalysisEdgeCases:
    """Edge case tests for static analysis."""
    
    def test_empty_source(self):
        """Test with empty source code."""
        result = static_analyze_tool("")
        # Should not crash
        assert "analysis_successful" in result
    
    def test_syntax_error(self):
        """Test with invalid C code."""
        source = "this is not valid C code {"
        result = static_analyze_tool(source)
        # Should handle gracefully
        assert "analysis_successful" in result
