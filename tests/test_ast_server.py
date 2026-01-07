"""Tests for the AST Server."""

import pytest

from src.mcp_servers.ast_server import ast_analyze_tool


class TestASTServer:
    """Test cases for AST analysis."""
    
    def test_basic_function_parse(self):
        """Test parsing a simple function."""
        source = """
void hello(char *name) {
    printf("Hello %s", name);
}
"""
        result = ast_analyze_tool(source)
        
        assert result["function_name"] == "hello"
        assert result["parse_error"] is None
        assert len(result["parameters"]) == 1
        assert result["parameters"][0]["name"] == "name"
    
    def test_risky_sink_detection(self):
        """Test detection of risky function calls."""
        source = """
void vulnerable(char *input) {
    char buffer[32];
    strcpy(buffer, input);
}
"""
        result = ast_analyze_tool(source)
        
        assert len(result["risky_sinks"]) == 1
        assert result["risky_sinks"][0]["function"] == "strcpy"
    
    def test_multiple_risky_calls(self):
        """Test detection of multiple risky calls."""
        source = """
void multiple_risks(char *src, size_t len) {
    char buf1[32];
    char buf2[64];
    strcpy(buf1, src);
    memcpy(buf2, src, len);
}
"""
        result = ast_analyze_tool(source)
        
        risky_funcs = [s["function"] for s in result["risky_sinks"]]
        assert "strcpy" in risky_funcs
        assert "memcpy" in risky_funcs
    
    def test_safe_function(self):
        """Test a function with no risky calls."""
        source = """
int add(int a, int b) {
    return a + b;
}
"""
        result = ast_analyze_tool(source)
        
        assert result["function_name"] == "add"
        assert len(result["risky_sinks"]) == 0
    
    def test_local_variable_detection(self):
        """Test detection of local variables."""
        source = """
void test_vars() {
    char buffer[100];
    int count = 0;
    char *ptr;
}
"""
        result = ast_analyze_tool(source)
        
        var_names = [v["name"] for v in result["local_variables"]]
        assert "buffer" in var_names
        assert "count" in var_names


class TestASTServerEdgeCases:
    """Edge case tests for AST server."""
    
    def test_empty_function(self):
        """Test parsing an empty function."""
        source = """
void empty() {
}
"""
        result = ast_analyze_tool(source)
        
        assert result["function_name"] == "empty"
        assert len(result["function_calls"]) == 0
    
    def test_nested_calls(self):
        """Test function calls with nested expressions."""
        source = """
void nested(char *s) {
    strcpy(buffer, get_input());
}
"""
        result = ast_analyze_tool(source)
        
        call_names = [c["name"] for c in result["function_calls"]]
        assert "strcpy" in call_names
    
    def test_no_function(self):
        """Test input without a function definition."""
        source = """
int x = 5;
char *y;
"""
        result = ast_analyze_tool(source)
        
        assert result["parse_error"] == "No function definition found"
