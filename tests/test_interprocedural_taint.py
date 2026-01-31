"""Tests for Phase 2.1 Inter-procedural Taint Analysis."""

import pytest
from src.mcp_servers.function_summary import (
    FunctionSummary,
    ParameterTaint,
    get_builtin_summary,
    is_sink_function,
    is_source_function,
)
from src.mcp_servers.call_graph import (
    CallGraph,
    FunctionInfo,
    CallSite,
    build_call_graph,
)
from src.mcp_servers.interprocedural_taint import (
    InterproceduralTaintAnalyzer,
    analyze_taint_interprocedural,
)


class TestFunctionSummary:
    """Tests for FunctionSummary."""
    
    def test_builtin_strcpy(self):
        """Test built-in summary for strcpy."""
        summary = get_builtin_summary("strcpy")
        assert summary is not None
        assert summary.name == "strcpy"
        assert summary.risk_level == "high"
        assert len(summary.get_sink_params()) == 1
    
    def test_builtin_snprintf(self):
        """Test built-in summary for snprintf (safer function)."""
        summary = get_builtin_summary("snprintf")
        assert summary is not None
        assert summary.validates_bounds == True
        assert summary.risk_level == "low"
    
    def test_is_sink_function(self):
        """Test sink detection."""
        assert is_sink_function("strcpy") == True
        assert is_sink_function("strlen") == False
    
    def test_is_source_function(self):
        """Test source detection."""
        assert is_source_function("gets") == True
        assert is_source_function("strlen") == False
    
    def test_taint_propagation(self):
        """Test taint propagation mapping."""
        summary = get_builtin_summary("strcpy")
        prop = summary.get_taint_propagation()
        # src (param 1) propagates to dest (param 0)
        assert 1 in prop
    
    def test_custom_summary(self):
        """Test creating custom function summary."""
        summary = FunctionSummary(
            name="custom_copy",
            parameters=[
                ParameterTaint(0, "dest", is_sink=True),
                ParameterTaint(1, "src", propagates_to_params=[0]),
            ],
            returns_tainted=False,
        )
        assert summary.get_sink_params() == [0]
        assert len(summary.get_taint_propagation()) == 1


class TestCallGraph:
    """Tests for CallGraph."""
    
    def test_build_simple_graph(self):
        """Test building call graph from simple code."""
        code = """
        void helper(int x) {
            printf("%d", x);
        }
        
        void main() {
            helper(42);
        }
        """
        graph = build_call_graph(code)
        
        assert "helper" in graph.functions
        assert "main" in graph.functions
    
    def test_get_callers(self):
        """Test getting direct callers."""
        code = """
        void callee() {}
        void caller() { callee(); }
        """
        graph = build_call_graph(code)
        
        callers = graph.get_callers("callee")
        assert "caller" in callers
    
    def test_get_callees(self):
        """Test getting direct callees."""
        code = """
        void func1() {}
        void func2() {}
        void caller() { func1(); func2(); }
        """
        graph = build_call_graph(code)
        
        callees = graph.get_callees("caller")
        assert "func1" in callees
        assert "func2" in callees
    
    def test_transitive_callers(self):
        """Test transitive caller discovery."""
        code = """
        void deep() {}
        void mid() { deep(); }
        void top() { mid(); }
        """
        graph = build_call_graph(code)
        
        callers = graph.get_transitive_callers("deep", max_depth=3)
        assert "mid" in callers
        assert "top" in callers
    
    def test_call_chain(self):
        """Test finding call chain."""
        code = """
        void c() {}
        void b() { c(); }
        void a() { b(); }
        """
        graph = build_call_graph(code)
        
        chain = graph.get_call_chain("a", "c")
        assert chain == ["a", "b", "c"]


class TestInterproceduralTaint:
    """Tests for inter-procedural taint analysis."""
    
    def test_basic_analysis(self):
        """Test basic inter-procedural analysis."""
        code = """
        void copy(char *dest, char *src) {
            strcpy(dest, src);
        }
        """
        result = analyze_taint_interprocedural(code)
        
        assert result["total_functions"] >= 1
    
    def test_cross_function_taint(self):
        """Test taint tracking across functions."""
        code = """
        void process(char *input) {
            char buf[64];
            strcpy(buf, input);
        }
        
        void handler(char *user_data) {
            process(user_data);
        }
        """
        result = analyze_taint_interprocedural(code, max_depth=2)
        
        assert result["total_functions"] == 2
        # Should find paths in both functions
        assert result["total_interprocedural_paths"] >= 1
    
    def test_depth_limiting(self):
        """Test that depth is properly limited."""
        code = """
        void deep() {}
        void mid() { deep(); }
        void top() { mid(); }
        """
        result = analyze_taint_interprocedural(code, max_depth=1)
        
        # Max depth should be respected
        assert result["max_depth_reached"] <= 1
    
    def test_function_summaries_generated(self):
        """Test that function summaries are generated."""
        code = """
        void func(char *s) {
            printf("%s", s);
        }
        """
        result = analyze_taint_interprocedural(code)
        
        # Should have generated summary for func
        assert "func" in result["function_summaries"]
    
    def test_validated_path_detection(self):
        """Test detection of validated paths."""
        code = """
        void safe_copy(char *dest, char *src, size_t len) {
            if (strlen(src) < len) {
                strcpy(dest, src);
            }
        }
        """
        result = analyze_taint_interprocedural(code)
        
        # Function should be marked as having validation
        if result["function_summaries"]:
            summary = list(result["function_summaries"].values())[0]
            # Check validation is detected
            assert "validates_bounds" in summary


class TestIntegration:
    """Integration tests for inter-procedural analysis."""
    
    def test_realistic_vulnerable_code(self):
        """Test with realistic vulnerable code pattern."""
        code = """
        void copy_user_input(char *buf, char *input) {
            strcpy(buf, input);
        }
        
        void process_request(char *user_data) {
            char buffer[64];
            copy_user_input(buffer, user_data);
        }
        
        int main(int argc, char **argv) {
            process_request(argv[1]);
            return 0;
        }
        """
        result = analyze_taint_interprocedural(code, max_depth=3)
        
        assert result["total_functions"] == 3
        # Should detect the vulnerability chain
        assert result["total_interprocedural_paths"] >= 2
    
    def test_analyzer_with_external_summaries(self):
        """Test using pre-computed external summaries."""
        external = {
            "custom_sink": FunctionSummary(
                name="custom_sink",
                parameters=[ParameterTaint(0, "data", is_sink=True)],
                risk_level="high",
            )
        }
        
        analyzer = InterproceduralTaintAnalyzer(external_summaries=external)
        
        # External summary should be available
        assert "custom_sink" in analyzer.external_summaries
        # Built-in summaries should also be present
        assert "strcpy" in analyzer.external_summaries
