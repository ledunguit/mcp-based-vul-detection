"""Tests for new MCP servers: taint, pattern, and CFG analysis."""

import pytest
from src.mcp_servers.taint_server import taint_analyze_tool
from src.mcp_servers.pattern_server import pattern_match_tool, get_all_patterns_tool
from src.mcp_servers.cfg_server import cfg_analyze_tool


class TestTaintServer:
    """Tests for taint analysis server."""
    
    def test_basic_taint_detection(self):
        """Test detection of taint from parameter to sink."""
        code = '''void bad(char *input) {
    char buf[32];
    strcpy(buf, input);
}'''
        result = taint_analyze_tool(code)
        
        assert len(result["taint_sources"]) >= 1
        assert len(result["taint_sinks"]) >= 1
        # Parameter should be a source
        source_names = [s["name"] for s in result["taint_sources"]]
        assert "input" in source_names
        
    def test_taint_path_tracking(self):
        """Test tracking taint path through assignments."""
        code = '''void process(char *data) {
    char *ptr = data;
    char buf[64];
    memcpy(buf, ptr, 100);
}'''
        result = taint_analyze_tool(code)
        
        assert len(result["taint_sinks"]) >= 1
        assert any(s["function"] == "memcpy" for s in result["taint_sinks"])
        
    def test_no_taint_with_validation(self):
        """Test that validated sinks may still be detected but marked."""
        code = '''void safe(char *src, size_t len) {
    char buf[64];
    if (len <= sizeof(buf)) {
        memcpy(buf, src, len);
    }
}'''
        result = taint_analyze_tool(code)
        
        assert result["summary"]["total_sinks"] >= 1
        # Should detect validation check
        assert len(result["validation_checks"]) >= 1
        
    def test_multiple_sources(self):
        """Test detection of multiple taint sources."""
        code = '''void multi(char *a, char *b) {
    char buf[32];
    strcpy(buf, a);
    strcat(buf, b);
}'''
        result = taint_analyze_tool(code)
        
        # Should detect both parameters as sources
        assert len(result["taint_sources"]) >= 2


class TestPatternServer:
    """Tests for pattern matching server."""
    
    def test_strcpy_pattern_detection(self):
        """Test detection of unbounded strcpy."""
        code = '''void bad(char *s) {
    char buf[32];
    strcpy(buf, s);
}'''
        result = pattern_match_tool(code)
        
        assert result["summary"]["total_matches"] >= 1
        patterns = [m["pattern_id"] for m in result["matches"]]
        assert "BOF-001" in patterns
        
    def test_gets_pattern_detection(self):
        """Test detection of gets() usage."""
        code = '''void bad() {
    char buf[100];
    gets(buf);
}'''
        result = pattern_match_tool(code)
        
        assert result["summary"]["total_matches"] >= 1
        patterns = [m["pattern_id"] for m in result["matches"]]
        assert "BOF-002" in patterns
        
    def test_sprintf_pattern_detection(self):
        """Test detection of sprintf without bounds."""
        code = '''void bad(char *name) {
    char msg[64];
    sprintf(msg, "Hello %s", name);
}'''
        result = pattern_match_tool(code)
        
        assert result["summary"]["total_matches"] >= 1
        assert any(m["pattern_id"] == "BOF-003" for m in result["matches"])
        
    def test_scanf_without_width(self):
        """Test detection of scanf without width specifier."""
        code = '''void bad() {
    char name[32];
    scanf("%s", name);
}'''
        result = pattern_match_tool(code)
        
        assert result["summary"]["total_matches"] >= 1
        
    def test_safe_code_no_matches(self):
        """Test that safe code has fewer or no critical matches."""
        code = '''void safe(char *s) {
    char buf[32];
    strncpy(buf, s, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\\0';
}'''
        result = pattern_match_tool(code)
        
        # strncpy might be flagged for potential null-termination issues
        # but should not have critical unbounded copy issues
        critical = [m for m in result["matches"] if m["severity"] == "critical"]
        assert len(critical) == 0
        
    def test_get_all_patterns(self):
        """Test getting all available patterns."""
        result = get_all_patterns_tool()
        
        assert result["total_patterns"] > 0
        assert "CWE-120" in result["patterns_by_cwe"]
        
    def test_cwe_filter(self):
        """Test filtering patterns by CWE."""
        code = '''void bad() {
    char buf[64];
    gets(buf);
    char *heap = malloc(100);
    strcpy(heap, buf);
}'''
        result = pattern_match_tool(code, cwe_filter="CWE-120")
        
        for match in result["matches"]:
            assert match["cwe_id"] == "CWE-120"


class TestCFGServer:
    """Tests for control flow graph server."""
    
    def test_basic_cfg(self):
        """Test basic CFG extraction."""
        code = '''void simple(int x) {
    int y = x + 1;
    printf("%d", y);
}'''
        result = cfg_analyze_tool(code)
        
        assert result["function_name"] == "simple"
        assert result["summary"]["total_blocks"] >= 1
        assert result["summary"]["cyclomatic_complexity"] >= 1
        
    def test_if_branch_detection(self):
        """Test detection of if branches."""
        code = '''void branch(int x) {
    if (x > 0) {
        printf("positive");
    } else {
        printf("non-positive");
    }
}'''
        result = cfg_analyze_tool(code)
        
        assert len(result["branches"]) >= 1
        assert result["branches"][0]["branch_type"] == "if"
        
    def test_loop_detection(self):
        """Test detection of loops."""
        code = '''void looper(int n) {
    for (int i = 0; i < n; i++) {
        printf("%d", i);
    }
}'''
        result = cfg_analyze_tool(code)
        
        assert len(result["loops"]) >= 1
        assert result["loops"][0]["loop_type"] == "for"
        
    def test_while_loop(self):
        """Test detection of while loops."""
        code = '''void reader(FILE *f) {
    char c;
    while ((c = fgetc(f)) != EOF) {
        putchar(c);
    }
}'''
        result = cfg_analyze_tool(code)
        
        assert len(result["loops"]) >= 1
        assert any(l["loop_type"] == "while" for l in result["loops"])
        
    def test_sink_path_detection(self):
        """Test detection of paths to sinks."""
        code = '''void vuln(char *input) {
    char buf[32];
    strcpy(buf, input);
}'''
        result = cfg_analyze_tool(code)
        
        assert len(result["paths_to_sinks"]) >= 1
        path = result["paths_to_sinks"][0]
        assert path["sink_function"] == "strcpy"
        
    def test_validation_before_sink(self):
        """Test detection of validation before sink."""
        code = '''void safe(char *input, size_t len) {
    char buf[64];
    if (len <= sizeof(buf)) {
        memcpy(buf, input, len);
    }
}'''
        result = cfg_analyze_tool(code)
        
        # Should detect bounds check before sink
        assert len(result["branches"]) >= 1
        # The branch should be marked as having bounds check
        has_bounds_check = any(b.get("has_bounds_check") for b in result["branches"])
        assert has_bounds_check
        
    def test_cyclomatic_complexity(self):
        """Test cyclomatic complexity calculation."""
        # Simple function: complexity = 1
        simple_code = '''void simple() {
    int x = 1;
}'''
        result1 = cfg_analyze_tool(simple_code)
        
        # Function with one if: complexity = 2
        if_code = '''void withif(int x) {
    if (x > 0) {
        printf("yes");
    }
}'''
        result2 = cfg_analyze_tool(if_code)
        
        assert result2["summary"]["cyclomatic_complexity"] >= result1["summary"]["cyclomatic_complexity"]


class TestIntegration:
    """Integration tests combining multiple tools."""
    
    def test_all_tools_on_vulnerable_code(self):
        """Test all tools agree on vulnerable code."""
        code = '''void vulnerable(char *user_input) {
    char stack_buffer[64];
    strcpy(stack_buffer, user_input);
    printf("%s", stack_buffer);
}'''
        
        taint = taint_analyze_tool(code)
        pattern = pattern_match_tool(code)
        cfg = cfg_analyze_tool(code)
        
        # All tools should find something
        assert taint["summary"]["total_sinks"] >= 1
        assert pattern["summary"]["total_matches"] >= 1
        assert len(cfg["paths_to_sinks"]) >= 1
        
    def test_all_tools_on_safe_code(self):
        """Test tool behavior on safe code."""
        code = '''void safe_copy(const char *src, size_t src_len) {
    char dest[128];
    if (src_len < sizeof(dest)) {
        memcpy(dest, src, src_len);
        dest[src_len] = '\\0';
    }
}'''
        
        taint = taint_analyze_tool(code)
        pattern = pattern_match_tool(code)
        cfg = cfg_analyze_tool(code)
        
        # Tools should detect the sink but also the validation
        assert taint["summary"]["total_sinks"] >= 1
        assert len(taint["validation_checks"]) >= 1
        
        # CFG should show bounds check before sink
        branches_with_check = [b for b in cfg["branches"] if b.get("has_bounds_check")]
        assert len(branches_with_check) >= 1
