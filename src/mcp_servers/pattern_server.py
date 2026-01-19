"""Pattern Matching Server - Rule-based vulnerability pattern detection.

This MCP tool server matches code against known vulnerability patterns:
- Pre-defined rules for common buffer overflow patterns
- Regex-based pattern matching
- Optional Semgrep integration (if available)

Patterns are based on:
- CWE-120/121/122 (Buffer Overflow)
- CWE-787 (Out-of-bounds Write)
- CWE-125 (Out-of-bounds Read)
"""

import re
import subprocess
import tempfile
import os
import json
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


@dataclass
class PatternMatch:
    """A pattern match result."""
    pattern_id: str
    pattern_name: str
    severity: str  # critical, high, medium, low
    cwe_id: str
    line: int
    matched_code: str
    message: str
    recommendation: str


@dataclass
class PatternMatchOutput:
    """Output from pattern matching analysis."""
    matches: list[PatternMatch] = field(default_factory=list)
    patterns_checked: int = 0
    semgrep_available: bool = False
    error: Optional[str] = None


# Pre-defined vulnerability patterns
VULNERABILITY_PATTERNS = [
    # CWE-120/121: Buffer Copy without Checking Size
    {
        "id": "BOF-001",
        "name": "Unbounded strcpy",
        "cwe": "CWE-120",
        "severity": "critical",
        "pattern": r'\bstrcpy\s*\(\s*\w+\s*,\s*\w+\s*\)',
        "negative_pattern": r'if\s*\([^)]*strlen[^)]*\)[^{]*\{[^}]*strcpy',  # Has length check
        "message": "strcpy() called without bounds checking",
        "recommendation": "Use strncpy() with explicit size limit, or strlcpy() if available",
    },
    {
        "id": "BOF-002",
        "name": "gets() usage",
        "cwe": "CWE-120",
        "severity": "critical",
        "pattern": r'\bgets\s*\(',
        "message": "gets() is inherently unsafe and cannot be used securely",
        "recommendation": "Use fgets() with explicit buffer size",
    },
    {
        "id": "BOF-003",
        "name": "sprintf without bounds",
        "cwe": "CWE-120",
        "severity": "high",
        "pattern": r'\bsprintf\s*\(\s*\w+\s*,',
        "message": "sprintf() does not check buffer bounds",
        "recommendation": "Use snprintf() with explicit size limit",
    },
    {
        "id": "BOF-004",
        "name": "scanf without width specifier",
        "cwe": "CWE-120",
        "severity": "high",
        "pattern": r'\bscanf\s*\(\s*"[^"]*%s[^"]*"',
        "negative_pattern": r'scanf\s*\(\s*"[^"]*%\d+s',  # Has width specifier
        "message": "scanf() with %s format without width limit",
        "recommendation": "Use width specifier like %31s for 32-byte buffer",
    },
    {
        "id": "BOF-005",
        "name": "Unbounded memcpy with external size",
        "cwe": "CWE-120",
        "severity": "high",
        "pattern": r'\bmemcpy\s*\([^,]+,\s*[^,]+,\s*\w+\s*\)',
        "context_check": "no_bounds_check",  # Needs context analysis
        "message": "memcpy() with size that may not be validated",
        "recommendation": "Validate size parameter against destination buffer size before memcpy()",
    },
    {
        "id": "BOF-006",
        "name": "Unbounded strcat",
        "cwe": "CWE-120",
        "severity": "high",
        "pattern": r'\bstrcat\s*\(\s*\w+\s*,\s*\w+\s*\)',
        "message": "strcat() does not check remaining buffer space",
        "recommendation": "Use strncat() with remaining space calculation, or strlcat() if available",
    },
    {
        "id": "BOF-007",
        "name": "strncpy without null termination",
        "cwe": "CWE-120",
        "severity": "medium",
        "pattern": r'\bstrncpy\s*\([^;]+;(?![^;]*\[\s*[\w\s\-\+]+\s*\]\s*=\s*[\'"]?\\?0)',
        "message": "strncpy() may not null-terminate if source >= size",
        "recommendation": "Always explicitly null-terminate after strncpy()",
    },
    # CWE-122: Heap-based Buffer Overflow
    {
        "id": "HBO-001",
        "name": "Malloc without size check",
        "cwe": "CWE-122",
        "severity": "medium",
        "pattern": r'malloc\s*\(\s*\w+\s*\)[^;]*;[^}]*(?:strcpy|memcpy|sprintf)',
        "message": "Heap buffer allocated then copied to without size validation",
        "recommendation": "Validate that copy size <= allocated size",
    },
    # CWE-787: Out-of-bounds Write
    {
        "id": "OOB-001",
        "name": "Array index from external source",
        "cwe": "CWE-787",
        "severity": "high",
        "pattern": r'\w+\s*\[\s*\w+\s*\]\s*=',
        "context_check": "index_not_validated",
        "message": "Array write with potentially unvalidated index",
        "recommendation": "Validate array index against array bounds before use",
    },
    # CWE-125: Out-of-bounds Read
    {
        "id": "OOR-001",
        "name": "Array read with external index",
        "cwe": "CWE-125",
        "severity": "medium",
        "pattern": r'=\s*\w+\s*\[\s*\w+\s*\]',
        "context_check": "index_not_validated",
        "message": "Array read with potentially unvalidated index",
        "recommendation": "Validate array index against array bounds before read",
    },
    # Wide character functions
    {
        "id": "BOF-008",
        "name": "Unbounded wcscpy",
        "cwe": "CWE-120",
        "severity": "critical",
        "pattern": r'\bwcscpy\s*\(',
        "message": "wcscpy() does not check buffer bounds",
        "recommendation": "Use wcsncpy() with explicit size limit",
    },
    # Network functions
    {
        "id": "BOF-009",
        "name": "recv without size validation",
        "cwe": "CWE-120",
        "severity": "high",
        "pattern": r'\brecv\s*\([^,]+,\s*[^,]+,\s*\d+\s*,',
        "context_check": "recv_size_vs_buffer",
        "message": "recv() with fixed size that may exceed buffer",
        "recommendation": "Ensure recv size parameter matches or is less than buffer size",
    },
    {
        "id": "BOF-010",
        "name": "fgets with wrong size",
        "cwe": "CWE-120",
        "severity": "high",
        "pattern": r'\bfgets\s*\(\s*(\w+)\s*,\s*(\d+)',
        "context_check": "fgets_size_check",
        "message": "fgets() size may not match buffer size",
        "recommendation": "Use sizeof(buffer) as the size argument to fgets()",
    },
]

# Semgrep rules in YAML format for more sophisticated matching
SEMGREP_RULES_YAML = """
rules:
  - id: buffer-overflow-strcpy
    patterns:
      - pattern: strcpy($DEST, $SRC)
      - pattern-not-inside: |
          if (strlen($SRC) < sizeof($DEST)) { ... }
    message: Unbounded strcpy detected
    severity: ERROR
    languages: [c]
    metadata:
      cwe: CWE-120
      
  - id: buffer-overflow-gets
    pattern: gets($BUF)
    message: gets() is inherently unsafe
    severity: ERROR  
    languages: [c]
    metadata:
      cwe: CWE-120
      
  - id: buffer-overflow-sprintf
    patterns:
      - pattern: sprintf($BUF, ...)
      - pattern-not: snprintf(...)
    message: Use snprintf instead of sprintf
    severity: WARNING
    languages: [c]
    metadata:
      cwe: CWE-120
"""


def check_semgrep_available() -> bool:
    """Check if Semgrep is installed and available."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_semgrep_analysis(source_code: str) -> list[PatternMatch]:
    """Run Semgrep analysis if available."""
    matches = []
    
    if not check_semgrep_available():
        return matches
    
    # Create temp files for source and rules
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as src_file:
        src_file.write(source_code)
        src_path = src_file.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as rules_file:
        rules_file.write(SEMGREP_RULES_YAML)
        rules_path = rules_file.name
    
    try:
        result = subprocess.run(
            ["semgrep", "--config", rules_path, "--json", src_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode == 0:
            output = json.loads(result.stdout)
            for finding in output.get("results", []):
                matches.append(PatternMatch(
                    pattern_id=f"SEMGREP-{finding.get('check_id', 'unknown')}",
                    pattern_name=finding.get('check_id', 'Unknown'),
                    severity=finding.get('extra', {}).get('severity', 'medium').lower(),
                    cwe_id=finding.get('extra', {}).get('metadata', {}).get('cwe', 'CWE-120'),
                    line=finding.get('start', {}).get('line', 0),
                    matched_code=finding.get('extra', {}).get('lines', ''),
                    message=finding.get('extra', {}).get('message', ''),
                    recommendation="See Semgrep documentation",
                ))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        pass
    finally:
        # Clean up temp files
        try:
            os.unlink(src_path)
            os.unlink(rules_path)
        except OSError:
            pass
    
    return matches


def analyze_patterns(source_code: str, use_semgrep: bool = True) -> PatternMatchOutput:
    """
    Analyze source code against vulnerability patterns.
    
    Args:
        source_code: C source code to analyze
        use_semgrep: Whether to try using Semgrep (if available)
    
    Returns:
        PatternMatchOutput with all matches found
    """
    matches = []
    lines = source_code.split('\n')
    
    # Run regex-based pattern matching
    for pattern_def in VULNERABILITY_PATTERNS:
        pattern = pattern_def["pattern"]
        negative_pattern = pattern_def.get("negative_pattern")
        
        # Check for matches
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line):
                # Check negative pattern (things that make it safe)
                if negative_pattern:
                    # Check surrounding context (5 lines before and after)
                    context_start = max(0, line_num - 6)
                    context_end = min(len(lines), line_num + 5)
                    context = '\n'.join(lines[context_start:context_end])
                    
                    if re.search(negative_pattern, context, re.DOTALL):
                        continue  # Safe pattern found, skip this match
                
                matches.append(PatternMatch(
                    pattern_id=pattern_def["id"],
                    pattern_name=pattern_def["name"],
                    severity=pattern_def["severity"],
                    cwe_id=pattern_def["cwe"],
                    line=line_num,
                    matched_code=line.strip(),
                    message=pattern_def["message"],
                    recommendation=pattern_def.get("recommendation", "Review code for security"),
                ))
    
    # Check Semgrep availability and run if requested
    semgrep_available = check_semgrep_available()
    if use_semgrep and semgrep_available:
        semgrep_matches = run_semgrep_analysis(source_code)
        matches.extend(semgrep_matches)
    
    # Deduplicate matches (same line, same pattern)
    seen = set()
    unique_matches = []
    for m in matches:
        key = (m.pattern_id, m.line)
        if key not in seen:
            seen.add(key)
            unique_matches.append(m)
    
    return PatternMatchOutput(
        matches=unique_matches,
        patterns_checked=len(VULNERABILITY_PATTERNS),
        semgrep_available=semgrep_available,
    )


def get_patterns_for_cwe(cwe_id: str) -> list[dict]:
    """Get all patterns for a specific CWE."""
    return [p for p in VULNERABILITY_PATTERNS if p["cwe"] == cwe_id]


def get_severity_counts(output: PatternMatchOutput) -> dict:
    """Get count of matches by severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for match in output.matches:
        severity = match.severity.lower()
        if severity in counts:
            counts[severity] += 1
    return counts


# MCP Tool interface
def pattern_match_tool(
    source_code: str,
    cwe_filter: Optional[str] = None,
    use_semgrep: bool = True,
) -> dict:
    """
    MCP Tool: Match code against vulnerability patterns.
    
    Args:
        source_code: C source code to analyze
        cwe_filter: Optional CWE ID to filter patterns (e.g., "CWE-120")
        use_semgrep: Whether to use Semgrep if available
    
    Returns:
        Dict with pattern matches and metadata
    """
    result = analyze_patterns(source_code, use_semgrep)
    
    # Filter by CWE if specified
    if cwe_filter:
        result.matches = [m for m in result.matches if m.cwe_id == cwe_filter]
    
    # Calculate severity distribution
    severity_counts = get_severity_counts(result)
    
    # Convert to dict format
    output = {
        "matches": [asdict(m) for m in result.matches],
        "summary": {
            "total_matches": len(result.matches),
            "patterns_checked": result.patterns_checked,
            "semgrep_available": result.semgrep_available,
            "severity_distribution": severity_counts,
        },
        "cwe_breakdown": {},
    }
    
    # Group by CWE
    for match in result.matches:
        cwe = match.cwe_id
        if cwe not in output["cwe_breakdown"]:
            output["cwe_breakdown"][cwe] = []
        output["cwe_breakdown"][cwe].append({
            "pattern_id": match.pattern_id,
            "line": match.line,
            "severity": match.severity,
        })
    
    if result.error:
        output["error"] = result.error
    
    return output


def get_all_patterns_tool() -> dict:
    """
    MCP Tool: Get all available vulnerability patterns.
    
    Returns:
        Dict with all pattern definitions
    """
    patterns_by_cwe = {}
    for pattern in VULNERABILITY_PATTERNS:
        cwe = pattern["cwe"]
        if cwe not in patterns_by_cwe:
            patterns_by_cwe[cwe] = []
        patterns_by_cwe[cwe].append({
            "id": pattern["id"],
            "name": pattern["name"],
            "severity": pattern["severity"],
            "message": pattern["message"],
        })
    
    return {
        "total_patterns": len(VULNERABILITY_PATTERNS),
        "patterns_by_cwe": patterns_by_cwe,
        "semgrep_available": check_semgrep_available(),
    }
