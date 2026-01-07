"""Static Analysis Server using Clang Static Analyzer.

This MCP tool server runs Clang's static analyzer on C code and extracts:
- Security-related findings (buffer overflows, taint propagation)
- Sink and source information
- Location data for each finding
"""

import subprocess
import tempfile
import os
import re
from pathlib import Path

from src.config import CLANG_PATH
from src.schemas import (
    StaticAnalysisInput,
    StaticAnalysisOutput,
    AnalysisFinding,
)


# Checkers to enable for CWE-120 detection
SECURITY_CHECKERS = [
    "security.insecureAPI.strcpy",
    "security.insecureAPI.gets",
    "security.insecureAPI.mktemp",
    "security.insecureAPI.mkstemp",
    "security.insecureAPI.vfork",
    "alpha.security.ArrayBound",
    "alpha.security.ArrayBoundV2",
    "alpha.security.MallocOverflow",
    "alpha.security.ReturnPtrRange",
    "alpha.security.taint.TaintPropagation",
    "core.uninitialized.ArraySubscript",
]


def analyze_static(input_data: StaticAnalysisInput) -> StaticAnalysisOutput:
    """
    Run Clang Static Analyzer on C source code.
    
    Args:
        input_data: Contains the source code to analyze
        
    Returns:
        StaticAnalysisOutput with findings from the analyzer
    """
    source_code = input_data.source_code
    context = input_data.context or ""
    
    # Combine context (if provided) with the main source
    full_source = context + "\n" + source_code if context else source_code
    
    # Add minimal includes for common functions
    includes = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
"""
    full_source = includes + full_source
    
    try:
        findings = _run_clang_analyzer(full_source)
        return StaticAnalysisOutput(
            findings=findings,
            analysis_successful=True,
        )
    except FileNotFoundError:
        return StaticAnalysisOutput(
            findings=[],
            analysis_successful=False,
            error="Clang not found. Please install LLVM/Clang.",
        )
    except subprocess.TimeoutExpired:
        return StaticAnalysisOutput(
            findings=[],
            analysis_successful=False,
            error="Analysis timed out.",
        )
    except Exception as e:
        return StaticAnalysisOutput(
            findings=[],
            analysis_successful=False,
            error=f"Analysis failed: {str(e)}",
        )


def _run_clang_analyzer(source_code: str) -> list[AnalysisFinding]:
    """Run clang static analyzer and parse output."""
    findings = []
    
    # Create temporary file for the source code
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".c",
        delete=False,
    ) as f:
        f.write(source_code)
        temp_path = f.name
    
    try:
        # Build the clang command
        checker_args = []
        for checker in SECURITY_CHECKERS:
            checker_args.extend(["-Xclang", "-analyzer-checker", "-Xclang", checker])
        
        cmd = [
            CLANG_PATH,
            "--analyze",
            "-Xclang", "-analyzer-output=text",
            *checker_args,
            "-fsyntax-only",
            "-Wno-everything",  # Suppress regular warnings, focus on analyzer
            temp_path,
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        # Parse the analyzer output (stderr contains the diagnostics)
        output = result.stderr
        findings = _parse_clang_output(output, temp_path)
        
    finally:
        # Clean up temp file
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        
        # Clean up plist files that clang may create
        plist_path = temp_path + ".plist"
        try:
            os.unlink(plist_path)
        except OSError:
            pass
    
    return findings


def _parse_clang_output(output: str, source_path: str) -> list[AnalysisFinding]:
    """Parse clang analyzer text output into findings."""
    findings = []
    
    # Pattern for clang diagnostic lines
    # Format: filename:line:column: warning: message [checker]
    pattern = re.compile(
        r"([^:]+):(\d+):(\d+):\s*(warning|error|note):\s*(.+?)(?:\s*\[([^\]]+)\])?$",
        re.MULTILINE
    )
    
    for match in pattern.finditer(output):
        filename = match.group(1)
        line = int(match.group(2))
        column = int(match.group(3))
        severity = match.group(4)
        message = match.group(5).strip()
        checker = match.group(6) or "unknown"
        
        # Skip notes (they're context for warnings)
        if severity == "note":
            continue
        
        # Determine category and extract sink info
        category = _categorize_finding(checker, message)
        sink = _extract_sink(message)
        taint_source = _extract_taint_source(message)
        
        # Adjust line number (subtract header lines we added)
        adjusted_line = max(1, line - 6)  # 6 lines of includes
        
        findings.append(AnalysisFinding(
            checker=checker,
            category=category,
            message=message,
            line=adjusted_line,
            column=column,
            sink=sink,
            taint_source=taint_source,
        ))
    
    return findings


def _categorize_finding(checker: str, message: str) -> str:
    """Categorize a finding based on checker and message."""
    checker_lower = checker.lower()
    message_lower = message.lower()
    
    if "insecureapi" in checker_lower:
        return "insecure_api"
    elif "arraybound" in checker_lower:
        return "buffer_overflow"
    elif "taint" in checker_lower:
        return "taint_propagation"
    elif "overflow" in checker_lower or "overflow" in message_lower:
        return "buffer_overflow"
    elif "strcpy" in message_lower or "strcat" in message_lower:
        return "insecure_copy"
    elif "gets" in message_lower:
        return "insecure_input"
    else:
        return "security"


def _extract_sink(message: str) -> str | None:
    """Extract sink function name from the message."""
    # Common pattern mentions
    sink_functions = [
        "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "gets", "scanf", "sscanf", "read", "recv",
    ]
    
    message_lower = message.lower()
    for func in sink_functions:
        if func in message_lower:
            return func
    
    return None


def _extract_taint_source(message: str) -> str | None:
    """Extract taint source from the message if present."""
    message_lower = message.lower()
    
    # Look for taint-related keywords
    if "taint" in message_lower:
        if "stdin" in message_lower:
            return "stdin"
        elif "argv" in message_lower:
            return "argv"
        elif "getenv" in message_lower:
            return "environment"
        elif "read" in message_lower or "recv" in message_lower:
            return "external_input"
        else:
            return "unknown_taint"
    
    return None


# MCP Tool interface
def static_analyze_tool(source_code: str, context: str | None = None) -> dict:
    """
    MCP Tool: Run static analysis on C source code.
    
    This is the entry point for MCP tool calls.
    """
    input_data = StaticAnalysisInput(source_code=source_code, context=context)
    output = analyze_static(input_data)
    return output.model_dump()
