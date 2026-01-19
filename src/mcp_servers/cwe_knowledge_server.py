"""CWE Knowledge Server - Official MITRE CWE knowledge for buffer overflows.

This MCP tool server provides:
- Official CWE descriptions and mitigations from MITRE database
- Required safety checks for dangerous sink functions
- Common vulnerability patterns and detection methods

Supported CWEs:
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow
- CWE-124: Buffer Underwrite
- CWE-125: Out-of-bounds Read
- CWE-126: Buffer Over-read
- CWE-127: Buffer Under-read
- CWE-787: Out-of-bounds Write
"""

import json
from pathlib import Path
from typing import Optional

from src.config import DATA_DIR
from src.schemas import (
    CWEKnowledgeInput,
    CWEKnowledgeOutput,
    CWEExample,
)


# Load knowledge bases
_mitre_knowledge: dict | None = None
_sink_rules: dict | None = None

# CWE descriptions and relationships
CWE_DEFINITIONS = {
    "CWE-120": {
        "name": "Buffer Copy without Checking Size of Input",
        "description": "The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer, leading to a buffer overflow.",
        "related_cwes": ["CWE-121", "CWE-122", "CWE-787"],
        "detection_hints": ["Look for memcpy/strcpy without size validation", "Check for user input reaching copy functions"],
    },
    "CWE-121": {
        "name": "Stack-based Buffer Overflow",
        "description": "A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function).",
        "related_cwes": ["CWE-120", "CWE-787"],
        "detection_hints": ["Look for local array variables", "Check for unbounded copy to stack buffers"],
    },
    "CWE-122": {
        "name": "Heap-based Buffer Overflow",
        "description": "A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally meaning that the buffer was allocated using malloc().",
        "related_cwes": ["CWE-120", "CWE-787"],
        "detection_hints": ["Look for malloc'd buffers", "Check for size validation after malloc"],
    },
    "CWE-124": {
        "name": "Buffer Underwrite",
        "description": "The software writes to a buffer using an index or pointer that references a memory location prior to the beginning of the buffer.",
        "related_cwes": ["CWE-787"],
        "detection_hints": ["Look for negative array indices", "Check for pointer arithmetic that goes before buffer start"],
    },
    "CWE-125": {
        "name": "Out-of-bounds Read",
        "description": "The software reads data past the end, or before the beginning, of the intended buffer.",
        "related_cwes": ["CWE-126", "CWE-127"],
        "detection_hints": ["Look for array reads without bounds checking", "Check for strlen on non-terminated strings"],
    },
    "CWE-126": {
        "name": "Buffer Over-read",
        "description": "The software reads from a buffer using buffer access mechanisms such as indexes or pointers that reference memory locations after the targeted buffer.",
        "related_cwes": ["CWE-125"],
        "detection_hints": ["Look for reads past array bounds", "Check for off-by-one errors in loops"],
    },
    "CWE-127": {
        "name": "Buffer Under-read",
        "description": "The software reads from a buffer using buffer access mechanisms such as indexes or pointers that reference memory locations prior to the targeted buffer.",
        "related_cwes": ["CWE-125"],
        "detection_hints": ["Look for negative indices", "Check for pointer decrements before reads"],
    },
    "CWE-787": {
        "name": "Out-of-bounds Write",
        "description": "The software writes data past the end, or before the beginning, of the intended buffer.",
        "related_cwes": ["CWE-120", "CWE-121", "CWE-122"],
        "detection_hints": ["Look for array writes without bounds checking", "Check for calculated indices from user input"],
    },
}


def _load_mitre_knowledge() -> dict:
    """Load the MITRE CWE knowledge base."""
    global _mitre_knowledge
    
    if _mitre_knowledge is None:
        kb_path = DATA_DIR / "cwe_knowledge_mitre.json"
        
        if kb_path.exists():
            with open(kb_path, "r") as f:
                _mitre_knowledge = json.load(f)
        else:
            _mitre_knowledge = {"weaknesses": {}}
    
    return _mitre_knowledge


def _get_sink_rules() -> dict:
    """Get sink-specific rules (hard-coded for common buffer overflow sinks)."""
    global _sink_rules
    
    if _sink_rules is None:
        _sink_rules = {
            # Memory copy functions
            "memcpy": {
                "check": "size <= dest_size",
                "safe_alt": "memcpy_s",
                "cwes": ["CWE-120", "CWE-121", "CWE-122", "CWE-787"],
                "severity": "high",
            },
            "memmove": {
                "check": "size <= dest_size",
                "safe_alt": "memmove_s",
                "cwes": ["CWE-120", "CWE-787"],
                "severity": "high",
            },
            "memset": {
                "check": "size <= buffer_size",
                "cwes": ["CWE-120", "CWE-787"],
                "severity": "medium",
            },
            
            # String copy functions
            "strcpy": {
                "check": "strlen(src) < dest_size",
                "safe_alt": "strncpy/strlcpy",
                "cwes": ["CWE-120", "CWE-121"],
                "severity": "critical",
            },
            "strncpy": {
                "check": "n <= dest_size, ensure null term",
                "cwes": ["CWE-120"],
                "severity": "medium",
            },
            "strlcpy": {
                "check": "size == dest_size",
                "cwes": ["CWE-120"],
                "severity": "low",
            },
            "wcscpy": {
                "check": "wcslen(src) < dest_size",
                "safe_alt": "wcsncpy",
                "cwes": ["CWE-120"],
                "severity": "critical",
            },
            "wcsncpy": {
                "check": "n <= dest_size",
                "cwes": ["CWE-120"],
                "severity": "medium",
            },
            
            # String concat functions
            "strcat": {
                "check": "strlen(dest)+strlen(src) < dest_size",
                "safe_alt": "strncat",
                "cwes": ["CWE-120", "CWE-787"],
                "severity": "critical",
            },
            "strncat": {
                "check": "n <= remaining_space",
                "cwes": ["CWE-120"],
                "severity": "medium",
            },
            "wcscat": {
                "check": "wcslen(dest)+wcslen(src) < dest_size",
                "cwes": ["CWE-120"],
                "severity": "critical",
            },
            "wcsncat": {
                "check": "n <= remaining_space",
                "cwes": ["CWE-120"],
                "severity": "medium",
            },
            
            # Format functions
            "sprintf": {
                "check": "use snprintf instead",
                "safe_alt": "snprintf",
                "cwes": ["CWE-120", "CWE-121"],
                "severity": "high",
            },
            "vsprintf": {
                "check": "use vsnprintf instead",
                "safe_alt": "vsnprintf",
                "cwes": ["CWE-120"],
                "severity": "high",
            },
            "snprintf": {
                "check": "size == buffer_size",
                "cwes": ["CWE-120"],
                "severity": "low",
            },
            "swprintf": {
                "check": "size == buffer_size",
                "cwes": ["CWE-120"],
                "severity": "low",
            },
            
            # Input functions
            "gets": {
                "check": "NEVER USE - always vulnerable",
                "safe_alt": "fgets",
                "cwes": ["CWE-120", "CWE-242"],
                "severity": "critical",
            },
            "scanf": {
                "check": "use width specifier: %31s",
                "risky_pattern": "%s",
                "cwes": ["CWE-120"],
                "severity": "high",
            },
            "sscanf": {
                "check": "use width specifier",
                "cwes": ["CWE-120"],
                "severity": "high",
            },
            "fscanf": {
                "check": "use width specifier",
                "cwes": ["CWE-120"],
                "severity": "high",
            },
            "wscanf": {
                "check": "use width specifier",
                "cwes": ["CWE-120"],
                "severity": "high",
            },
            
            # File/network I/O
            "fgets": {
                "check": "size == buffer_size",
                "cwes": ["CWE-120"],
                "severity": "low",
            },
            "fread": {
                "check": "size*nmemb <= buffer_size",
                "cwes": ["CWE-120", "CWE-122"],
                "severity": "medium",
            },
            "read": {
                "check": "count <= buffer_size",
                "cwes": ["CWE-120", "CWE-787"],
                "severity": "high",
            },
            "recv": {
                "check": "len <= buffer_size",
                "cwes": ["CWE-120", "CWE-122"],
                "severity": "high",
            },
            "recvfrom": {
                "check": "len <= buffer_size",
                "cwes": ["CWE-120"],
                "severity": "high",
            },
        }
    
    return _sink_rules


def lookup_cwe_knowledge(
    input_data: CWEKnowledgeInput,
    cwe_filter: Optional[str] = None,
) -> CWEKnowledgeOutput:
    """
    Look up CWE knowledge for a specific sink function.
    
    Combines official MITRE CWE data with sink-specific rules.
    
    Args:
        input_data: Input containing sink function and query type
        cwe_filter: Optional specific CWE to focus on (e.g., "CWE-122")
    """
    mitre_kb = _load_mitre_knowledge()
    sink_rules = _get_sink_rules()
    
    sink_function = input_data.sink_function.lower()
    
    # Get MITRE data for relevant CWEs
    weaknesses = mitre_kb.get("weaknesses", {})
    
    # Determine which CWEs are relevant based on sink function
    sink_info = sink_rules.get(sink_function, {})
    relevant_cwes = sink_info.get("cwes", ["CWE-120", "CWE-121", "CWE-122", "CWE-787"])
    
    # If a specific CWE filter is provided, prioritize it
    if cwe_filter and cwe_filter in CWE_DEFINITIONS:
        relevant_cwes = [cwe_filter] + [c for c in relevant_cwes if c != cwe_filter]
    
    # Collect mitigations and descriptions from MITRE
    mitigations = []
    descriptions = []
    detection_info = []
    
    for cwe_id in relevant_cwes:
        # Check MITRE data first
        if cwe_id in weaknesses:
            cwe_data = weaknesses[cwe_id]
            
            # Add description
            if cwe_data.get('description'):
                descriptions.append(f"{cwe_id}: {cwe_data['description']}")
            
            # Add mitigations
            for mit in cwe_data.get('mitigations', []):
                if mit.get('description'):
                    mitigations.append(mit['description'][:200])
            
            # Add detection methods
            for det in cwe_data.get('detection_methods', []):
                if det.get('method'):
                    detection_info.append(f"{det['method']}: {det.get('description', '')[:100]}")
        
        # Fallback to built-in definitions
        elif cwe_id in CWE_DEFINITIONS:
            cwe_def = CWE_DEFINITIONS[cwe_id]
            descriptions.append(f"{cwe_id}: {cwe_def['description']}")
            for hint in cwe_def.get('detection_hints', []):
                detection_info.append(f"Detection: {hint}")
    
    # Build required safety checks
    required_checks = []
    
    if sink_info:
        if sink_info.get('check'):
            required_checks.append(f"For {sink_function}: {sink_info['check']}")
        if sink_info.get('safe_alt'):
            required_checks.append(f"Consider using safer alternative: {sink_info['safe_alt']}")
        if sink_info.get('risky_pattern'):
            required_checks.append(f"Risky pattern to avoid: {sink_info['risky_pattern']}")
        if sink_info.get('severity'):
            required_checks.append(f"Severity level: {sink_info['severity']}")
    else:
        required_checks = [
            "Validate buffer size before copy operation",
            "Ensure destination has sufficient capacity",
            "Check input length against buffer bounds",
        ]
    
    # Add top mitigations from MITRE
    for mit in mitigations[:3]:
        if len(mit) < 200:
            required_checks.append(mit)
    
    # Build description
    main_desc = descriptions[0] if descriptions else "Buffer overflow vulnerability"
    
    # Build common patterns
    common_patterns = [
        f"Unsafe use of {sink_function} without bounds checking",
        "Fixed-size buffer receiving variable-length input",
        "Missing input validation before memory operation",
    ]
    
    # Add CWE-specific patterns
    for cwe_id in relevant_cwes[:2]:
        if cwe_id in CWE_DEFINITIONS:
            for hint in CWE_DEFINITIONS[cwe_id].get('detection_hints', [])[:1]:
                common_patterns.append(hint)
    
    # Extract examples from MITRE data
    examples = []
    for cwe_id in relevant_cwes[:2]:
        if cwe_id in weaknesses:
            cwe_data = weaknesses[cwe_id]
            for ex in cwe_data.get('examples', [])[:1]:
                bad_code = ""
                good_code = ""
                for code_ex in ex.get('code_examples', []):
                    if code_ex.get('nature') == 'Bad':
                        bad_code = code_ex.get('code', '')[:200]
                    elif code_ex.get('nature') == 'Good':
                        good_code = code_ex.get('code', '')[:200]
                if bad_code or good_code:
                    examples.append(CWEExample(
                        vulnerable=bad_code,
                        safe=good_code,
                    ))
    
    # Determine primary CWE
    primary_cwe = cwe_filter if cwe_filter else (relevant_cwes[0] if relevant_cwes else "CWE-120")
    
    return CWEKnowledgeOutput(
        cwe_id=primary_cwe,
        sink_function=sink_function,
        required_safety_checks=required_checks[:6],  # Limit to 6
        common_patterns=common_patterns[:5],  # Limit to 5
        description=main_desc,
        examples=examples[:2],  # Limit to 2
    )


def get_all_risky_sinks() -> list[str]:
    """Get list of all known risky sink functions."""
    return list(_get_sink_rules().keys())


def get_sinks_by_cwe(cwe_id: str) -> list[dict]:
    """Get all sink functions associated with a specific CWE."""
    sink_rules = _get_sink_rules()
    result = []
    
    for sink_name, sink_info in sink_rules.items():
        if cwe_id in sink_info.get("cwes", []):
            result.append({
                "function": sink_name,
                "check": sink_info.get("check"),
                "safe_alt": sink_info.get("safe_alt"),
                "severity": sink_info.get("severity", "medium"),
            })
    
    return result


def get_cwe_description(cwe_id: str) -> dict:
    """Get the full description for a specific CWE."""
    # Try MITRE data first
    mitre_kb = _load_mitre_knowledge()
    weaknesses = mitre_kb.get("weaknesses", {})
    
    if cwe_id in weaknesses:
        return weaknesses[cwe_id]
    
    # Fallback to built-in definitions
    if cwe_id in CWE_DEFINITIONS:
        return CWE_DEFINITIONS[cwe_id]
    
    return {}


def get_all_supported_cwes() -> list[dict]:
    """Get information about all supported CWE types."""
    cwes = []
    for cwe_id, cwe_def in CWE_DEFINITIONS.items():
        cwes.append({
            "id": cwe_id,
            "name": cwe_def["name"],
            "description": cwe_def["description"][:200],
            "related_cwes": cwe_def.get("related_cwes", []),
        })
    return cwes


# MCP Tool interface
def cwe_lookup_tool(
    sink_function: str,
    query_type: str = "safety_checks",
    cwe_filter: Optional[str] = None,
) -> dict:
    """
    MCP Tool: Look up CWE knowledge for a sink function.
    
    Uses official MITRE CWE database combined with sink-specific rules.
    
    Args:
        sink_function: Name of the dangerous function (e.g., memcpy, strcpy)
        query_type: Type of query (safety_checks, vulnerability_pattern, description)
        cwe_filter: Optional specific CWE to focus on (e.g., "CWE-122")
    """
    input_data = CWEKnowledgeInput(
        sink_function=sink_function,
        query_type=query_type,
    )
    output = lookup_cwe_knowledge(input_data, cwe_filter)
    
    result = output.model_dump()
    
    # Add sink severity if available
    sink_rules = _get_sink_rules()
    if sink_function.lower() in sink_rules:
        result["sink_severity"] = sink_rules[sink_function.lower()].get("severity", "medium")
        result["associated_cwes"] = sink_rules[sink_function.lower()].get("cwes", [])
    
    return result


def get_cwe_info_tool(cwe_id: str) -> dict:
    """
    MCP Tool: Get detailed information about a specific CWE.
    
    Args:
        cwe_id: CWE identifier (e.g., "CWE-121", "CWE-787")
    """
    cwe_info = get_cwe_description(cwe_id)
    
    if not cwe_info:
        return {
            "error": f"Unknown CWE: {cwe_id}",
            "supported_cwes": list(CWE_DEFINITIONS.keys()),
        }
    
    # Get associated sinks
    associated_sinks = get_sinks_by_cwe(cwe_id)
    
    result = {
        "cwe_id": cwe_id,
        "name": cwe_info.get("name", "Unknown"),
        "description": cwe_info.get("description", ""),
        "related_cwes": cwe_info.get("related_cwes", []),
        "detection_hints": cwe_info.get("detection_hints", []),
        "associated_sinks": associated_sinks,
    }
    
    return result
