"""CWE Knowledge Server - Official MITRE CWE knowledge for buffer overflows.

This MCP tool server provides:
- Official CWE descriptions and mitigations from MITRE database
- Required safety checks for dangerous sink functions
- Common vulnerability patterns and detection methods
"""

import json
from pathlib import Path

from src.config import DATA_DIR
from src.schemas import (
    CWEKnowledgeInput,
    CWEKnowledgeOutput,
    CWEExample,
)


# Load knowledge bases
_mitre_knowledge: dict | None = None
_sink_rules: dict | None = None


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
            "memcpy": {"check": "size <= dest_size", "safe_alt": "memcpy_s"},
            "memmove": {"check": "size <= dest_size", "safe_alt": "memmove_s"},
            "memset": {"check": "size <= buffer_size"},
            
            # String copy functions
            "strcpy": {"check": "strlen(src) < dest_size", "safe_alt": "strncpy/strlcpy"},
            "strncpy": {"check": "n <= dest_size, ensure null term"},
            "strlcpy": {"check": "size == dest_size"},
            "wcscpy": {"check": "wcslen(src) < dest_size", "safe_alt": "wcsncpy"},
            "wcsncpy": {"check": "n <= dest_size"},
            
            # String concat functions
            "strcat": {"check": "strlen(dest)+strlen(src) < dest_size", "safe_alt": "strncat"},
            "strncat": {"check": "n <= remaining_space"},
            "wcscat": {"check": "wcslen(dest)+wcslen(src) < dest_size"},
            "wcsncat": {"check": "n <= remaining_space"},
            
            # Format functions
            "sprintf": {"check": "use snprintf instead", "safe_alt": "snprintf"},
            "vsprintf": {"check": "use vsnprintf instead", "safe_alt": "vsnprintf"},
            "snprintf": {"check": "size == buffer_size"},
            "swprintf": {"check": "size == buffer_size"},
            
            # Input functions
            "gets": {"check": "NEVER USE - always vulnerable", "safe_alt": "fgets"},
            "scanf": {"check": "use width specifier: %31s", "risky_pattern": "%s"},
            "sscanf": {"check": "use width specifier"},
            "fscanf": {"check": "use width specifier"},
            "wscanf": {"check": "use width specifier"},
            
            # File/network I/O
            "fgets": {"check": "size == buffer_size"},
            "fread": {"check": "size*nmemb <= buffer_size"},
            "read": {"check": "count <= buffer_size"},
            "recv": {"check": "len <= buffer_size"},
            "recvfrom": {"check": "len <= buffer_size"},
        }
    
    return _sink_rules


def lookup_cwe_knowledge(input_data: CWEKnowledgeInput) -> CWEKnowledgeOutput:
    """
    Look up CWE knowledge for a specific sink function.
    
    Combines official MITRE CWE data with sink-specific rules.
    """
    mitre_kb = _load_mitre_knowledge()
    sink_rules = _get_sink_rules()
    
    sink_function = input_data.sink_function.lower()
    
    # Get MITRE data for relevant CWEs
    weaknesses = mitre_kb.get("weaknesses", {})
    
    # Determine which CWEs are relevant
    relevant_cwes = ["CWE-120", "CWE-121", "CWE-122", "CWE-787"]
    
    # Collect mitigations and descriptions from MITRE
    mitigations = []
    descriptions = []
    detection_info = []
    
    for cwe_id in relevant_cwes:
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
    
    # Get sink-specific rules
    sink_info = sink_rules.get(sink_function, {})
    
    # Build required safety checks
    required_checks = []
    
    if sink_info:
        if sink_info.get('check'):
            required_checks.append(f"For {sink_function}: {sink_info['check']}")
        if sink_info.get('safe_alt'):
            required_checks.append(f"Consider using safer alternative: {sink_info['safe_alt']}")
        if sink_info.get('risky_pattern'):
            required_checks.append(f"Risky pattern: {sink_info['risky_pattern']}")
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
    
    # Extract examples from MITRE data
    examples = []
    for cwe_id in ["CWE-120", "CWE-121"]:
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
    
    return CWEKnowledgeOutput(
        cwe_id="CWE-120",
        sink_function=sink_function,
        required_safety_checks=required_checks[:5],  # Limit to 5
        common_patterns=[
            f"Unsafe use of {sink_function} without bounds checking",
            "Fixed-size buffer receiving variable-length input",
            "Missing input validation before memory operation",
        ],
        description=main_desc,
        examples=examples[:2],  # Limit to 2
    )


def get_all_risky_sinks() -> list[str]:
    """Get list of all known risky sink functions."""
    return list(_get_sink_rules().keys())


def get_cwe_description(cwe_id: str) -> dict:
    """Get the full MITRE description for a specific CWE."""
    mitre_kb = _load_mitre_knowledge()
    weaknesses = mitre_kb.get("weaknesses", {})
    return weaknesses.get(cwe_id, {})


# MCP Tool interface
def cwe_lookup_tool(
    sink_function: str,
    query_type: str = "safety_checks",
) -> dict:
    """
    MCP Tool: Look up CWE knowledge for a sink function.
    
    Uses official MITRE CWE database combined with sink-specific rules.
    """
    input_data = CWEKnowledgeInput(
        sink_function=sink_function,
        query_type=query_type,
    )
    output = lookup_cwe_knowledge(input_data)
    return output.model_dump()
