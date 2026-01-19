"""Taint Analysis Server - Track data flow from sources to sinks.

This MCP tool server performs lightweight taint analysis to identify:
- Taint sources: User input, external data (function parameters, stdin, etc.)
- Taint sinks: Dangerous functions (memcpy, strcpy, etc.)
- Taint propagation paths: How data flows from sources to sinks

This is a lightweight implementation using AST traversal.
For production, consider integrating with tools like:
- Joern (Code Property Graph)
- Infer (Facebook)
- SVF (Static Value-Flow Analysis)
"""

import re
from dataclasses import dataclass, field, asdict
from typing import Optional

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node

from src.config import RISKY_FUNCTIONS


# Initialize tree-sitter parser for C
C_LANGUAGE = Language(tsc.language())
parser = Parser(C_LANGUAGE)


# Taint sources - functions/patterns that introduce external data
TAINT_SOURCES = {
    # Direct user input
    "gets": "stdin",
    "fgets": "file_input",
    "scanf": "stdin",
    "fscanf": "file_input",
    "sscanf": "string_input",
    "read": "file_descriptor",
    "fread": "file_input",
    "recv": "network",
    "recvfrom": "network",
    "getenv": "environment",
    "getc": "stdin",
    "fgetc": "file_input",
    "getchar": "stdin",
    # Parameter sources (tracked separately)
}

# Functions that propagate taint
TAINT_PROPAGATORS = [
    "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "memmove", "memset",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "strdup", "strndup",
]


@dataclass
class TaintSource:
    """A source of tainted data."""
    name: str
    source_type: str  # parameter, stdin, file, network, environment
    line: int
    variable: Optional[str] = None


@dataclass
class TaintSink:
    """A sink where tainted data may cause issues."""
    function: str
    line: int
    arguments: list[str] = field(default_factory=list)
    tainted_args: list[int] = field(default_factory=list)  # Which arguments are tainted (0-indexed)


@dataclass
class TaintPath:
    """A path from taint source to sink."""
    source: TaintSource
    sink: TaintSink
    path: list[str]  # Variable names in the path
    is_validated: bool = False  # True if bounds check found before sink


@dataclass
class TaintAnalysisOutput:
    """Output from taint analysis."""
    taint_sources: list[TaintSource] = field(default_factory=list)
    taint_sinks: list[TaintSink] = field(default_factory=list)
    taint_paths: list[TaintPath] = field(default_factory=list)
    untainted_sinks: list[TaintSink] = field(default_factory=list)
    validation_checks: list[dict] = field(default_factory=list)
    parse_error: Optional[str] = None


def analyze_taint(source_code: str) -> TaintAnalysisOutput:
    """
    Perform lightweight taint analysis on C source code.
    
    This identifies:
    1. Sources of external/untrusted data
    2. Dangerous sinks
    3. Data flow paths from sources to sinks
    4. Validation checks that may sanitize tainted data
    """
    source_bytes = source_code.encode("utf-8")
    
    try:
        tree = parser.parse(source_bytes)
    except Exception as e:
        return TaintAnalysisOutput(parse_error=f"Parse error: {str(e)}")
    
    root = tree.root_node
    
    # Find function definition
    func_node = _find_function_definition(root)
    if not func_node:
        return TaintAnalysisOutput(parse_error="No function definition found")
    
    # Step 1: Identify taint sources
    taint_sources = _find_taint_sources(func_node, source_bytes)
    
    # Step 2: Identify taint sinks
    taint_sinks = _find_taint_sinks(func_node, source_bytes)
    
    # Step 3: Build variable assignments map
    assignments = _build_assignment_map(func_node, source_bytes)
    
    # Step 4: Find validation checks (bounds checking)
    validation_checks = _find_validation_checks(func_node, source_bytes)
    
    # Step 5: Trace taint flow
    tainted_vars = set()
    for src in taint_sources:
        if src.variable:
            tainted_vars.add(src.variable)
    
    # Propagate taint through assignments
    tainted_vars = _propagate_taint(tainted_vars, assignments)
    
    # Step 6: Match tainted variables to sinks
    taint_paths = []
    untainted_sinks = []
    
    for sink in taint_sinks:
        tainted_args = []
        for i, arg in enumerate(sink.arguments):
            # Check if argument or any variable it references is tainted
            if _is_tainted(arg, tainted_vars, assignments):
                tainted_args.append(i)
        
        if tainted_args:
            sink.tainted_args = tainted_args
            
            # Find the source for each tainted path
            for src in taint_sources:
                if src.variable and _is_tainted(sink.arguments[tainted_args[0]], {src.variable}, assignments):
                    # Check if validated
                    is_validated = _check_validation_before_line(
                        validation_checks, 
                        src.variable, 
                        sink.line
                    )
                    
                    path = TaintPath(
                        source=src,
                        sink=sink,
                        path=_trace_path(src.variable, sink.arguments[tainted_args[0]], assignments),
                        is_validated=is_validated,
                    )
                    taint_paths.append(path)
        else:
            untainted_sinks.append(sink)
    
    return TaintAnalysisOutput(
        taint_sources=taint_sources,
        taint_sinks=taint_sinks,
        taint_paths=taint_paths,
        untainted_sinks=untainted_sinks,
        validation_checks=validation_checks,
    )


def _find_function_definition(node: Node) -> Optional[Node]:
    """Find the first function definition."""
    if node.type == "function_definition":
        return node
    for child in node.children:
        result = _find_function_definition(child)
        if result:
            return result
    return None


def _find_taint_sources(func_node: Node, source: bytes) -> list[TaintSource]:
    """Identify all taint sources in the function."""
    sources = []
    
    # 1. Function parameters are taint sources
    params = _extract_parameters(func_node, source)
    for param in params:
        # Pointer parameters are more likely to be external data
        is_pointer = "*" in param["type"] or "char" in param["type"]
        sources.append(TaintSource(
            name=param["name"],
            source_type="parameter",
            line=1,  # Parameters are at function start
            variable=param["name"],
        ))
    
    # 2. Find calls to taint source functions
    call_nodes = _find_all_nodes_type(func_node, "call_expression")
    for call in call_nodes:
        func_name = _get_call_function_name(call, source)
        if func_name in TAINT_SOURCES:
            line = call.start_point[0] + 1
            # Try to find the assigned variable
            assigned_var = _get_assigned_variable(call, source)
            sources.append(TaintSource(
                name=func_name,
                source_type=TAINT_SOURCES[func_name],
                line=line,
                variable=assigned_var,
            ))
    
    return sources


def _find_taint_sinks(func_node: Node, source: bytes) -> list[TaintSink]:
    """Find all potentially dangerous sinks."""
    sinks = []
    
    call_nodes = _find_all_nodes_type(func_node, "call_expression")
    for call in call_nodes:
        func_name = _get_call_function_name(call, source)
        if func_name in RISKY_FUNCTIONS:
            line = call.start_point[0] + 1
            args = _get_call_arguments(call, source)
            sinks.append(TaintSink(
                function=func_name,
                line=line,
                arguments=args,
            ))
    
    return sinks


def _build_assignment_map(func_node: Node, source: bytes) -> dict[str, list[str]]:
    """
    Build a map of variable assignments.
    
    Returns: {variable_name: [source_variables_or_expressions]}
    """
    assignments = {}
    
    # Find all assignment expressions
    for node in _find_all_nodes_type(func_node, "assignment_expression"):
        left = None
        right = None
        
        for child in node.children:
            if child.type == "identifier" and left is None:
                left = source[child.start_byte:child.end_byte].decode("utf-8")
            elif child.type == "=" :
                continue
            else:
                right = source[child.start_byte:child.end_byte].decode("utf-8")
        
        if left and right:
            if left not in assignments:
                assignments[left] = []
            assignments[left].append(right)
    
    # Find init_declarators (int x = y;)
    for node in _find_all_nodes_type(func_node, "init_declarator"):
        var_name = None
        init_value = None
        
        for child in node.children:
            if child.type == "identifier":
                var_name = source[child.start_byte:child.end_byte].decode("utf-8")
            elif child.type == "array_declarator":
                for sub in child.children:
                    if sub.type == "identifier":
                        var_name = source[sub.start_byte:sub.end_byte].decode("utf-8")
            elif child.type not in ["=", "[", "]"]:
                init_value = source[child.start_byte:child.end_byte].decode("utf-8")
        
        if var_name and init_value:
            if var_name not in assignments:
                assignments[var_name] = []
            assignments[var_name].append(init_value)
    
    return assignments


def _find_validation_checks(func_node: Node, source: bytes) -> list[dict]:
    """Find potential validation/bounds checks."""
    checks = []
    
    # Find if statements that might be bounds checks
    for node in _find_all_nodes_type(func_node, "if_statement"):
        condition_node = None
        for child in node.children:
            if child.type == "parenthesized_expression":
                condition_node = child
                break
        
        if condition_node:
            condition = source[condition_node.start_byte:condition_node.end_byte].decode("utf-8")
            line = node.start_point[0] + 1
            
            # Check if this looks like a bounds check
            is_bounds_check = any(pattern in condition.lower() for pattern in [
                "sizeof", "strlen", "<=", ">=", "<", ">", "len", "size", "max", "min"
            ])
            
            if is_bounds_check:
                # Extract variables mentioned
                var_pattern = re.compile(r'\b([a-zA-Z_]\w*)\b')
                variables = var_pattern.findall(condition)
                # Filter out keywords and functions
                variables = [v for v in variables if v not in ["sizeof", "strlen", "if", "else"]]
                
                checks.append({
                    "type": "bounds_check",
                    "line": line,
                    "condition": condition,
                    "variables": variables,
                })
    
    return checks


def _propagate_taint(tainted: set[str], assignments: dict) -> set[str]:
    """Propagate taint through variable assignments."""
    changed = True
    while changed:
        changed = False
        for var, sources in assignments.items():
            if var not in tainted:
                for src in sources:
                    # Check if any tainted variable appears in the source expression
                    for t in tainted:
                        if t in src:
                            tainted.add(var)
                            changed = True
                            break
    return tainted


def _is_tainted(expr: str, tainted_vars: set[str], assignments: dict) -> bool:
    """Check if an expression uses any tainted variables."""
    for var in tainted_vars:
        if var in expr:
            return True
    
    # Check if it's assigned from a tainted source
    # Extract variable names from expression
    var_pattern = re.compile(r'\b([a-zA-Z_]\w*)\b')
    expr_vars = var_pattern.findall(expr)
    
    for v in expr_vars:
        if v in tainted_vars:
            return True
    
    return False


def _trace_path(source_var: str, sink_arg: str, assignments: dict) -> list[str]:
    """Trace the path from source to sink through assignments."""
    path = [source_var]
    current = source_var
    visited = {source_var}
    
    # Simple forward tracing
    for var, sources in assignments.items():
        if var not in visited:
            for src in sources:
                if current in src:
                    path.append(var)
                    visited.add(var)
                    current = var
                    break
    
    if sink_arg not in path:
        path.append(sink_arg)
    
    return path


def _check_validation_before_line(checks: list[dict], variable: str, sink_line: int) -> bool:
    """Check if there's a validation check for the variable before the sink line."""
    for check in checks:
        if check["line"] < sink_line:
            if variable in check.get("variables", []):
                return True
    return False


def _extract_parameters(func_node: Node, source: bytes) -> list[dict]:
    """Extract function parameters."""
    params = []
    
    declarator = _find_node_type(func_node, "function_declarator")
    if not declarator:
        return params
    
    param_list = _find_node_type(declarator, "parameter_list")
    if not param_list:
        return params
    
    for child in param_list.children:
        if child.type == "parameter_declaration":
            param_name = None
            param_type = ""
            
            for subchild in child.children:
                if subchild.type == "identifier":
                    param_name = source[subchild.start_byte:subchild.end_byte].decode("utf-8")
                elif subchild.type in ("primitive_type", "type_identifier", "sized_type_specifier"):
                    param_type = source[subchild.start_byte:subchild.end_byte].decode("utf-8")
                elif subchild.type == "pointer_declarator":
                    param_type += " *"
                    for ptr_child in subchild.children:
                        if ptr_child.type == "identifier":
                            param_name = source[ptr_child.start_byte:ptr_child.end_byte].decode("utf-8")
            
            if param_name:
                params.append({"name": param_name, "type": param_type})
    
    return params


def _find_node_type(node: Node, node_type: str) -> Optional[Node]:
    """Recursively find a node of the given type."""
    if node.type == node_type:
        return node
    for child in node.children:
        result = _find_node_type(child, node_type)
        if result:
            return result
    return None


def _find_all_nodes_type(node: Node, node_type: str) -> list[Node]:
    """Find all nodes of the given type."""
    results = []
    
    def traverse(n: Node):
        if n.type == node_type:
            results.append(n)
        for child in n.children:
            traverse(child)
    
    traverse(node)
    return results


def _get_call_function_name(call_node: Node, source: bytes) -> str:
    """Get the function name from a call expression."""
    for child in call_node.children:
        if child.type == "identifier":
            return source[child.start_byte:child.end_byte].decode("utf-8")
    return ""


def _get_call_arguments(call_node: Node, source: bytes) -> list[str]:
    """Get arguments from a call expression."""
    args = []
    for child in call_node.children:
        if child.type == "argument_list":
            for arg_child in child.children:
                if arg_child.type not in ("(", ")", ","):
                    arg_text = source[arg_child.start_byte:arg_child.end_byte].decode("utf-8")
                    args.append(arg_text)
    return args


def _get_assigned_variable(call_node: Node, source: bytes) -> Optional[str]:
    """Get the variable that a call result is assigned to."""
    parent = call_node.parent
    
    if parent and parent.type == "assignment_expression":
        for child in parent.children:
            if child.type == "identifier":
                return source[child.start_byte:child.end_byte].decode("utf-8")
    elif parent and parent.type == "init_declarator":
        for child in parent.children:
            if child.type == "identifier":
                return source[child.start_byte:child.end_byte].decode("utf-8")
    
    return None


# MCP Tool interface
def taint_analyze_tool(source_code: str) -> dict:
    """
    MCP Tool: Perform taint analysis on C source code.
    
    Tracks data flow from untrusted sources to dangerous sinks.
    """
    result = analyze_taint(source_code)
    
    # Convert to dict format
    output = {
        "taint_sources": [asdict(s) for s in result.taint_sources],
        "taint_sinks": [asdict(s) for s in result.taint_sinks],
        "taint_paths": [],
        "untainted_sinks": [asdict(s) for s in result.untainted_sinks],
        "validation_checks": result.validation_checks,
        "summary": {
            "total_sources": len(result.taint_sources),
            "total_sinks": len(result.taint_sinks),
            "tainted_paths": len(result.taint_paths),
            "validated_paths": sum(1 for p in result.taint_paths if p.is_validated),
        }
    }
    
    for path in result.taint_paths:
        output["taint_paths"].append({
            "source": asdict(path.source),
            "sink": asdict(path.sink),
            "path": path.path,
            "is_validated": path.is_validated,
        })
    
    if result.parse_error:
        output["parse_error"] = result.parse_error
    
    return output
