"""AST Server using tree-sitter for C code analysis.

This MCP tool server parses C source code and extracts:
- Function name and parameters
- Local variable declarations
- Function calls (with risky function detection)
- Risky sinks for buffer overflow analysis
"""

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node

from src.config import RISKY_FUNCTIONS
from src.schemas import (
    ASTAnalysisInput,
    ASTAnalysisOutput,
    Parameter,
    LocalVariable,
    FunctionCall,
    RiskySink,
)


# Initialize tree-sitter parser for C
C_LANGUAGE = Language(tsc.language())
parser = Parser(C_LANGUAGE)


def analyze_ast(input_data: ASTAnalysisInput) -> ASTAnalysisOutput:
    """
    Parse C source code and extract structural information.
    
    Args:
        input_data: Contains the source code to analyze
        
    Returns:
        ASTAnalysisOutput with function structure and risky sinks
    """
    source_code = input_data.source_code
    source_bytes = source_code.encode("utf-8")
    
    try:
        tree = parser.parse(source_bytes)
    except Exception as e:
        return ASTAnalysisOutput(parse_error=f"Failed to parse: {str(e)}")
    
    root = tree.root_node
    
    # Find the function definition
    function_node = _find_function_definition(root)
    if not function_node:
        return ASTAnalysisOutput(parse_error="No function definition found")
    
    # Extract function name
    function_name = _extract_function_name(function_node, source_bytes)
    
    # Extract parameters
    parameters = _extract_parameters(function_node, source_bytes)
    
    # Extract local variables
    local_variables = _extract_local_variables(function_node, source_bytes)
    
    # Extract all function calls
    function_calls = _extract_function_calls(function_node, source_bytes)
    
    # Identify risky sinks
    risky_sinks = [
        RiskySink(
            function=call.name,
            line=call.line,
            arguments=call.arguments,
        )
        for call in function_calls
        if call.is_risky
    ]
    
    return ASTAnalysisOutput(
        function_name=function_name,
        parameters=parameters,
        local_variables=local_variables,
        function_calls=function_calls,
        risky_sinks=risky_sinks,
    )


def _find_function_definition(node: Node) -> Node | None:
    """Find the first function definition in the AST."""
    if node.type == "function_definition":
        return node
    
    for child in node.children:
        result = _find_function_definition(child)
        if result:
            return result
    
    return None


def _extract_function_name(func_node: Node, source: bytes) -> str | None:
    """Extract the function name from a function definition."""
    # Look for the declarator
    declarator = None
    for child in func_node.children:
        if child.type == "function_declarator":
            declarator = child
            break
        elif child.type == "pointer_declarator":
            # Handle pointer return types
            for subchild in child.children:
                if subchild.type == "function_declarator":
                    declarator = subchild
                    break
    
    if not declarator:
        # Try to find declarator nested in other nodes
        declarator = _find_node_type(func_node, "function_declarator")
    
    if not declarator:
        return None
    
    # Get the identifier (function name)
    for child in declarator.children:
        if child.type == "identifier":
            return source[child.start_byte:child.end_byte].decode("utf-8")
        elif child.type == "pointer_declarator":
            # Handle pointer declarators
            for subchild in child.children:
                if subchild.type == "identifier":
                    return source[subchild.start_byte:subchild.end_byte].decode("utf-8")
    
    return None


def _find_node_type(node: Node, node_type: str) -> Node | None:
    """Recursively find a node of the given type."""
    if node.type == node_type:
        return node
    
    for child in node.children:
        result = _find_node_type(child, node_type)
        if result:
            return result
    
    return None


def _extract_parameters(func_node: Node, source: bytes) -> list[Parameter]:
    """Extract function parameters."""
    parameters = []
    
    # Find the parameter list
    declarator = _find_node_type(func_node, "function_declarator")
    if not declarator:
        return parameters
    
    param_list = _find_node_type(declarator, "parameter_list")
    if not param_list:
        return parameters
    
    for child in param_list.children:
        if child.type == "parameter_declaration":
            param_name = None
            param_type_parts = []
            
            for subchild in child.children:
                if subchild.type == "identifier":
                    param_name = source[subchild.start_byte:subchild.end_byte].decode("utf-8")
                elif subchild.type in ("primitive_type", "type_identifier", "sized_type_specifier"):
                    param_type_parts.append(
                        source[subchild.start_byte:subchild.end_byte].decode("utf-8")
                    )
                elif subchild.type == "pointer_declarator":
                    # Handle pointer parameters
                    for ptr_child in subchild.children:
                        if ptr_child.type == "identifier":
                            param_name = source[ptr_child.start_byte:ptr_child.end_byte].decode("utf-8")
                    param_type_parts.append("*")
            
            if param_name:
                parameters.append(Parameter(
                    name=param_name,
                    type=" ".join(param_type_parts) if param_type_parts else "unknown",
                ))
    
    return parameters


def _extract_local_variables(func_node: Node, source: bytes) -> list[LocalVariable]:
    """Extract local variable declarations from the function body."""
    variables = []

    # Find the compound statement (function body)
    body = _find_node_type(func_node, "compound_statement")
    if not body:
        return variables

    # Find all declarations
    declarations = _find_all_nodes_type(body, "declaration")

    for decl in declarations:
        var_type_parts = []
        var_name = None
        line = decl.start_point[0] + 1  # 1-indexed
        array_size = None
        array_size_expr = None

        for child in decl.children:
            if child.type in ("primitive_type", "type_identifier", "sized_type_specifier"):
                var_type_parts.append(
                    source[child.start_byte:child.end_byte].decode("utf-8")
                )
            elif child.type == "init_declarator":
                # Variable with initialization
                for subchild in child.children:
                    if subchild.type == "identifier":
                        var_name = source[subchild.start_byte:subchild.end_byte].decode("utf-8")
                    elif subchild.type == "array_declarator":
                        # Array declaration - extract size
                        var_name, array_size, array_size_expr = _extract_array_info(
                            subchild, source, var_name
                        )
                        size_str = _format_array_size(array_size, array_size_expr)
                        var_type_parts.append(f"[{size_str}]")
                    elif subchild.type == "pointer_declarator":
                        for ptr_child in subchild.children:
                            if ptr_child.type == "identifier":
                                var_name = source[ptr_child.start_byte:ptr_child.end_byte].decode("utf-8")
                        var_type_parts.append("*")
            elif child.type == "identifier":
                var_name = source[child.start_byte:child.end_byte].decode("utf-8")
            elif child.type == "array_declarator":
                var_name, array_size, array_size_expr = _extract_array_info(
                    child, source, var_name
                )
                size_str = _format_array_size(array_size, array_size_expr)
                var_type_parts.append(f"[{size_str}]")
            elif child.type == "pointer_declarator":
                for ptr_child in child.children:
                    if ptr_child.type == "identifier":
                        var_name = source[ptr_child.start_byte:ptr_child.end_byte].decode("utf-8")
                var_type_parts.append("*")

        if var_name:
            variables.append(LocalVariable(
                name=var_name,
                type=" ".join(var_type_parts) if var_type_parts else "unknown",
                line=line,
                size=array_size,
                size_expr=array_size_expr,
            ))

    # Also extract heap allocations
    heap_vars = _extract_heap_allocations(body, source)
    for var_name, alloc_info in heap_vars.items():
        # Check if variable already exists, update with allocation info
        found = False
        for var in variables:
            if var.name == var_name:
                var.size_expr = alloc_info.get("size_expr")
                found = True
                break
        if not found:
            variables.append(LocalVariable(
                name=var_name,
                type="*",  # Heap allocated pointer
                line=alloc_info.get("line", 0),
                size=None,
                size_expr=alloc_info.get("size_expr"),
            ))

    return variables


def _extract_array_info(
    array_node: Node, source: bytes, current_name: str | None
) -> tuple[str | None, int | None, str | None]:
    """Extract array name and size from an array_declarator node.

    Array declarator structure: identifier "[" size_expression "]"
    The first child is typically the variable name, and subsequent children
    within brackets are the size.
    """
    var_name = current_name
    array_size = None
    array_size_expr = None
    found_open_bracket = False

    for arr_child in array_node.children:
        if arr_child.type == "[":
            found_open_bracket = True
            continue
        elif arr_child.type == "]":
            continue

        if not found_open_bracket:
            # Before the bracket - this is the variable name
            if arr_child.type == "identifier":
                var_name = source[arr_child.start_byte:arr_child.end_byte].decode("utf-8")
        else:
            # Inside the brackets - this is the size
            if arr_child.type == "number_literal":
                size_text = source[arr_child.start_byte:arr_child.end_byte].decode("utf-8")
                try:
                    array_size = int(size_text)
                except ValueError:
                    array_size_expr = size_text
            elif arr_child.type in ("identifier", "binary_expression", "sizeof_expression",
                                     "unary_expression", "parenthesized_expression"):
                array_size_expr = source[arr_child.start_byte:arr_child.end_byte].decode("utf-8")

    return var_name, array_size, array_size_expr


def _format_array_size(size: int | None, size_expr: str | None) -> str:
    """Format array size for type string."""
    if size is not None:
        return str(size)
    elif size_expr is not None:
        return size_expr
    return ""


def _extract_heap_allocations(body: Node, source: bytes) -> dict[str, dict]:
    """Extract buffer sizes from malloc/calloc/realloc calls."""
    allocations = {}

    # Find all assignment expressions
    for node in _find_all_nodes_type(body, "assignment_expression"):
        left = None
        right = None

        for child in node.children:
            if child.type == "identifier" and left is None:
                left = child
            elif child.type == "call_expression":
                right = child

        if left and right:
            # Check if it's a memory allocation function
            func_name = None
            for child in right.children:
                if child.type == "identifier":
                    func_name = source[child.start_byte:child.end_byte].decode("utf-8")
                    break

            if func_name in ("malloc", "calloc", "realloc", "alloca"):
                var_name = source[left.start_byte:left.end_byte].decode("utf-8")

                # Extract arguments
                for child in right.children:
                    if child.type == "argument_list":
                        arg_text = source[child.start_byte:child.end_byte].decode("utf-8")
                        # Clean up parentheses
                        arg_text = arg_text.strip("()")

                        allocations[var_name] = {
                            "allocator": func_name,
                            "size_expr": arg_text,
                            "line": node.start_point[0] + 1
                        }
                        break

    return allocations


def _find_all_nodes_type(node: Node, node_type: str) -> list[Node]:
    """Find all nodes of the given type (non-recursive for direct children context)."""
    results = []
    
    def traverse(n: Node):
        if n.type == node_type:
            results.append(n)
        for child in n.children:
            traverse(child)
    
    traverse(node)
    return results


def _extract_function_calls(func_node: Node, source: bytes) -> list[FunctionCall]:
    """Extract all function calls from the function body."""
    calls = []
    
    # Find the compound statement (function body)
    body = _find_node_type(func_node, "compound_statement")
    if not body:
        return calls
    
    # Find all call expressions
    call_exprs = _find_all_nodes_type(body, "call_expression")
    
    for call_expr in call_exprs:
        func_name = None
        arguments = []
        line = call_expr.start_point[0] + 1  # 1-indexed
        
        for child in call_expr.children:
            if child.type == "identifier":
                func_name = source[child.start_byte:child.end_byte].decode("utf-8")
            elif child.type == "argument_list":
                for arg_child in child.children:
                    if arg_child.type not in ("(", ")", ","):
                        arg_text = source[arg_child.start_byte:arg_child.end_byte].decode("utf-8")
                        arguments.append(arg_text)
        
        if func_name:
            is_risky = func_name in RISKY_FUNCTIONS
            calls.append(FunctionCall(
                name=func_name,
                arguments=arguments,
                line=line,
                is_risky=is_risky,
            ))
    
    return calls


# MCP Tool interface
def ast_analyze_tool(source_code: str) -> dict:
    """
    MCP Tool: Analyze C source code AST.
    
    This is the entry point for MCP tool calls.
    """
    input_data = ASTAnalysisInput(source_code=source_code)
    output = analyze_ast(input_data)
    return output.model_dump()
