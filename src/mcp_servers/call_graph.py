"""
Call Graph Builder - Phase 2.1

Provides utilities for building and analyzing call graphs for
inter-procedural taint analysis.
"""

from dataclasses import dataclass, field
from typing import Optional
import re

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node


# Initialize tree-sitter parser
C_LANGUAGE = Language(tsc.language())
parser = Parser(C_LANGUAGE)


@dataclass
class FunctionInfo:
    """Information about a function definition."""
    name: str
    file_path: Optional[str] = None
    start_line: int = 0
    end_line: int = 0
    parameters: list[dict] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    is_external: bool = False


@dataclass
class CallSite:
    """Information about a function call site."""
    caller: str
    callee: str
    line: int
    arguments: list[str] = field(default_factory=list)
    file_path: Optional[str] = None


@dataclass
class CallGraph:
    """
    Call graph representing function call relationships.
    
    Supports:
    - Finding callers of a function
    - Finding callees from a function
    - Traversing call chains
    """
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    call_sites: list[CallSite] = field(default_factory=list)
    
    # Pre-computed edges for fast lookup
    _callers: dict[str, set[str]] = field(default_factory=dict)
    _callees: dict[str, set[str]] = field(default_factory=dict)
    
    def add_function(self, func: FunctionInfo) -> None:
        """Add a function to the graph."""
        self.functions[func.name] = func
        if func.name not in self._callers:
            self._callers[func.name] = set()
        if func.name not in self._callees:
            self._callees[func.name] = set()
    
    def add_call(self, site: CallSite) -> None:
        """Add a call site to the graph."""
        self.call_sites.append(site)
        
        # Update caller/callee maps
        if site.callee not in self._callers:
            self._callers[site.callee] = set()
        self._callers[site.callee].add(site.caller)
        
        if site.caller not in self._callees:
            self._callees[site.caller] = set()
        self._callees[site.caller].add(site.callee)
    
    def get_callers(self, func_name: str) -> set[str]:
        """Get direct callers of a function."""
        return self._callers.get(func_name, set())
    
    def get_callees(self, func_name: str) -> set[str]:
        """Get functions directly called by a function."""
        return self._callees.get(func_name, set())
    
    def get_transitive_callers(
        self, 
        func_name: str, 
        max_depth: int = 5
    ) -> dict[str, int]:
        """
        Get all callers transitively, with their call depth.
        
        Returns:
            Dict mapping caller name to minimum depth from target function.
        """
        result = {}
        queue = [(func_name, 0)]
        visited = {func_name}
        
        while queue:
            current, depth = queue.pop(0)
            if depth > max_depth:
                continue
            
            for caller in self.get_callers(current):
                if caller not in visited:
                    visited.add(caller)
                    result[caller] = depth + 1
                    queue.append((caller, depth + 1))
        
        return result
    
    def get_transitive_callees(
        self, 
        func_name: str, 
        max_depth: int = 5
    ) -> dict[str, int]:
        """
        Get all callees transitively, with their call depth.
        
        Returns:
            Dict mapping callee name to minimum depth from caller function.
        """
        result = {}
        queue = [(func_name, 0)]
        visited = {func_name}
        
        while queue:
            current, depth = queue.pop(0)
            if depth > max_depth:
                continue
            
            for callee in self.get_callees(current):
                if callee not in visited:
                    visited.add(callee)
                    result[callee] = depth + 1
                    queue.append((callee, depth + 1))
        
        return result
    
    def get_call_chain(
        self, 
        from_func: str, 
        to_func: str
    ) -> Optional[list[str]]:
        """
        Find a call chain from one function to another.
        
        Returns:
            List of function names forming the chain, or None if no path exists.
        """
        if from_func == to_func:
            return [from_func]
        
        queue = [(from_func, [from_func])]
        visited = {from_func}
        
        while queue:
            current, path = queue.pop(0)
            
            for callee in self.get_callees(current):
                if callee == to_func:
                    return path + [callee]
                
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))
        
        return None
    
    def get_call_sites_for(
        self, 
        caller: str = None, 
        callee: str = None
    ) -> list[CallSite]:
        """Get call sites filtered by caller and/or callee."""
        result = []
        for site in self.call_sites:
            if caller and site.caller != caller:
                continue
            if callee and site.callee != callee:
                continue
            result.append(site)
        return result
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "functions": {
                name: {
                    "name": f.name,
                    "file_path": f.file_path,
                    "calls": f.calls,
                    "parameters": f.parameters,
                }
                for name, f in self.functions.items()
            },
            "call_sites": [
                {
                    "caller": s.caller,
                    "callee": s.callee,
                    "line": s.line,
                    "arguments": s.arguments,
                    "file_path": s.file_path,
                }
                for s in self.call_sites
            ],
            "summary": {
                "total_functions": len(self.functions),
                "total_call_sites": len(self.call_sites),
                "unique_callers": len(self._callers),
            }
        }


def build_call_graph(source_code: str, file_path: str = None) -> CallGraph:
    """
    Build a call graph from C source code.
    
    Args:
        source_code: C source code
        file_path: Optional file path for context
    
    Returns:
        CallGraph with function definitions and call sites
    """
    graph = CallGraph()
    source_bytes = source_code.encode("utf-8")
    
    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return graph
    
    root = tree.root_node
    
    # Find all function definitions
    func_nodes = _find_all_nodes_type(root, "function_definition")
    
    for func_node in func_nodes:
        func_info = _extract_function_info(func_node, source_bytes, file_path)
        if func_info:
            graph.add_function(func_info)
            
            # Find all calls within this function
            call_nodes = _find_all_nodes_type(func_node, "call_expression")
            for call in call_nodes:
                site = _extract_call_site(call, func_info.name, source_bytes, file_path)
                if site:
                    func_info.calls.append(site.callee)
                    graph.add_call(site)
    
    return graph


def build_call_graph_multi_file(files: dict[str, str]) -> CallGraph:
    """
    Build a call graph from multiple source files.
    
    Args:
        files: Dict mapping file paths to source code
    
    Returns:
        Combined CallGraph from all files
    """
    graph = CallGraph()
    
    for file_path, source_code in files.items():
        file_graph = build_call_graph(source_code, file_path)
        
        # Merge functions
        for name, func in file_graph.functions.items():
            graph.add_function(func)
        
        # Merge call sites
        for site in file_graph.call_sites:
            graph.add_call(site)
    
    return graph


def _extract_function_info(
    func_node: Node, 
    source: bytes, 
    file_path: str = None
) -> Optional[FunctionInfo]:
    """Extract function information from a function_definition node."""
    declarator = _find_node_type(func_node, "function_declarator")
    if not declarator:
        return None
    
    # Get function name
    name = None
    for child in declarator.children:
        if child.type == "identifier":
            name = source[child.start_byte:child.end_byte].decode("utf-8")
            break
    
    if not name:
        return None
    
    # Get parameters
    params = []
    param_list = _find_node_type(declarator, "parameter_list")
    if param_list:
        for child in param_list.children:
            if child.type == "parameter_declaration":
                param_name = None
                param_type = ""
                
                for sub in child.children:
                    if sub.type == "identifier":
                        param_name = source[sub.start_byte:sub.end_byte].decode("utf-8")
                    elif sub.type in ("primitive_type", "type_identifier"):
                        param_type = source[sub.start_byte:sub.end_byte].decode("utf-8")
                    elif sub.type == "pointer_declarator":
                        param_type += " *"
                        for ptr_child in sub.children:
                            if ptr_child.type == "identifier":
                                param_name = source[ptr_child.start_byte:ptr_child.end_byte].decode("utf-8")
                
                if param_name:
                    params.append({"name": param_name, "type": param_type})
    
    return FunctionInfo(
        name=name,
        file_path=file_path,
        start_line=func_node.start_point[0] + 1,
        end_line=func_node.end_point[0] + 1,
        parameters=params,
    )


def _extract_call_site(
    call_node: Node, 
    caller: str, 
    source: bytes,
    file_path: str = None
) -> Optional[CallSite]:
    """Extract call site information from a call_expression node."""
    callee = None
    for child in call_node.children:
        if child.type == "identifier":
            callee = source[child.start_byte:child.end_byte].decode("utf-8")
            break
    
    if not callee:
        return None
    
    # Get arguments
    args = []
    for child in call_node.children:
        if child.type == "argument_list":
            for arg in child.children:
                if arg.type not in ("(", ")", ","):
                    arg_text = source[arg.start_byte:arg.end_byte].decode("utf-8")
                    args.append(arg_text)
    
    return CallSite(
        caller=caller,
        callee=callee,
        line=call_node.start_point[0] + 1,
        arguments=args,
        file_path=file_path,
    )


def _find_node_type(node: Node, node_type: str) -> Optional[Node]:
    """Find first node of given type."""
    if node.type == node_type:
        return node
    for child in node.children:
        result = _find_node_type(child, node_type)
        if result:
            return result
    return None


def _find_all_nodes_type(node: Node, node_type: str) -> list[Node]:
    """Find all nodes of given type."""
    results = []
    
    def traverse(n: Node):
        if n.type == node_type:
            results.append(n)
        for child in n.children:
            traverse(child)
    
    traverse(node)
    return results


# MCP Tool interface
def call_graph_tool(source_code: str) -> dict:
    """
    MCP Tool: Build call graph from C source code.
    
    Returns information about function call relationships.
    """
    graph = build_call_graph(source_code)
    return graph.to_dict()
