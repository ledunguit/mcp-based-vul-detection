"""Control Flow Graph Server - Extract CFG for code path analysis.

This MCP tool server extracts control flow information to understand:
- Basic blocks and their relationships
- Conditional branches (if/else, switch)
- Loops (for, while, do-while)
- Code paths to dangerous sinks
- Validation checks on code paths

This helps determine if there are execution paths that bypass security checks.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
import re

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node

from src.config import RISKY_FUNCTIONS


# Initialize tree-sitter parser
C_LANGUAGE = Language(tsc.language())
parser = Parser(C_LANGUAGE)


@dataclass
class BasicBlock:
    """A basic block in the CFG."""
    id: int
    start_line: int
    end_line: int
    statements: list[str] = field(default_factory=list)
    has_sink: bool = False
    sink_functions: list[str] = field(default_factory=list)
    has_validation: bool = False
    validation_type: Optional[str] = None


@dataclass
class CFGEdge:
    """An edge in the CFG."""
    from_block: int
    to_block: int
    edge_type: str  # "sequential", "true_branch", "false_branch", "loop_back"
    condition: Optional[str] = None


@dataclass
class LoopInfo:
    """Information about a loop."""
    loop_type: str  # "for", "while", "do_while"
    start_line: int
    end_line: int
    condition: str
    contains_sink: bool = False


@dataclass
class BranchInfo:
    """Information about a conditional branch."""
    branch_type: str  # "if", "switch"
    line: int
    condition: str
    has_bounds_check: bool = False
    branches_count: int = 0


@dataclass
class PathToSink:
    """A code path from entry to a sink."""
    sink_function: str
    sink_line: int
    path_blocks: list[int]  # Block IDs in path
    has_validation_before_sink: bool = False
    validation_details: Optional[str] = None


@dataclass
class CFGOutput:
    """Output from CFG analysis."""
    function_name: Optional[str] = None
    basic_blocks: list[BasicBlock] = field(default_factory=list)
    edges: list[CFGEdge] = field(default_factory=list)
    loops: list[LoopInfo] = field(default_factory=list)
    branches: list[BranchInfo] = field(default_factory=list)
    paths_to_sinks: list[PathToSink] = field(default_factory=list)
    entry_block: int = 0
    exit_blocks: list[int] = field(default_factory=list)
    total_blocks: int = 0
    cyclomatic_complexity: int = 1
    parse_error: Optional[str] = None


def analyze_cfg(source_code: str) -> CFGOutput:
    """
    Analyze the control flow graph of C source code.
    
    This extracts:
    1. Basic blocks (sequences of statements)
    2. Control flow edges
    3. Loop and branch information
    4. Paths to dangerous sinks
    """
    source_bytes = source_code.encode("utf-8")
    
    try:
        tree = parser.parse(source_bytes)
    except Exception as e:
        return CFGOutput(parse_error=f"Parse error: {str(e)}")
    
    root = tree.root_node
    
    # Find function definition
    func_node = _find_function_definition(root)
    if not func_node:
        return CFGOutput(parse_error="No function definition found")
    
    # Get function name
    func_name = _get_function_name(func_node, source_bytes)
    
    # Find the compound statement (function body)
    body = _find_node_type(func_node, "compound_statement")
    if not body:
        return CFGOutput(function_name=func_name, parse_error="No function body found")
    
    # Build CFG
    blocks = []
    edges = []
    loops = []
    branches = []
    block_counter = [0]  # Use list to allow mutation in nested function
    
    # Analyze the function body
    _analyze_compound_statement(
        body, source_bytes, blocks, edges, loops, branches, block_counter
    )
    
    # Find exit blocks (blocks with no outgoing edges)
    block_ids = {b.id for b in blocks}
    from_blocks = {e.from_block for e in edges}
    exit_blocks = [b.id for b in blocks if b.id not in from_blocks or b.id == block_counter[0] - 1]
    
    # Calculate cyclomatic complexity: E - N + 2P (P=1 for single function)
    cyclomatic = len(edges) - len(blocks) + 2
    
    # Find paths to sinks
    paths_to_sinks = _find_paths_to_sinks(blocks, edges)
    
    return CFGOutput(
        function_name=func_name,
        basic_blocks=blocks,
        edges=edges,
        loops=loops,
        branches=branches,
        paths_to_sinks=paths_to_sinks,
        entry_block=0 if blocks else -1,
        exit_blocks=exit_blocks,
        total_blocks=len(blocks),
        cyclomatic_complexity=max(1, cyclomatic),
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


def _find_node_type(node: Node, node_type: str) -> Optional[Node]:
    """Find a node of specific type."""
    if node.type == node_type:
        return node
    for child in node.children:
        result = _find_node_type(child, node_type)
        if result:
            return result
    return None


def _get_function_name(func_node: Node, source: bytes) -> Optional[str]:
    """Get function name from function definition."""
    declarator = _find_node_type(func_node, "function_declarator")
    if declarator:
        for child in declarator.children:
            if child.type == "identifier":
                return source[child.start_byte:child.end_byte].decode("utf-8")
    return None


def _analyze_compound_statement(
    node: Node,
    source: bytes,
    blocks: list[BasicBlock],
    edges: list[CFGEdge],
    loops: list[LoopInfo],
    branches: list[BranchInfo],
    block_counter: list[int],
    parent_block_id: Optional[int] = None,
) -> tuple[int, list[int]]:
    """
    Analyze a compound statement and build CFG components.
    
    Returns:
        Tuple of (entry_block_id, exit_block_ids)
    """
    current_statements = []
    current_start_line = node.start_point[0] + 1
    entry_block_id = None
    last_block_id = parent_block_id
    current_exit_blocks = []
    
    for child in node.children:
        if child.type in ("{", "}"):
            continue
        
        # Check for control flow statements
        if child.type == "if_statement":
            # Flush current block
            if current_statements:
                block = _create_block(
                    block_counter, current_start_line, child.start_point[0],
                    current_statements, source
                )
                blocks.append(block)
                if entry_block_id is None:
                    entry_block_id = block.id
                if last_block_id is not None and last_block_id != block.id:
                    edges.append(CFGEdge(last_block_id, block.id, "sequential"))
                last_block_id = block.id
                current_statements = []
            
            # Analyze if statement
            if_entry, if_exits = _analyze_if_statement(
                child, source, blocks, edges, loops, branches, block_counter
            )
            
            if last_block_id is not None:
                edges.append(CFGEdge(last_block_id, if_entry, "sequential"))
            if entry_block_id is None:
                entry_block_id = if_entry
            
            current_exit_blocks.extend(if_exits)
            last_block_id = None  # Multiple exits
            current_start_line = child.end_point[0] + 2
            
        elif child.type in ("for_statement", "while_statement", "do_statement"):
            # Flush current block
            if current_statements:
                block = _create_block(
                    block_counter, current_start_line, child.start_point[0],
                    current_statements, source
                )
                blocks.append(block)
                if entry_block_id is None:
                    entry_block_id = block.id
                if last_block_id is not None and last_block_id != block.id:
                    edges.append(CFGEdge(last_block_id, block.id, "sequential"))
                last_block_id = block.id
                current_statements = []
            
            # Analyze loop
            loop_entry, loop_exits = _analyze_loop(
                child, source, blocks, edges, loops, branches, block_counter
            )
            
            if last_block_id is not None:
                edges.append(CFGEdge(last_block_id, loop_entry, "sequential"))
            if entry_block_id is None:
                entry_block_id = loop_entry
            
            # After loop, continue from loop exits
            last_block_id = loop_entry  # Loop can exit to next statement
            current_exit_blocks.extend(loop_exits)
            current_start_line = child.end_point[0] + 2
            
        elif child.type == "return_statement":
            # Add return to current statements and create block
            stmt_text = source[child.start_byte:child.end_byte].decode("utf-8")
            current_statements.append(stmt_text)
            
            block = _create_block(
                block_counter, current_start_line, child.end_point[0] + 1,
                current_statements, source
            )
            blocks.append(block)
            if entry_block_id is None:
                entry_block_id = block.id
            if last_block_id is not None and last_block_id != block.id:
                edges.append(CFGEdge(last_block_id, block.id, "sequential"))
            
            current_exit_blocks.append(block.id)
            current_statements = []
            last_block_id = None  # Return terminates path
            current_start_line = child.end_point[0] + 2
            
        else:
            # Regular statement
            stmt_text = source[child.start_byte:child.end_byte].decode("utf-8")
            current_statements.append(stmt_text)
    
    # Create final block if there are remaining statements
    if current_statements:
        block = _create_block(
            block_counter, current_start_line, node.end_point[0],
            current_statements, source
        )
        blocks.append(block)
        if entry_block_id is None:
            entry_block_id = block.id
        if last_block_id is not None and last_block_id != block.id:
            edges.append(CFGEdge(last_block_id, block.id, "sequential"))
        current_exit_blocks.append(block.id)
    elif last_block_id is not None and last_block_id not in current_exit_blocks:
        current_exit_blocks.append(last_block_id)
    
    return entry_block_id or 0, current_exit_blocks


def _analyze_if_statement(
    node: Node,
    source: bytes,
    blocks: list[BasicBlock],
    edges: list[CFGEdge],
    loops: list[LoopInfo],
    branches: list[BranchInfo],
    block_counter: list[int],
) -> tuple[int, list[int]]:
    """Analyze an if statement."""
    condition = ""
    then_node = None
    else_node = None
    
    for child in node.children:
        if child.type == "parenthesized_expression":
            condition = source[child.start_byte:child.end_byte].decode("utf-8")
        elif child.type == "compound_statement" and then_node is None:
            then_node = child
        elif child.type == "else_clause":
            for else_child in child.children:
                if else_child.type in ("compound_statement", "if_statement"):
                    else_node = else_child
    
    # Create condition block
    cond_block = BasicBlock(
        id=block_counter[0],
        start_line=node.start_point[0] + 1,
        end_line=node.start_point[0] + 1,
        statements=[f"if {condition}"],
        has_validation=_is_bounds_check(condition),
        validation_type="bounds_check" if _is_bounds_check(condition) else None,
    )
    block_counter[0] += 1
    blocks.append(cond_block)
    
    # Record branch info
    branches.append(BranchInfo(
        branch_type="if",
        line=node.start_point[0] + 1,
        condition=condition,
        has_bounds_check=_is_bounds_check(condition),
        branches_count=2 if else_node else 1,
    ))
    
    exit_blocks = []
    
    # Analyze then branch
    if then_node:
        then_entry, then_exits = _analyze_compound_statement(
            then_node, source, blocks, edges, loops, branches, block_counter
        )
        edges.append(CFGEdge(cond_block.id, then_entry, "true_branch", condition))
        exit_blocks.extend(then_exits)
    
    # Analyze else branch
    if else_node:
        if else_node.type == "if_statement":
            else_entry, else_exits = _analyze_if_statement(
                else_node, source, blocks, edges, loops, branches, block_counter
            )
        else:
            else_entry, else_exits = _analyze_compound_statement(
                else_node, source, blocks, edges, loops, branches, block_counter
            )
        edges.append(CFGEdge(cond_block.id, else_entry, "false_branch", f"!{condition}"))
        exit_blocks.extend(else_exits)
    else:
        # No else - condition block is also an exit
        exit_blocks.append(cond_block.id)
    
    return cond_block.id, exit_blocks


def _analyze_loop(
    node: Node,
    source: bytes,
    blocks: list[BasicBlock],
    edges: list[CFGEdge],
    loops: list[LoopInfo],
    branches: list[BranchInfo],
    block_counter: list[int],
) -> tuple[int, list[int]]:
    """Analyze a loop statement."""
    loop_type = node.type.replace("_statement", "")
    condition = ""
    body_node = None
    
    for child in node.children:
        if child.type == "parenthesized_expression":
            condition = source[child.start_byte:child.end_byte].decode("utf-8")
        elif child.type == "compound_statement":
            body_node = child
    
    # Create loop header block
    header_block = BasicBlock(
        id=block_counter[0],
        start_line=node.start_point[0] + 1,
        end_line=node.start_point[0] + 1,
        statements=[f"{loop_type} {condition}"],
    )
    block_counter[0] += 1
    blocks.append(header_block)
    
    # Analyze loop body
    exit_blocks = [header_block.id]  # Loop can exit to next statement
    
    if body_node:
        body_entry, body_exits = _analyze_compound_statement(
            body_node, source, blocks, edges, loops, branches, block_counter
        )
        edges.append(CFGEdge(header_block.id, body_entry, "true_branch", condition))
        
        # Loop back edges
        for exit_id in body_exits:
            edges.append(CFGEdge(exit_id, header_block.id, "loop_back"))
    
    # Check if loop body contains sinks
    body_text = source[body_node.start_byte:body_node.end_byte].decode("utf-8") if body_node else ""
    contains_sink = any(sink in body_text for sink in RISKY_FUNCTIONS)
    
    loops.append(LoopInfo(
        loop_type=loop_type,
        start_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
        condition=condition,
        contains_sink=contains_sink,
    ))
    
    return header_block.id, exit_blocks


def _create_block(
    counter: list[int],
    start_line: int,
    end_line: int,
    statements: list[str],
    source: bytes,
) -> BasicBlock:
    """Create a basic block."""
    block_id = counter[0]
    counter[0] += 1
    
    # Check for sinks in statements
    sinks = []
    for stmt in statements:
        for func in RISKY_FUNCTIONS:
            if func in stmt:
                sinks.append(func)
    
    # Check for validation
    combined = " ".join(statements)
    has_validation = _is_bounds_check(combined)
    
    return BasicBlock(
        id=block_id,
        start_line=start_line,
        end_line=end_line,
        statements=statements,
        has_sink=len(sinks) > 0,
        sink_functions=list(set(sinks)),
        has_validation=has_validation,
        validation_type="bounds_check" if has_validation else None,
    )


def _is_bounds_check(text: str) -> bool:
    """Check if text contains a bounds checking pattern."""
    bounds_patterns = [
        r'\bsizeof\b',
        r'\bstrlen\b',
        r'\blen\s*[<>=]',
        r'\bsize\s*[<>=]',
        r'[<>=]\s*\blen\b',
        r'[<>=]\s*\bsize\b',
        r'\bMAX\b',
        r'\bMIN\b',
    ]
    
    for pattern in bounds_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def _find_paths_to_sinks(blocks: list[BasicBlock], edges: list[CFGEdge]) -> list[PathToSink]:
    """Find all paths from entry to blocks containing sinks."""
    paths = []
    
    # Find blocks with sinks
    sink_blocks = [b for b in blocks if b.has_sink]
    
    if not blocks:
        return paths
    
    # Build adjacency list
    adj = {b.id: [] for b in blocks}
    for edge in edges:
        if edge.from_block in adj:
            adj[edge.from_block].append(edge.to_block)
    
    # For each sink block, trace back to entry
    for sink_block in sink_blocks:
        # Simple BFS to find path from entry (block 0) to sink
        path = _find_path_bfs(0, sink_block.id, adj)
        
        if path:
            # Check if any block on path has validation
            has_validation = False
            validation_details = None
            
            for block_id in path[:-1]:  # Check blocks before sink
                block = next((b for b in blocks if b.id == block_id), None)
                if block and block.has_validation:
                    has_validation = True
                    validation_details = block.validation_type
                    break
            
            for sink_func in sink_block.sink_functions:
                paths.append(PathToSink(
                    sink_function=sink_func,
                    sink_line=sink_block.start_line,
                    path_blocks=path,
                    has_validation_before_sink=has_validation,
                    validation_details=validation_details,
                ))
    
    return paths


def _find_path_bfs(start: int, end: int, adj: dict) -> list[int]:
    """Find a path from start to end using BFS."""
    if start == end:
        return [start]
    
    visited = {start}
    queue = [(start, [start])]
    
    while queue:
        current, path = queue.pop(0)
        
        for neighbor in adj.get(current, []):
            if neighbor == end:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))
    
    return []


# MCP Tool interface
def cfg_analyze_tool(source_code: str) -> dict:
    """
    MCP Tool: Analyze control flow graph of C source code.
    
    Returns CFG information including basic blocks, edges, loops,
    branches, and paths to dangerous sinks.
    """
    result = analyze_cfg(source_code)
    
    output = {
        "function_name": result.function_name,
        "basic_blocks": [asdict(b) for b in result.basic_blocks],
        "edges": [asdict(e) for e in result.edges],
        "loops": [asdict(l) for l in result.loops],
        "branches": [asdict(b) for b in result.branches],
        "paths_to_sinks": [asdict(p) for p in result.paths_to_sinks],
        "summary": {
            "entry_block": result.entry_block,
            "exit_blocks": result.exit_blocks,
            "total_blocks": result.total_blocks,
            "cyclomatic_complexity": result.cyclomatic_complexity,
            "has_loops": len(result.loops) > 0,
            "has_branches": len(result.branches) > 0,
            "sinks_without_validation": sum(
                1 for p in result.paths_to_sinks if not p.has_validation_before_sink
            ),
            "sinks_with_validation": sum(
                1 for p in result.paths_to_sinks if p.has_validation_before_sink
            ),
        }
    }
    
    if result.parse_error:
        output["parse_error"] = result.parse_error
    
    return output
