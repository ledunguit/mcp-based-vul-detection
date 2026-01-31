"""
Inter-procedural Taint Analysis - Phase 2.1

Extends basic taint analysis to track taint flow across function boundaries.
Uses function summaries and call graphs for context-sensitive analysis.
"""

from dataclasses import dataclass, field
from typing import Optional

from .taint_server import (
    TaintSource,
    TaintSink,
    TaintPath,
    TaintAnalysisOutput,
    analyze_taint,
)
from .function_summary import (
    FunctionSummary,
    ParameterTaint,
    get_builtin_summary,
    BUILTIN_SUMMARIES,
)
from .call_graph import (
    CallGraph,
    CallSite,
    build_call_graph,
)


@dataclass
class InterproceduralTaintPath:
    """A taint path that crosses function boundaries."""
    source: TaintSource
    sink: TaintSink
    call_chain: list[str]  # Function names in the call path
    path_details: list[dict]  # Details at each step
    is_validated: bool = False
    depth: int = 0


@dataclass  
class InterproceduralTaintOutput:
    """Output from inter-procedural taint analysis."""
    # Basic intra-procedural results
    basic_results: dict[str, TaintAnalysisOutput] = field(default_factory=dict)
    
    # Inter-procedural paths
    interprocedural_paths: list[InterproceduralTaintPath] = field(default_factory=list)
    
    # Function summaries generated
    function_summaries: dict[str, FunctionSummary] = field(default_factory=dict)
    
    # Call graph used
    call_graph_summary: dict = field(default_factory=dict)
    
    # Summary statistics
    total_functions: int = 0
    total_interprocedural_paths: int = 0
    max_depth_reached: int = 0


class InterproceduralTaintAnalyzer:
    """
    Analyzer for tracking taint across function boundaries.
    
    Workflow:
    1. Parse source code and build call graph
    2. Generate function summaries (or use provided ones)
    3. Perform intra-procedural analysis on each function
    4. Propagate taint through call edges using summaries
    
    Example:
        analyzer = InterproceduralTaintAnalyzer()
        result = analyzer.analyze(source_code, max_depth=2)
    """
    
    def __init__(self, external_summaries: dict[str, FunctionSummary] = None):
        """
        Initialize analyzer.
        
        Args:
            external_summaries: Pre-computed function summaries (e.g., for libraries)
        """
        self.external_summaries = external_summaries or {}
        self._combine_with_builtins()
    
    def _combine_with_builtins(self):
        """Combine external summaries with built-in ones."""
        # Built-ins have lower priority
        for name, summary in BUILTIN_SUMMARIES.items():
            if name not in self.external_summaries:
                self.external_summaries[name] = summary
    
    def analyze(
        self,
        source_code: str,
        max_depth: int = 2,
        entry_points: list[str] = None,
    ) -> InterproceduralTaintOutput:
        """
        Perform inter-procedural taint analysis.
        
        Args:
            source_code: C source code containing function definitions
            max_depth: Maximum call depth to analyze
            entry_points: Optional list of entry point functions
        
        Returns:
            InterproceduralTaintOutput with all analysis results
        """
        output = InterproceduralTaintOutput()
        
        # Step 1: Build call graph
        call_graph = build_call_graph(source_code)
        output.call_graph_summary = call_graph.to_dict().get("summary", {})
        output.total_functions = len(call_graph.functions)
        
        # Step 2: Perform intra-procedural analysis on each function
        for func_name, func_info in call_graph.functions.items():
            # Extract function body for analysis
            func_code = self._extract_function_code(source_code, func_info)
            if func_code:
                result = analyze_taint(func_code)
                output.basic_results[func_name] = result
        
        # Step 3: Generate summaries for analyzed functions
        for func_name, basic_result in output.basic_results.items():
            if func_name not in self.external_summaries:
                summary = self._generate_summary(func_name, basic_result, call_graph)
                output.function_summaries[func_name] = summary
                self.external_summaries[func_name] = summary
        
        # Step 4: Find inter-procedural taint paths
        entry_funcs = entry_points or list(call_graph.functions.keys())
        
        for entry in entry_funcs:
            if entry in output.basic_results:
                paths = self._trace_interprocedural(
                    entry,
                    output.basic_results[entry],
                    call_graph,
                    max_depth,
                )
                output.interprocedural_paths.extend(paths)
        
        # Update statistics
        output.total_interprocedural_paths = len(output.interprocedural_paths)
        if output.interprocedural_paths:
            output.max_depth_reached = max(p.depth for p in output.interprocedural_paths)
        
        return output
    
    def _extract_function_code(
        self, 
        source_code: str, 
        func_info
    ) -> Optional[str]:
        """Extract function body from source code."""
        lines = source_code.split('\n')
        start = func_info.start_line - 1
        end = func_info.end_line
        
        if start >= 0 and end <= len(lines):
            return '\n'.join(lines[start:end])
        return None
    
    def _generate_summary(
        self,
        func_name: str,
        result: TaintAnalysisOutput,
        call_graph: CallGraph,
    ) -> FunctionSummary:
        """Generate a function summary from analysis results."""
        params = []
        
        # Analyze parameters from taint sources
        param_sources = [s for s in result.taint_sources if s.source_type == "parameter"]
        
        for i, src in enumerate(param_sources):
            is_sink = any(
                src.variable in sink.arguments 
                for sink in result.taint_sinks
            )
            propagates_to_return = False  # Would need return analysis
            
            params.append(ParameterTaint(
                index=i,
                name=src.variable or f"param{i}",
                is_source=True,  # All params are potential sources
                is_sink=is_sink,
                propagates_to_return=propagates_to_return,
            ))
        
        # Get called functions
        calls = list(call_graph.get_callees(func_name))
        
        return FunctionSummary(
            name=func_name,
            parameters=params,
            calls=calls,
            validates_bounds=len(result.validation_checks) > 0,
        )
    
    def _trace_interprocedural(
        self,
        func_name: str,
        basic_result: TaintAnalysisOutput,
        call_graph: CallGraph,
        max_depth: int,
        current_depth: int = 0,
        visited: set = None,
    ) -> list[InterproceduralTaintPath]:
        """Trace taint through function calls."""
        if visited is None:
            visited = set()
        
        if current_depth >= max_depth or func_name in visited:
            return []
        
        visited.add(func_name)
        paths = []
        
        # Convert basic paths to inter-procedural
        for basic_path in basic_result.taint_paths:
            paths.append(InterproceduralTaintPath(
                source=basic_path.source,
                sink=basic_path.sink,
                call_chain=[func_name],
                path_details=[{
                    "function": func_name,
                    "path": basic_path.path,
                }],
                is_validated=basic_path.is_validated,
                depth=current_depth,
            ))
        
        # Trace through function calls
        callees = call_graph.get_callees(func_name)
        
        for callee in callees:
            callee_summary = self.external_summaries.get(callee)
            
            if callee_summary:
                # Check if any tainted data flows into callee's sink params
                sink_params = callee_summary.get_sink_params()
                
                if sink_params:
                    # Get call sites to this callee
                    call_sites = call_graph.get_call_sites_for(
                        caller=func_name, 
                        callee=callee
                    )
                    
                    for site in call_sites:
                        for i in sink_params:
                            if i < len(site.arguments):
                                arg = site.arguments[i]
                                
                                # Check if this argument is tainted in the caller
                                for src in basic_result.taint_sources:
                                    if src.variable and src.variable in arg:
                                        # Found inter-procedural path!
                                        sink = TaintSink(
                                            function=callee,
                                            line=site.line,
                                            arguments=site.arguments,
                                            tainted_args=[i],
                                        )
                                        
                                        paths.append(InterproceduralTaintPath(
                                            source=src,
                                            sink=sink,
                                            call_chain=[func_name, callee],
                                            path_details=[
                                                {"function": func_name, "variable": src.variable},
                                                {"function": callee, "argument": i, "arg_value": arg},
                                            ],
                                            is_validated=callee_summary.validates_bounds,
                                            depth=current_depth + 1,
                                        ))
        
        return paths


def analyze_taint_interprocedural(
    source_code: str,
    max_depth: int = 2,
    external_summaries: dict[str, FunctionSummary] = None,
) -> dict:
    """
    MCP Tool: Perform inter-procedural taint analysis.
    
    Tracks taint flow across function boundaries up to max_depth calls.
    
    Args:
        source_code: C source code
        max_depth: Maximum call depth (default: 2)
        external_summaries: Pre-computed function summaries
    
    Returns:
        Dict with analysis results
    """
    analyzer = InterproceduralTaintAnalyzer(external_summaries)
    result = analyzer.analyze(source_code, max_depth=max_depth)
    
    return {
        "total_functions": result.total_functions,
        "total_interprocedural_paths": result.total_interprocedural_paths,
        "max_depth_reached": result.max_depth_reached,
        "call_graph_summary": result.call_graph_summary,
        "interprocedural_paths": [
            {
                "source": {
                    "name": p.source.name,
                    "type": p.source.source_type,
                    "variable": p.source.variable,
                },
                "sink": {
                    "function": p.sink.function,
                    "line": p.sink.line,
                    "tainted_args": p.sink.tainted_args,
                },
                "call_chain": p.call_chain,
                "is_validated": p.is_validated,
                "depth": p.depth,
            }
            for p in result.interprocedural_paths
        ],
        "function_summaries": {
            name: summary.to_dict()
            for name, summary in result.function_summaries.items()
        },
        "basic_results": {
            name: {
                "taint_sources": len(r.taint_sources),
                "taint_sinks": len(r.taint_sinks),
                "taint_paths": len(r.taint_paths),
            }
            for name, r in result.basic_results.items()
        },
    }
