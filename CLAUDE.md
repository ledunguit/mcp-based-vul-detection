# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP-Vul is a Master's thesis research project implementing **LLM-orchestrated vulnerability detection** using the **Model Context Protocol (MCP)**. It analyzes C source code to detect security vulnerabilities across multiple CWE categories using a hybrid approach combining static analysis tools with LLM reasoning.

## Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run analysis on a file
python -m src.pipeline path/to/code.c -v

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_mcp_protocol.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run experiments
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches static_only llm_only mcp_based \
  --output results/

# Analyze experiment results
python experiments/analyze_results.py --input results/combined_*.json
```

## Architecture

The system uses a four-layer architecture:

1. **Orchestrator Layer** (`src/agents/orchestrator.py`) - LLM-driven tool selection with Chain of Thought reasoning, aggregates evidence from multiple tools

2. **MCP Protocol Layer** (`src/mcp_protocol/`) - JSON-RPC 2.0 compliant tool communication with registry and call history tracking

3. **Tool Layer** (`src/mcp_servers/`) - 6 analysis tools:
   - `ast_server.py` - Tree-sitter C parser with buffer size extraction
   - `static_analysis_server.py` - Clang Static Analyzer
   - `cwe_knowledge_server.py` - CWE knowledge base
   - `taint_server.py` - Enhanced taint analysis with alias/field sensitivity
   - `pattern_server.py` - Pattern matching (12+ patterns)
   - `cfg_server.py` - Control flow graph analysis

4. **Judge Layer** (`src/agents/judge.py`, `src/agents/ensemble_judge.py`) - Evidence validation with 4 perspectives and Chain of Thought reasoning

## Recent Improvements

### Enhanced Taint Analysis
- **Alias Analysis**: Tracks pointer assignments (`p = &x` → p points to x)
- **Field Sensitivity**: Tracks struct fields separately (`s.field1` vs `s.field2`)
- **TaintLocation Dataclass**: Precise memory location tracking
- **Location**: `src/mcp_servers/taint_server.py`

### Parallel Tool Execution
- **7x speedup** in batch mode via async execution
- Wave-based parallelization respecting dependencies
- Wave 1 (parallel): ast_analyze, static_analyze, taint_analyze, pattern_analyze
- Wave 2 (parallel): cfg_analyze, cwe_lookup calls
- **Location**: `src/agents/orchestrator.py` - `analyze_batch_async()`

### AST Buffer Size Extraction
- Extracts numeric sizes: `char buffer[32]` → `size=32`
- Extracts symbolic sizes: `char buffer[MAX_SIZE]` → `size_expr="MAX_SIZE"`
- Tracks heap allocations: `buf = malloc(1024)` → `size_expr="1024"`
- **Location**: `src/mcp_servers/ast_server.py`, `src/schemas.py`

### Chain of Thought (CoT) Prompting
All LLM prompts now use structured step-by-step reasoning:

| Component | CoT Steps |
|-----------|-----------|
| Orchestrator | Sink ID → Data Flow → Safety Checks → Synthesis |
| Judge | Sink Check → Flow Check → Missing Checks → Verdict |
| Ensemble Judge | Perspective-specific 3-step reasoning |
| LLM-Only Baseline | Buffers → Sources → Flow → Validation → Verdict |

### Optimized Prompts
- **58% token reduction** in prompts (~9,800 → ~4,100 tokens)
- Table format for quick reference
- Unified decision criteria across components
- Enhanced ensemble perspective prompts with specific guidance

## CWE Handlers

Located in `src/mcp_servers/cwe_handlers/`, each handler implements `CWEHandler` ABC:

| Handler | CWEs |
|---------|------|
| `buffer_overflow.py` | 120, 121, 122, 125, 787 |
| `sql_injection.py` | 89 |
| `command_injection.py` | 78 |
| `xss.py` | 79 |
| `path_traversal.py` | 22, 23, 36 |

## Key Patterns

- **MCP Protocol**: All tools implement `MCPServer` ABC from `mcp_protocol/base_server.py`
- **Handler Registry**: CWE handlers use `CWERegistry.get_handler(cwe_id)` for lookup
- **Async/Await**: All MCP server methods are async; parallel execution via `asyncio.gather()`
- **Pydantic Models**: Data validation via `src/schemas.py`
- **Evidence-Based**: All conclusions must reference specific tool outputs
- **Chain of Thought**: All LLM prompts use structured step-by-step reasoning

## Output Formats

### Orchestrator Output (with CoT)
```json
{
  "chain_of_thought": {
    "step1_sinks": "risky sinks found",
    "step2_data_flow": "source to sink flow",
    "step3_safety_checks": "checks present/missing",
    "step4_synthesis": "evidence summary"
  },
  "hypothesis": "VULNERABLE|SAFE|NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "evidence": [{"tool": "name", "finding": "what", "citation": "exact output"}],
  "reasoning": "final explanation"
}
```

### Judge Output (with CoT)
```json
{
  "chain_of_thought": {
    "step1_sink": "sink evidence",
    "step2_flow": "flow evidence",
    "step3_checks": "safety check evidence",
    "step4_verdict": "verdict reasoning"
  },
  "verdict": "VULNERABLE|SAFE|NOT_ENOUGH_EVIDENCE",
  "confidence": 0.0-1.0,
  "validation": {
    "dangerous_sink": {"present": true, "citation": "...", "confidence": "strong"},
    "data_flow": {"present": true, "citation": "...", "confidence": "strong"},
    "missing_checks": {"present": true, "citation": "...", "confidence": "medium"}
  }
}
```

## Configuration

Copy `.env.example` to `.env` and set:
- `LLM_PROVIDER` - "claude" or "local"
- `ANTHROPIC_API_KEY` - for Claude API
- `LOCAL_LLM_BASE_URL` and `LOCAL_LLM_MODEL` - for local LLM

## External Dependencies

- Clang/LLVM required for static analysis (`brew install llvm` on macOS)
- tree-sitter for AST parsing

## Performance Characteristics

| Feature | Improvement |
|---------|-------------|
| Parallel tool execution | 7x speedup in batch mode |
| Prompt optimization | 58% token reduction |
| Enhanced taint analysis | Alias + field sensitivity |
| Buffer size extraction | Numeric + symbolic + heap |
| Chain of Thought | Structured reasoning in all prompts |
