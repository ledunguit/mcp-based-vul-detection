# MCP-Based Vulnerability Detection

An experimental system for **LLM-orchestrated vulnerability detection** using the **Model Context Protocol (MCP)**.

> **Note**: This is the source code for a Master's thesis research project on applying LLM orchestration with MCP tools for automated vulnerability detection in C source code.

---

## Table of Contents

- [MCP-Based Vulnerability Detection](#mcp-based-vulnerability-detection)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
    - [Key Features](#key-features)
  - [System Architecture](#system-architecture)
  - [Module Structure](#module-structure)
  - [MCP Tools](#mcp-tools)
    - [Core Analysis Tools](#core-analysis-tools)
    - [Inter-procedural Analysis (NEW)](#inter-procedural-analysis-new)
    - [CWE Handlers (NEW)](#cwe-handlers-new)
  - [Supported CWEs](#supported-cwes)
  - [Quick Start](#quick-start)
    - [1. Installation](#1-installation)
    - [2. Configuration](#2-configuration)
    - [3. Run Analysis](#3-run-analysis)
  - [Experiments](#experiments)
    - [Dataset Preparation](#dataset-preparation)
    - [Run Experiments](#run-experiments)
    - [Enhanced Metrics (NEW)](#enhanced-metrics-new)
  - [Project Structure](#project-structure)
  - [Test Coverage](#test-coverage)
  - [Approach Comparison](#approach-comparison)
  - [Requirements](#requirements)
  - [Citation](#citation)
  - [License](#license)

---

## Overview

This system demonstrates:

- **LLM-based orchestration** using Model Context Protocol (MCP)
- **Multi-CWE vulnerability detection** for C source code
- **Evidence-based reasoning** with tool-grounded conclusions
- **Ensemble judging** with multiple analysis perspectives
- **Inter-procedural taint analysis** across function boundaries
- **Enhanced metrics** including AUC-ROC, statistical significance testing
- **Comparison with baselines** (LLM-only, static-only)

### Key Features

| Feature | Description |
|---------|-------------|
| 6 MCP Analysis Tools | AST, Static Analysis, CWE Knowledge, Taint, Pattern, CFG |
| 5 CWE Handlers | Buffer Overflow, SQL Injection, Command Injection, XSS, Path Traversal |
| Ensemble Judging | 4 perspectives with weighted voting |
| Inter-procedural Analysis | Cross-function taint tracking with call graph |
| MCP Protocol | JSON-RPC 2.0 compliant tool communication |
| Dataset Tools | SARD, NVD, Juliet dataset downloaders |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        MCP-VUL SYSTEM ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│                           Source Code (C function)                              │
│                                    │                                            │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                     ORCHESTRATOR AGENT (LLM)                            │   │
│  │  • Few-shot prompting                                                   │   │
│  │  • Tool selection and invocation                                        │   │
│  │  • Evidence aggregation                                                 │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                           ┌────────┴────────┐                                   │
│                           ▼                 ▼                                   │
│  ┌──────────────────────────────┐  ┌──────────────────────────────┐            │
│  │    MCP PROTOCOL LAYER        │  │    MCP PROTOCOL LAYER        │            │
│  │  • JSON-RPC 2.0              │  │  • Tool Registry             │            │
│  │  • MCPServer / MCPClient     │  │  • Call History Tracking     │            │
│  └──────────────────────────────┘  └──────────────────────────────┘            │
│                           │                 │                                   │
│                           ▼                 ▼                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                        MCP TOOL LAYER (6 Tools)                         │   │
│  ├─────────────────────────────────────────────────────────────────────────┤   │
│  │  Core Analysis:                    │  Advanced Analysis:                │   │
│  │    • AST Server (tree-sitter)      │    • Taint Analysis                │   │
│  │    • Static Analysis (Clang)       │    • Pattern Matching              │   │
│  │    • CWE Knowledge Base            │    • CFG Analysis                  │   │
│  ├─────────────────────────────────────────────────────────────────────────┤   │
│  │  NEW: Inter-procedural Analysis:   │  NEW: CWE Handlers:                │   │
│  │    • Function Summary              │    • Buffer Overflow (120,121,122) │   │
│  │    • Call Graph Builder            │    • SQL Injection (89)            │   │
│  │    • Cross-function Taint          │    • Command Injection (78)        │   │
│  │                                    │    • XSS (79), Path Traversal (22) │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                      JUDGE LAYER (Enhanced)                             │   │
│  ├─────────────────────────────────────────────────────────────────────────┤   │
│  │  Standard Judge:           │  NEW: Ensemble Judge:                      │   │
│  │    • Hallucination check   │    • Security Expert perspective           │   │
│  │    • Evidence validation   │    • Code Quality perspective              │   │
│  │    • Confidence scoring    │    • False Positive Filter perspective     │   │
│  │                            │    • Conservative perspective              │   │
│  │                            │    • Weighted voting aggregation           │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│                          Final Verdict + Evidence Trail                         │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Structure

```
src/
├── config.py                      # Configuration (API keys, LLM provider)
├── schemas.py                     # Pydantic data models
├── llm_client.py                  # Unified LLM client (Claude + Local)
├── pipeline.py                    # Main analysis pipeline
│
├── mcp_protocol/                  # NEW: MCP Protocol Implementation
│   ├── base_server.py             # MCPServer ABC, MCPRequest/Response
│   ├── client.py                  # MCPClient with call history
│   └── registry.py                # ToolRegistry for tool management
│
├── mcp_servers/                   # MCP Tool Servers
│   ├── ast_server.py              # Tree-sitter C parser
│   ├── static_analysis_server.py  # Clang Static Analyzer
│   ├── cwe_knowledge_server.py    # CWE knowledge base (multi-CWE)
│   ├── taint_server.py            # Intra-procedural taint analysis
│   ├── pattern_server.py          # Pattern matching (12+ patterns)
│   ├── cfg_server.py              # Control flow graph analysis
│   │
│   ├── function_summary.py        # NEW: Function summaries for taint
│   ├── call_graph.py              # NEW: Call graph builder
│   ├── interprocedural_taint.py   # NEW: Cross-function taint analysis
│   │
│   └── cwe_handlers/              # NEW: Multi-CWE Support
│       ├── base.py                # CWEHandler ABC, CWERegistry
│       ├── buffer_overflow.py     # CWE-120, 121, 122, 125, 787
│       ├── sql_injection.py       # CWE-89
│       ├── command_injection.py   # CWE-78
│       ├── xss.py                 # CWE-79
│       └── path_traversal.py      # CWE-22, 23, 36
│
├── agents/                        # LLM Agents
│   ├── orchestrator.py            # Tool orchestration (few-shot)
│   ├── judge.py                   # Evidence validation
│   └── ensemble_judge.py          # NEW: Multi-perspective judging
│
├── metrics/                       # NEW: Enhanced Metrics
│   └── explanation_scorer.py      # LLM explanation quality scoring
│
└── baselines/                     # Comparison Baselines
    ├── static_only.py
    └── llm_only.py
```

---

## MCP Tools

### Core Analysis Tools

| Tool | Description | Output |
|------|-------------|--------|
| **ast_analyze** | Parse C code with tree-sitter | Function structure, variables, risky calls |
| **static_analyze** | Run Clang Static Analyzer | Security warnings, bug reports |
| **cwe_lookup** | Query CWE knowledge base | Safety checks, patterns, mitigations |
| **taint_analyze** | Track data flow (source → sink) | Taint paths, sanitization status |
| **pattern_analyze** | Match vulnerability patterns | Pattern matches with severity |
| **cfg_analyze** | Build control flow graph | Nodes, edges, paths to sinks |

### Inter-procedural Analysis (NEW)

| Component | Description |
|-----------|-------------|
| **FunctionSummary** | Summarizes function behavior for taint propagation |
| **CallGraph** | Builds caller/callee relationships across functions |
| **InterproceduralTaintAnalyzer** | Tracks taint across function boundaries |

### CWE Handlers (NEW)

| Handler | CWEs | Category |
|---------|------|----------|
| BufferOverflowHandler | 120, 121, 122, 125, 787 | Memory Safety |
| SQLInjectionHandler | 89 | Injection |
| CommandInjectionHandler | 78 | Injection |
| XSSHandler | 79 | Injection |
| PathTraversalHandler | 22, 23, 36 | Traversal |

---

## Supported CWEs

| CWE ID | Name | Handler |
|--------|------|---------|
| CWE-120 | Buffer Copy without Size Check | BufferOverflowHandler |
| CWE-121 | Stack-based Buffer Overflow | BufferOverflowHandler |
| CWE-122 | Heap-based Buffer Overflow | BufferOverflowHandler |
| CWE-125 | Out-of-bounds Read | BufferOverflowHandler |
| CWE-787 | Out-of-bounds Write | BufferOverflowHandler |
| CWE-89 | SQL Injection | SQLInjectionHandler |
| CWE-78 | OS Command Injection | CommandInjectionHandler |
| CWE-79 | Cross-site Scripting (XSS) | XSSHandler |
| CWE-22 | Path Traversal | PathTraversalHandler |

---

## Quick Start

### 1. Installation

```bash
# Clone and setup
cd MCP-Vul

# Create virtual environment (using pyenv)
pyenv virtualenv 3.12 mcp-vul
pyenv local mcp-vul

# Install dependencies
pip install -e ".[dev]"

# Install clang (macOS)
brew install llvm
```

### 2. Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
```

**.env options:**
```bash
# LLM Provider: "claude" or "local"
LLM_PROVIDER=claude

# Claude API (if LLM_PROVIDER=claude)
ANTHROPIC_API_KEY=sk-ant-xxx

# Local LLM (if LLM_PROVIDER=local)
LOCAL_LLM_BASE_URL=http://127.0.0.1:1234/v1
LOCAL_LLM_MODEL=your-model-name
```

### 3. Run Analysis

```bash
# Analyze a single file
python -m src.pipeline path/to/function.c -v

# Analyze from stdin
echo 'void bad(char *s) { char buf[32]; strcpy(buf, s); }' | python -m src.pipeline - -v

# With local LLM
LLM_PROVIDER=local python -m src.pipeline code.c -v
```

---

## Experiments

### Dataset Preparation

```bash
# Option A: Hand-crafted samples (quick)
python experiments/prepare_dataset.py --sample-only --output data/juliet_samples/dataset.json

# Option B: Download datasets for multi-CWE testing
python experiments/download_datasets.py --dataset all --cwe 120,89,78,79,22 --output experiments/datasets/
```

### Run Experiments

```bash
# Run all approaches
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches static_only llm_only mcp_based \
  --output results/

# Analyze results
python experiments/analyze_results.py --input results/combined_*.json
```

### Enhanced Metrics (NEW)

The analyzer now includes:
- **AUC-ROC** calculation from confidence scores
- **Tool Contribution Analysis** showing each tool's impact
- **McNemar's Test** for statistical significance between approaches
- **Explanation Quality Scoring** for LLM outputs

---

## Project Structure

```
MCP-Vul/
├── src/
│   ├── config.py                 # Configuration
│   ├── schemas.py                # Data models
│   ├── llm_client.py             # LLM client
│   ├── pipeline.py               # Main pipeline
│   ├── mcp_protocol/             # NEW: MCP Protocol
│   │   ├── base_server.py
│   │   ├── client.py
│   │   └── registry.py
│   ├── mcp_servers/              # Tool servers
│   │   ├── ast_server.py
│   │   ├── static_analysis_server.py
│   │   ├── cwe_knowledge_server.py
│   │   ├── taint_server.py
│   │   ├── pattern_server.py
│   │   ├── cfg_server.py
│   │   ├── function_summary.py   # NEW
│   │   ├── call_graph.py         # NEW
│   │   ├── interprocedural_taint.py  # NEW
│   │   └── cwe_handlers/         # NEW: Multi-CWE
│   ├── agents/
│   │   ├── orchestrator.py
│   │   ├── judge.py
│   │   └── ensemble_judge.py     # NEW
│   ├── metrics/                  # NEW
│   │   └── explanation_scorer.py
│   └── baselines/
├── experiments/
│   ├── prepare_dataset.py
│   ├── extract_juliet.py
│   ├── download_datasets.py      # NEW
│   ├── run_experiment.py
│   └── analyze_results.py        # Enhanced
├── data/
│   ├── cwe_knowledge.json
│   └── juliet_samples/
├── results/
└── tests/                        # 112 tests
```

---

## Test Coverage

| Test File | Tests | Coverage |
|-----------|-------|----------|
| test_enhanced_metrics.py | 10 | AUC-ROC, Tool Contribution, McNemar |
| test_mcp_protocol.py | 20 | MCPServer, Client, Registry |
| test_interprocedural_taint.py | 18 | Function Summary, Call Graph, Taint |
| test_ensemble_judge.py | 17 | Perspectives, Voting, Aggregation |
| test_cwe_handlers.py | 29 | All CWE Handlers |
| test_dataset_download.py | 18 | SARD, NVD, Juliet Downloaders |
| (other tests) | ~10 | AST, Static, CWE Server |
| **Total** | **112+** | |

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

---

## Approach Comparison

| Approach | Description | Pros | Cons |
|----------|-------------|------|------|
| **Static-only** | Clang analyzer only | Fast, deterministic | Low recall, misses context |
| **LLM-only** | Direct LLM analysis | Good recall | May hallucinate, no evidence |
| **MCP-based** | Orchestrator + Judge + 6 tools | Evidence-backed, verifiable | Slower, API costs |

---

## Requirements

- Python 3.11+
- clang (for static analysis)
- tree-sitter (for AST parsing)
- Anthropic API key OR local LLM endpoint

---

## Citation

If you use this code in your research, please cite:

```bibtex
@mastersthesis{mcpvul2026,
  title={LLM-Orchestrated Vulnerability Detection using Model Context Protocol},
  author={Le Dang Dung},
  year={2026},
  school={Ho Chi Minh City National University - University Of Information Technology }
}
```

---

## License

MIT - For academic research purposes.
