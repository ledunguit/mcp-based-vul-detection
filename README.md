# MCP-Based Vulnerability Detection

An experimental system for LLM-orchestrated vulnerability detection using the Model Context Protocol (MCP).

## Overview

This system demonstrates:
- **LLM-based orchestration** using Model Context Protocol (MCP)
- **Vulnerability detection** for C source code (Buffer Overflow family)
- **Multi-CWE support**: CWE-120, CWE-121, CWE-122, CWE-787, CWE-125
- **Evidence-based reasoning** with tool-grounded conclusions
- **6 MCP Tools**: AST, Static Analysis, CWE Knowledge, Taint Analysis, Pattern Matching, CFG
- **Enhanced metrics**: Hallucination detection, Confidence calibration
- **Comparison with baselines** (LLM-only, static-only)
- **Dual LLM provider support**: Claude API or local OpenAI-compatible endpoints

## Architecture

```
Source Code (C function)
        ↓
Orchestrator Agent (LLM)
        ↓ MCP Tools
┌─────────────────────────────────────────────┐
│            MCP Tool Layer (6 Tools)         │
├─────────────────────────────────────────────┤
│  Core Analysis:                             │
│    - AST Server (tree-sitter)               │
│    - Static Analysis (Clang analyzer)       │
│    - CWE Knowledge (MITRE rules)            │
├─────────────────────────────────────────────┤
│  Advanced Analysis:                         │
│    - Taint Analysis (source → sink flow)    │
│    - Pattern Matching (regex + Semgrep)     │
│    - CFG Analysis (control flow graph)      │
└─────────────────────────────────────────────┘
        ↓
Evidence Aggregation
        ↓
Judge Agent (LLM)
  - Hallucination detection
  - Confidence calibration
  - Evidence validation
        ↓
Final Verdict + Evidence Trail
```

## MCP Tools

| Tool | Description | Output |
|------|-------------|--------|
| **ast_analyze** | Parse C code with tree-sitter | Function structure, variables, risky calls |
| **static_analyze** | Run Clang Static Analyzer | Security warnings, bug reports |
| **cwe_lookup** | Query CWE knowledge base | Safety checks, patterns, mitigations |
| **taint_analyze** | Track data flow from sources to sinks | Taint paths, sanitization status |
| **pattern_analyze** | Match known vulnerability patterns | Pattern matches with severity |
| **cfg_analyze** | Build control flow graph | Nodes, edges, paths to sinks, complexity |

## Supported CWEs

| CWE ID | Name | Description |
|--------|------|-------------|
| CWE-120 | Buffer Copy without Size Check | Classic buffer overflow |
| CWE-121 | Stack-based Buffer Overflow | Overflow on stack memory |
| CWE-122 | Heap-based Buffer Overflow | Overflow on heap memory |
| CWE-787 | Out-of-bounds Write | Write outside allocated bounds |
| CWE-125 | Out-of-bounds Read | Read outside allocated bounds |

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

## Experiments

### Complete Experiment Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        EXPERIMENT WORKFLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                   │
│  │   STEP 1    │     │   STEP 2    │     │   STEP 3    │                   │
│  │   Setup     │ ──▶ │  Dataset    │ ──▶ │    Run      │                   │
│  │Environment  │     │ Preparation │     │ Experiments │                   │
│  └─────────────┘     └─────────────┘     └─────────────┘                   │
│        │                   │                   │                            │
│        ▼                   ▼                   ▼                            │
│  • Install deps      • Download CWE KB   • static_only                     │
│  • Configure .env    • Generate samples  • llm_only                        │
│  • Verify clang      • Or extract Juliet • mcp_based                       │
│                                                                             │
│                      ┌─────────────┐     ┌─────────────┐                   │
│                      │   STEP 4    │     │   STEP 5    │                   │
│                      │  Analyze    │ ──▶ │   Report    │                   │
│                      │  Results    │     │  & Compare  │                   │
│                      └─────────────┘     └─────────────┘                   │
│                            │                   │                            │
│                            ▼                   ▼                            │
│                      • Compute metrics   • Precision/Recall/F1             │
│                      • Confusion matrix  • Per-CWE breakdown               │
│                      • Error analysis    • Approach comparison             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Step 1: Environment Setup

```bash
# 1.1 Create and activate virtual environment
pyenv virtualenv 3.12 mcp-vul
pyenv local mcp-vul

# 1.2 Install dependencies
pip install -e ".[dev]"

# 1.3 Install clang (macOS)
brew install llvm

# 1.4 Configure environment
cp .env.example .env
# Edit .env: set LLM_PROVIDER and API keys

# 1.5 Verify installation
python -c "from src.mcp_servers import ast_analyze_tool; print('OK')"
pytest tests/ -v --tb=short
```

---

### Step 2: Dataset Preparation

**Option A: Hand-crafted Samples (Quick Start)**
```bash
# Generate 30 multi-CWE samples (15 vulnerable, 15 safe)
python experiments/prepare_dataset.py \
  --sample-only \
  --output data/juliet_samples/dataset.json

# Verify dataset
python -c "import json; d=json.load(open('data/juliet_samples/dataset.json')); print(f'Samples: {len(d['samples'])}')"
```

**Option B: Juliet Test Suite (Production)**
```bash
# 2.1 Download Juliet (one-time, ~500MB)
mkdir -p data/juliet_raw && cd data/juliet_raw
curl -L -o juliet.zip "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
unzip -q juliet.zip && cd ../..

# 2.2 Extract balanced dataset (CWE-121: Stack Buffer Overflow)
python experiments/extract_juliet.py \
  --cwe CWE121 \
  --count 100 \
  --output data/juliet_samples/juliet_cwe121.json

# 2.3 Or extract multiple CWEs
python experiments/extract_juliet.py \
  --cwe CWE122 \
  --count 50 \
  --output data/juliet_samples/juliet_cwe122.json
```

**Option C: Download MITRE CWE Knowledge (Optional)**
```bash
# Download official CWE database
mkdir -p data/cwe_mitre && cd data/cwe_mitre
curl -L -o cwec_latest.xml.zip "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
unzip -o cwec_latest.xml.zip && cd ../..

# Parse buffer overflow CWEs
python experiments/parse_cwe_xml.py \
  --input data/cwe_mitre/cwec_v4.19.xml \
  --output data/cwe_knowledge_mitre.json
```

---

### Step 3: Run Experiments

**3.1 Run All Approaches (Recommended)**
```bash
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches static_only llm_only mcp_based \
  --output results/
```

**3.2 Run Single Approach**
```bash
# Static analysis only (fastest, no LLM)
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches static_only \
  --output results/

# LLM only (requires API)
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches llm_only \
  --output results/

# MCP-based (full pipeline)
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches mcp_based \
  --output results/
```

**3.3 With Local LLM (LM Studio, Ollama, etc.)**
```bash
# Start local LLM server first (e.g., LM Studio on port 1234)
LLM_PROVIDER=local \
LOCAL_LLM_BASE_URL=http://127.0.0.1:1234/v1 \
LOCAL_LLM_MODEL=qwen2.5-coder-32b \
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches mcp_based \
  --output results/
```

**3.4 Limit Samples (for Testing)**
```bash
# Run on first 10 samples only
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches mcp_based \
  --limit 10 \
  --output results/
```

---

### Step 4: Analyze Results

```bash
# Analyze combined results
python experiments/analyze_results.py \
  --input results/combined_*.json

# Analyze specific result file
python experiments/analyze_results.py \
  --input results/mcp_based_20260119_120000.json
```

**Output Metrics:**
| Metric | Description |
|--------|-------------|
| Precision | TP / (TP + FP) - How many detected vulns are real |
| Recall | TP / (TP + FN) - How many real vulns are detected |
| F1 Score | Harmonic mean of Precision and Recall |
| Accuracy | (TP + TN) / Total |
| Hallucination Rate | % of claims not supported by evidence |
| Confidence Calibration | Expected Calibration Error (ECE) |

---

### Step 5: Compare Approaches

**Expected Output:**
```
======================================================================
COMPARISON SUMMARY
======================================================================
-----------+-------------+----------+-----------
   Metric  | Static-only | LLM-only | MCP-based 
-----------+-------------+----------+-----------
 Precision |    0.XX     |   0.XX   |   0.XX    
   Recall  |    0.XX     |   0.XX   |   0.XX    
  F1 Score |    0.XX     |   0.XX   |   0.XX    
  Accuracy |    0.XX     |   0.XX   |   0.XX    
-----------+-------------+----------+-----------

Per-CWE Breakdown:
  CWE-120: Precision=X.XX, Recall=X.XX, F1=X.XX
  CWE-121: Precision=X.XX, Recall=X.XX, F1=X.XX
  CWE-122: Precision=X.XX, Recall=X.XX, F1=X.XX

Confusion Matrix (mcp_based):
                Predicted
                VULN    SAFE
Actual  VULN      TP      FN
        SAFE      FP      TN
```

---

### Quick Commands Reference

```bash
# Full experiment (all steps)
python experiments/prepare_dataset.py --sample-only --output data/juliet_samples/dataset.json && \
python experiments/run_experiment.py --dataset data/juliet_samples/dataset.json --approaches static_only llm_only mcp_based --output results/ && \
python experiments/analyze_results.py --input results/combined_*.json

# Quick test (10 samples, MCP only)
python experiments/run_experiment.py --dataset data/juliet_samples/dataset.json --approaches mcp_based --limit 10 --output results/

# Local LLM full run
LLM_PROVIDER=local python experiments/run_experiment.py --dataset data/juliet_samples/dataset.json --approaches mcp_based --output results/
```

## Project Structure

```
MCP-Vul/
├── src/
│   ├── config.py                 # Configuration (API keys, LLM provider)
│   ├── schemas.py                # Pydantic data models
│   ├── llm_client.py             # Unified LLM client (Claude + Local)
│   ├── pipeline.py               # Main analysis pipeline
│   ├── mcp_servers/              # MCP tool servers
│   │   ├── ast_server.py         # Tree-sitter C parser
│   │   ├── static_analysis_server.py  # Clang analyzer
│   │   ├── cwe_knowledge_server.py    # CWE knowledge base (multi-CWE)
│   │   ├── taint_server.py       # Taint analysis (source → sink)
│   │   ├── pattern_server.py     # Pattern matching (12+ patterns)
│   │   └── cfg_server.py         # Control flow graph analysis
│   ├── agents/                   # LLM agents
│   │   ├── orchestrator.py       # Tool orchestration (few-shot, confidence)
│   │   └── judge.py              # Evidence validation (hallucination check)
│   └── baselines/                # Comparison baselines
│       ├── static_only.py
│       └── llm_only.py
├── experiments/
│   ├── prepare_dataset.py        # Sample dataset generator (30 samples)
│   ├── extract_juliet.py         # Juliet dataset extractor (multi-CWE)
│   ├── run_experiment.py         # Experiment runner
│   └── analyze_results.py        # Enhanced metrics calculator
├── data/
│   ├── cwe_knowledge.json        # CWE knowledge base
│   ├── cwe_knowledge_mitre.json  # MITRE CWE data
│   └── juliet_samples/           # Test datasets
├── results/                      # Experiment outputs
└── tests/                        # Unit tests (38 tests)
```

## Approach Comparison

| Approach | Description | Pros | Cons |
|----------|-------------|------|------|
| **Static-only** | Clang analyzer only | Fast, deterministic | Misses context, low recall |
| **LLM-only** | Direct LLM analysis | Good recall | No evidence trail, may hallucinate |
| **MCP-based** | Orchestrator + Judge with 6 tools | Evidence-backed, verifiable, multi-tool | Slower, API costs |

## Enhanced Features

### Few-shot Examples
The Orchestrator uses few-shot examples for:
- VULNERABLE detection with evidence
- SAFE code verification
- NOT_ENOUGH_EVIDENCE handling

### Confidence Scoring
```
0.9-1.0: Very high - Multiple tools confirm
0.7-0.9: High - Strong evidence from 2+ tools
0.5-0.7: Medium - Single tool or weak evidence
0.3-0.5: Low - Indirect evidence only
0.0-0.3: Very low - Speculation
```

### Hallucination Detection
Judge validates:
- Claims match tool outputs
- No fabricated evidence
- Confidence calibration

## Key Files

- **Orchestrator Prompt**: `src/agents/orchestrator.py`
- **Judge Criteria**: `src/agents/judge.py`
- **CWE Knowledge**: `src/mcp_servers/cwe_knowledge_server.py`
- **Risky Functions**: `src/config.py` (RISKY_FUNCTIONS)
- **Taint Rules**: `src/mcp_servers/taint_server.py`
- **Vulnerability Patterns**: `src/mcp_servers/pattern_server.py`

## Requirements

- Python 3.11+
- clang (for static analysis)
- Anthropic API key OR local LLM endpoint

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_new_servers.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

## License

MIT - For academic research purposes.
