# MCP-Based Vulnerability Detection MVP

An experimental system for LLM-orchestrated vulnerability detection using the Model Context Protocol (MCP).

## Overview

This system demonstrates:
- **LLM-based orchestration** using Model Context Protocol (MCP)
- **Vulnerability detection** for C source code (CWE-120/121: Buffer Overflow)
- **Evidence-based reasoning** with tool-grounded conclusions
- **Comparison with baselines** (LLM-only, static-only)
- **Dual LLM provider support**: Claude API or local OpenAI-compatible endpoints

## Architecture

```
Source Code (C function)
        ↓
Orchestrator Agent (LLM)
        ↓ MCP Tools
┌──────────────────────────────┐
│        MCP Tool Layer        │
│  - AST Server (tree-sitter)  │
│  - Static Analysis (clang)   │
│  - CWE Knowledge (rules)     │
└──────────────────────────────┘
        ↓
Evidence Aggregation
        ↓
Judge Agent (LLM)
        ↓
Final Verdict + Evidence Trail
```

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

### Prepare Dataset

**Option A: Sample dataset (10 functions)**
```bash
python experiments/prepare_dataset.py --sample-only --output data/juliet_samples/dataset.json
```

**Option B: Juliet Test Suite (real-world)**
```bash
# Download Juliet (first time only)
mkdir -p data/juliet_raw && cd data/juliet_raw
curl -L -o juliet.zip "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
unzip -q juliet.zip && cd ../..

# Extract CWE-121 samples (100 balanced)
python experiments/extract_juliet.py --count 100 --output data/juliet_samples/juliet_cwe121.json
```

### Run Experiments

```bash
# Run all approaches
python experiments/run_experiment.py \
  --dataset data/juliet_samples/juliet_cwe121.json \
  --approaches static_only llm_only mcp_based \
  --output results/

# Run single approach
python experiments/run_experiment.py --approaches mcp_based --output results/

# With local LLM
LLM_PROVIDER=local python experiments/run_experiment.py --approaches mcp_based --output results/
```

### Analyze Results

```bash
python experiments/analyze_results.py --input results/combined_*.json
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
│   │   └── cwe_knowledge_server.py    # CWE-120 rules
│   ├── agents/                   # LLM agents
│   │   ├── orchestrator.py       # Tool orchestration
│   │   └── judge.py              # Evidence validation
│   └── baselines/                # Comparison baselines
│       ├── static_only.py
│       └── llm_only.py
├── experiments/
│   ├── prepare_dataset.py        # Sample dataset generator
│   ├── extract_juliet.py         # Juliet dataset extractor
│   ├── run_experiment.py         # Experiment runner
│   └── analyze_results.py        # Metrics calculator
├── data/
│   ├── cwe_knowledge.json        # CWE-120 knowledge base
│   └── juliet_samples/           # Test datasets
├── results/                      # Experiment outputs
└── tests/                        # Unit tests
```

## Approach Comparison

| Approach | Description | Pros | Cons |
|----------|-------------|------|------|
| **Static-only** | Clang analyzer only | Fast, deterministic | Misses context, low recall |
| **LLM-only** | Direct LLM analysis | Good recall | No evidence trail, may hallucinate |
| **MCP-based** | Orchestrator + Judge with tools | Evidence-backed, verifiable | Slower, API costs |

## Example Results

```
Approach     | Precision | Recall | F1
-------------|-----------|--------|-----
Static-only  |    N/A    |   0%   | 0.00
LLM-only     |   100%    |  100%  | 1.00
MCP-based    |   100%    |  100%  | 1.00
```

*Note: MCP-based provides full evidence trail for each verdict*

## Key Files

- **Orchestrator System Prompt**: `src/agents/orchestrator.py`
- **Judge Decision Criteria**: `src/agents/judge.py`
- **CWE-120 Knowledge Base**: `data/cwe_knowledge.json`
- **Risky Sink Functions**: `src/config.py` (RISKY_FUNCTIONS)

## Requirements

- Python 3.11+
- clang (for static analysis)
- Anthropic API key OR local LLM endpoint

## License

MIT - For academic research purposes.
