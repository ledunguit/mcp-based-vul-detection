# PIPELINE.md

This guide explains how to extract vulnerability samples from the Juliet Test Suite and run the MCP-Vul analysis pipeline.

---

## Quick Start

```bash
# Option A: Analyze a single C file
python -m src.pipeline path/to/code.c -v

# Option B: Extract samples and run experiments
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --cwe CWE121 CWE122 \
  --count 100 \
  --output data/juliet_samples/dataset.json

python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches mcp_based \
  --limit 10
```

---

## Prerequisites

### 1. Install Dependencies

```bash
pip install -e ".[dev]"
```

### 2. Install Clang (required for static analysis)

```bash
# macOS
brew install llvm

# Ubuntu/Debian
sudo apt-get install clang clang-tools

# Verify installation
clang --version
```

### 3. Configure LLM Provider

Copy `.env.example` to `.env` and set:

```bash
# For Claude API
LLM_PROVIDER=claude
ANTHROPIC_API_KEY=your_key_here

# Or for local LLM
LLM_PROVIDER=local
LOCAL_LLM_BASE_URL=http://localhost:8000/v1
LOCAL_LLM_MODEL=your_model_name
```

### 4. Download Juliet Test Suite (Optional)

```bash
# Download from NIST
# https://samate.nist.gov/SARD/test-suites/112

# Extract to:
# data/juliet_raw/C/testcases/
```

---

## Extracting Juliet Samples

### Command: `experiments/extract_juliet.py`

Extracts vulnerable and safe code samples from Juliet Test Suite into a JSON dataset.

### Basic Usage

```bash
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --cwe CWE121 CWE122 \
  --count 100 \
  --output data/juliet_samples/dataset.json
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--juliet-path` | Path to Juliet testcases directory | Required |
| `--cwe` | Space-separated CWE IDs (e.g., `CWE121 CWE122`) | All supported |
| `--count` | Maximum samples per CWE | 100 |
| `--output` | Output JSON file path | `data/juliet_samples/dataset.json` |
| `--extended-samples` | Use hand-crafted samples (no Juliet required) | False |

### Examples

```bash
# Extract buffer overflow samples
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --cwe CWE121 CWE122 CWE124 CWE126 CWE127 \
  --count 200 \
  --output data/juliet_samples/buffer_overflow.json

# Extract command injection samples
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --cwe CWE78 \
  --count 100 \
  --output data/juliet_samples/command_injection.json

# Use hand-crafted samples (no Juliet download required)
python experiments/extract_juliet.py \
  --extended-samples \
  --output data/juliet_samples/extended_samples.json
```

### Available CWEs in C Juliet

| CWE ID | Name | Juliet Directory | Coverage |
|--------|------|------------------|----------|
| 121 | Stack-based Buffer Overflow | `CWE121_*` | Excellent |
| 122 | Heap-based Buffer Overflow | `CWE122_*` | Excellent |
| 124 | Buffer Underwrite | `CWE124_*` | Good |
| 126 | Buffer Over-read | `CWE126_*` | Good |
| 127 | Buffer Under-read | `CWE127_*` | Good |
| 78 | OS Command Injection | `CWE78_*` | Good |
| 23 | Relative Path Traversal | `CWE23_*` | Moderate |

**Note:** Web vulnerabilities (CWE-89 SQL Injection, CWE-79 XSS) are not available in C Juliet - they exist in Java/PHP versions.

### Output Format

The extracted dataset JSON:

```json
{
  "metadata": {
    "source": "Juliet Test Suite 1.3",
    "cwe_types": ["CWE-121", "CWE-122"],
    "total_samples": 100,
    "vulnerable_count": 50,
    "safe_count": 50,
    "per_cwe_stats": {
      "CWE-121": {"vulnerable": 25, "safe": 25},
      "CWE-122": {"vulnerable": 25, "safe": 25}
    }
  },
  "samples": [
    {
      "id": "juliet_CWE121_0001",
      "source_code": "void bad_func(char *input) {\n    char buf[32];\n    strcpy(buf, input);\n}",
      "function_name": "bad_func",
      "is_vulnerable": true,
      "file_origin": "CWE121_Stack_Based_Buffer_Overflow__char_01.c",
      "cwe_id": "CWE-121",
      "sink_functions": ["strcpy"]
    }
  ]
}
```

---

## Running the Analysis Pipeline

### Option 1: Single File Analysis

Analyze a single C file directly:

```bash
# Basic usage
python -m src.pipeline path/to/code.c

# With verbose output
python -m src.pipeline path/to/code.c -v

# Analyze a Juliet sample directly
python -m src.pipeline \
  "data/juliet_raw/C/testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c" \
  -v
```

### Option 2: Dataset Experiments

Run experiments on a dataset with multiple approaches:

```bash
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches mcp_based \
  --output results/
```

### Experiment Options

| Option | Description | Default |
|--------|-------------|---------|
| `--dataset` | Path to dataset JSON | Required |
| `--approaches` | Analysis approaches to use | All |
| `--output` | Output directory for results | `results/` |
| `--limit` | Max samples to analyze (for testing) | All |
| `--verbose` | Enable detailed output | False |
| `--ablation` | Run ablation study | False |

### Available Approaches

| Approach | Description | Speed | Accuracy |
|----------|-------------|-------|----------|
| `static_only` | Clang Static Analyzer only | Fast | Baseline |
| `llm_only` | Direct LLM analysis (no tools) | Medium | Moderate |
| `mcp_based` | Full MCP orchestration (agentic) | Slow | Best |
| `mcp_batch` | MCP with parallel batch mode | Medium | Best |

### Examples

```bash
# Quick test with 10 samples
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches mcp_based \
  --limit 10 \
  --verbose

# Compare all approaches
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches static_only llm_only mcp_based mcp_batch \
  --output results/comparison/

# Run batch mode (faster, 7x speedup)
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches mcp_batch \
  --output results/batch/

# Ablation study
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --ablation \
  --output results/ablation/
```

---

## Analyzing Results

### Command: `experiments/analyze_results.py`

```bash
python experiments/analyze_results.py --input results/combined_*.json
```

### Output Metrics

| Metric | Description |
|--------|-------------|
| **Accuracy** | Overall correct predictions |
| **Precision** | True positives / Predicted positives |
| **Recall** | True positives / Actual positives |
| **F1 Score** | Harmonic mean of precision and recall |
| **False Positive Rate** | Safe samples incorrectly flagged |
| **False Negative Rate** | Vulnerable samples missed |

### Example Output

```
=== Experiment Results ===

Approach: mcp_based
  Samples: 100
  Accuracy: 0.85
  Precision: 0.88
  Recall: 0.82
  F1 Score: 0.85

Approach: static_only
  Samples: 100
  Accuracy: 0.72
  Precision: 0.75
  Recall: 0.68
  F1 Score: 0.71

Approach: llm_only
  Samples: 100
  Accuracy: 0.78
  Precision: 0.80
  Recall: 0.76
  F1 Score: 0.78
```

---

## Complete Workflows

### Workflow 1: Quick Testing (No Juliet Required)

```bash
# Use hand-crafted samples
python experiments/extract_juliet.py \
  --extended-samples \
  --output data/juliet_samples/test.json

# Run quick experiment
python experiments/run_experiment.py \
  --dataset data/juliet_samples/test.json \
  --approaches mcp_based \
  --limit 5 \
  --verbose
```

### Workflow 2: Buffer Overflow Analysis

```bash
# 1. Extract buffer overflow samples
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --cwe CWE121 CWE122 CWE124 CWE126 CWE127 \
  --count 200 \
  --output data/juliet_samples/buffer_overflow.json

# 2. Run MCP-based analysis
python experiments/run_experiment.py \
  --dataset data/juliet_samples/buffer_overflow.json \
  --approaches mcp_based mcp_batch \
  --output results/buffer_overflow/

# 3. Analyze results
python experiments/analyze_results.py \
  --input results/buffer_overflow/combined_*.json
```

### Workflow 3: Approach Comparison Study

```bash
# 1. Extract balanced dataset
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --cwe CWE121 CWE122 CWE78 \
  --count 100 \
  --output data/juliet_samples/comparison.json

# 2. Run all approaches
python experiments/run_experiment.py \
  --dataset data/juliet_samples/comparison.json \
  --approaches static_only llm_only mcp_based mcp_batch \
  --output results/comparison/

# 3. Generate comparison report
python experiments/analyze_results.py \
  --input results/comparison/combined_*.json
```

### Workflow 4: Single Sample Deep Analysis

```bash
# Analyze with maximum verbosity
python -m src.pipeline \
  "data/juliet_raw/C/testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memcpy_01.c" \
  -v

# Or analyze inline code
echo 'void bad(char *in) { char buf[32]; strcpy(buf, in); }' > /tmp/test.c
python -m src.pipeline /tmp/test.c -v
```

---

## Understanding Pipeline Output

### Single File Analysis Output

```
=== MCP-Vul Analysis ===

Source: path/to/code.c
Function: bad_strcpy

=== Tool Execution ===
[ast_analyze] Completed in 0.12s
  - Found 3 local variables
  - Found 2 risky sinks: strcpy, memcpy

[taint_analyze] Completed in 0.08s
  - Sources: input (parameter)
  - Sinks reached: strcpy (line 5)
  - Validation: None found

[static_analyze] Completed in 1.23s
  - Warnings: 1 (potential buffer overflow)

=== Orchestrator Hypothesis ===
Verdict: VULNERABLE
Confidence: 0.92
Reasoning: strcpy at line 5 receives unbounded input...

=== Judge Validation ===
Verdict: VULNERABLE
Confidence: 0.88
Evidence Quality: strong

=== Final Result ===
VULNERABLE (confidence: 0.90)
```

### Verdict Meanings

| Verdict | Meaning |
|---------|---------|
| `VULNERABLE` | Code contains exploitable vulnerability |
| `SAFE` | Code has proper bounds checking |
| `NOT_ENOUGH_EVIDENCE` | Cannot determine from available evidence |

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `Juliet directory not found` | Check `--juliet-path` points to `testcases/` |
| `0 samples extracted` | Verify CWE directory exists (use `CWE121` not `CWE-121`) |
| `Clang not found` | Install LLVM: `brew install llvm` |
| `API key error` | Check `.env` file has valid `ANTHROPIC_API_KEY` |
| `Timeout errors` | Reduce `--limit` or use `mcp_batch` approach |

### Verify Juliet Structure

```bash
# Check Juliet is correctly extracted
ls data/juliet_raw/C/testcases/

# Expected output:
# CWE121_Stack_Based_Buffer_Overflow/
# CWE122_Heap_Based_Buffer_Overflow/
# CWE124_Buffer_Underwrite/
# ...
```

### Debug Mode

```bash
# Enable maximum verbosity
python -m src.pipeline code.c -v 2>&1 | tee debug.log

# Check tool outputs
python -c "
from src.mcp_servers.ast_server import analyze_ast
result = analyze_ast(open('code.c').read())
import json
print(json.dumps(result, indent=2))
"
```

---

## Performance Tips

| Tip | Description |
|-----|-------------|
| Use `mcp_batch` | 7x faster than `mcp_based` via parallel execution |
| Limit samples | Use `--limit 10` for testing before full runs |
| Local LLM | Faster iteration with local models |
| SSD storage | Juliet extraction is I/O bound |
| Batch experiments | Run overnight for large datasets |

---

## Directory Structure

```
MCP-Vul/
├── data/
│   ├── juliet_raw/              # Raw Juliet Test Suite
│   │   └── C/testcases/
│   │       ├── CWE121_*/
│   │       ├── CWE122_*/
│   │       └── ...
│   └── juliet_samples/          # Extracted datasets
│       ├── dataset.json
│       └── buffer_overflow.json
│
├── experiments/
│   ├── extract_juliet.py        # Sample extraction
│   ├── run_experiment.py        # Experiment runner
│   └── analyze_results.py       # Results analyzer
│
├── results/                     # Experiment outputs
│   ├── combined_*.json
│   └── metrics_*.json
│
└── src/
    ├── pipeline.py              # Single file analysis
    └── ...
```

---

## Next Steps

1. **Start with hand-crafted samples** to verify setup works
2. **Download Juliet** for comprehensive testing
3. **Run comparison study** to validate approach effectiveness
4. **Analyze results** to identify improvement areas

See [DATASET.md](DATASET.md) for more details on dataset formats and sources.
