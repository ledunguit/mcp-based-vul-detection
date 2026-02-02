# DATASET.md

This guide explains how to download, prepare, and use datasets for the MCP-Vul vulnerability detection system.

## Supported Datasets

| Dataset | Description | Source |
|---------|-------------|--------|
| **Juliet Test Suite** | NIST's comprehensive C/C++ vulnerability test cases | Local extraction |
| **SARD** | Software Assurance Reference Dataset | Manual download |
| **NVD** | National Vulnerability Database CVE entries | API fetch |

## Supported CWEs

| CWE ID | Name | Category |
|--------|------|----------|
| 120 | Buffer Copy without Size Check | Memory Safety |
| 121 | Stack-based Buffer Overflow | Memory Safety |
| 122 | Heap-based Buffer Overflow | Memory Safety |
| 125 | Out-of-bounds Read | Memory Safety |
| 787 | Out-of-bounds Write | Memory Safety |
| 89 | SQL Injection | Injection |
| 78 | OS Command Injection | Injection |
| 79 | Cross-site Scripting (XSS) | Injection |
| 22 | Path Traversal | Traversal |

---

## Quick Start

### Option A: Hand-crafted Samples (No Download Required)

```bash
# Create sample dataset with built-in examples
python experiments/prepare_dataset.py --sample-only --output data/juliet_samples/dataset.json

# Run experiment
python experiments/run_experiment.py --dataset data/juliet_samples/dataset.json --limit 10
```

### Option B: Full Juliet Pipeline

```bash
# 1. Download Juliet Test Suite from NIST
# https://samate.nist.gov/SARD/test-suites/112

# 2. Extract to data/juliet_raw/C/testcases/

# 3. Prepare dataset
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --cwe CWE120 CWE121 CWE122 \
  --count 200 \
  --output data/juliet_samples/dataset.json

# 4. Run experiments
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches static_only llm_only mcp_based
```

---

## Downloading Datasets

### Command: `experiments/download_datasets.py`

```bash
# Download all datasets for multiple CWEs
python experiments/download_datasets.py --dataset all --cwe 120,89,78,79,22

# Download only NVD CVEs
python experiments/download_datasets.py --dataset nvd --cwe 89 --limit 100

# Download with NVD API key (higher rate limit)
python experiments/download_datasets.py --dataset nvd --nvd-api-key YOUR_KEY

# Specify custom output directory
python experiments/download_datasets.py --dataset all --output my_datasets/
```

### Options

| Option | Description |
|--------|-------------|
| `--dataset` | Dataset to download: `all`, `sard`, `nvd`, `juliet` |
| `--cwe` | Comma-separated CWE IDs (e.g., `120,89,78`) |
| `--output` | Output directory (default: `experiments/datasets/`) |
| `--limit` | Maximum samples per CWE |
| `--nvd-api-key` | NVD API key for higher rate limits |

### Output Structure

```
experiments/datasets/
├── sard/
│   └── CWE120/
│       └── samples/
├── nvd/
│   └── CWE89/
│       └── cves.json
└── juliet/
    └── CWE121/
        └── manifest.json
```

---

## Preparing Datasets

### Command: `experiments/prepare_dataset.py`

```bash
# From Juliet Test Suite
python experiments/prepare_dataset.py \
  --juliet-path data/juliet_raw/C/testcases \
  --output data/juliet_samples/dataset.json \
  --max-samples 100

# Hand-crafted samples only (no Juliet required)
python experiments/prepare_dataset.py \
  --sample-only \
  --output data/juliet_samples/dataset.json
```

### Command: `experiments/extract_juliet.py`

Advanced multi-CWE extraction with more options:

```bash
# Extract specific CWEs
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --output data/juliet_samples/juliet_cwe121.json \
  --cwe CWE121 CWE122 \
  --count 200

# Create extended sample dataset (no Juliet required)
python experiments/extract_juliet.py \
  --extended-samples \
  --output data/juliet_samples/extended_samples.json
```

---

## Dataset JSON Format

### Minimum Required Schema

```json
{
  "metadata": {
    "source": "Juliet Test Suite",
    "total_samples": 100,
    "vulnerable_count": 50,
    "safe_count": 50
  },
  "samples": [
    {
      "id": "unique_identifier",
      "source_code": "void bad_strcpy(char *input) { char buf[32]; strcpy(buf, input); }",
      "function_name": "bad_strcpy",
      "is_vulnerable": true,
      "file_origin": "CWE120_Buffer_Copy__char_01.c"
    }
  ]
}
```

### Enhanced Schema (with CWE info)

```json
{
  "metadata": {
    "source": "Juliet Test Suite 1.3",
    "cwe_types": ["CWE-120", "CWE-121", "CWE-122"],
    "total_samples": 200,
    "vulnerable_count": 100,
    "safe_count": 100,
    "per_cwe_stats": {
      "CWE-120": {"vulnerable": 40, "safe": 35},
      "CWE-121": {"vulnerable": 35, "safe": 40},
      "CWE-122": {"vulnerable": 25, "safe": 25}
    }
  },
  "samples": [
    {
      "id": "juliet_CWE120_0001",
      "source_code": "void bad_strcpy(char *input) { ... }",
      "function_name": "bad_strcpy",
      "is_vulnerable": true,
      "file_origin": "CWE120_Buffer_Copy__char_01.c",
      "cwe_id": "CWE-120",
      "sink_functions": ["strcpy", "memcpy"]
    }
  ]
}
```

### Field Descriptions

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique sample identifier |
| `source_code` | Yes | Complete C function code |
| `function_name` | Yes | Name of the function |
| `is_vulnerable` | Yes | Ground truth: `true` = vulnerable, `false` = safe |
| `file_origin` | Yes | Source file path |
| `cwe_id` | No | CWE identifier (e.g., "CWE-120") |
| `sink_functions` | No | List of dangerous function calls detected |

---

## Running Experiments with Datasets

### Command: `experiments/run_experiment.py`

```bash
# Run all approaches
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches static_only llm_only mcp_based \
  --output results/

# Run with sample limit (for testing)
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --limit 10 \
  --verbose

# Run ablation study
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --ablation
```

### Available Approaches

| Approach | Description |
|----------|-------------|
| `static_only` | Clang Static Analyzer only |
| `llm_only` | Direct LLM analysis (no tools) |
| `mcp_based` | Full MCP orchestration (agentic) |
| `mcp_batch` | MCP with parallel batch mode |

### Analyze Results

```bash
python experiments/analyze_results.py --input results/combined_*.json
```

---

## Directory Structure

```
data/
├── cwe_knowledge.json              # CWE knowledge base
├── cwe_knowledge_mitre.json        # Extended MITRE CWE data
├── juliet_raw/                     # Raw Juliet Test Suite (download)
│   └── C/testcases/
│       ├── CWE120_Buffer_Copy/
│       ├── CWE121_Stack_Based/
│       └── ...
└── juliet_samples/                 # Prepared datasets
    ├── dataset.json                # Main dataset
    └── extended_samples.json       # Hand-crafted samples

experiments/
├── datasets/                       # Downloaded datasets
│   ├── sard/
│   ├── nvd/
│   └── juliet/
├── download_datasets.py            # Dataset downloader
├── prepare_dataset.py              # Dataset preparer
├── extract_juliet.py               # Juliet extractor
├── run_experiment.py               # Experiment runner
└── analyze_results.py              # Results analyzer

results/                            # Experiment outputs
├── combined_*.json
└── metrics_*.json
```

---

## Workflow Examples

### Workflow 1: Quick Testing

```bash
# Create hand-crafted samples (no download)
python experiments/prepare_dataset.py --sample-only

# Run quick test
python experiments/run_experiment.py --limit 10
```

### Workflow 2: Buffer Overflow Analysis

```bash
# Extract buffer overflow samples
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --cwe CWE120 CWE121 CWE122 CWE125 CWE787 \
  --count 500 \
  --output data/juliet_samples/buffer_overflow.json

# Run experiment
python experiments/run_experiment.py \
  --dataset data/juliet_samples/buffer_overflow.json \
  --approaches mcp_based mcp_batch
```

### Workflow 3: Multi-CWE Comparison

```bash
# Download multiple CWE types
python experiments/download_datasets.py \
  --dataset all \
  --cwe 120,89,78,79,22 \
  --output experiments/datasets/

# Prepare combined dataset
python experiments/extract_juliet.py \
  --juliet-path data/juliet_raw/C/testcases \
  --cwe CWE120 CWE89 CWE78 \
  --count 100 \
  --output data/juliet_samples/multi_cwe.json

# Run comparison
python experiments/run_experiment.py \
  --dataset data/juliet_samples/multi_cwe.json \
  --approaches static_only llm_only mcp_based
```

---

## Creating Custom Datasets

To create a custom dataset, create a JSON file following this format:

```json
{
  "metadata": {
    "source": "Custom Dataset",
    "total_samples": 2,
    "vulnerable_count": 1,
    "safe_count": 1
  },
  "samples": [
    {
      "id": "custom_vuln_001",
      "source_code": "void vulnerable(char *input) {\n    char buffer[32];\n    strcpy(buffer, input);\n}",
      "function_name": "vulnerable",
      "is_vulnerable": true,
      "file_origin": "custom",
      "cwe_id": "CWE-120"
    },
    {
      "id": "custom_safe_001",
      "source_code": "void safe(char *input) {\n    char buffer[32];\n    strncpy(buffer, input, sizeof(buffer)-1);\n    buffer[31] = '\\0';\n}",
      "function_name": "safe",
      "is_vulnerable": false,
      "file_origin": "custom",
      "cwe_id": "CWE-120"
    }
  ]
}
```

Then run:

```bash
python experiments/run_experiment.py --dataset path/to/custom_dataset.json
```

---

## Detected Sink Functions

The system automatically detects these dangerous sink functions:

| Category | Functions |
|----------|-----------|
| **Memory** | `memcpy`, `memmove`, `memset` |
| **String** | `strcpy`, `strncpy`, `strcat`, `strncat` |
| **Format** | `sprintf`, `snprintf`, `vsprintf`, `vsnprintf` |
| **Input** | `gets`, `fgets`, `scanf`, `sscanf`, `fscanf` |
| **I/O** | `read`, `recv`, `recvfrom` |
| **Wide String** | `wcscpy`, `wcsncpy`, `wcscat`, `wcsncat` |

---

## Tips

1. **Balanced Datasets**: The extractors automatically balance vulnerable/safe samples 50/50
2. **CWE Focus**: Use `--cwe` to focus on specific vulnerability types
3. **Sample Limits**: Use `--limit` or `--count` to control dataset size
4. **Quick Testing**: Use `--sample-only` for testing without downloading Juliet
5. **Verbose Mode**: Add `--verbose` or `-v` for detailed output
