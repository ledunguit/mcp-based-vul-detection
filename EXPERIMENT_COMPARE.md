# Experiment Comparison Guide

So sánh 4 approaches với 2 models khác nhau.

## Prerequisites

1. **LM Studio** đang chạy tại `http://127.0.0.1:1234`
2. **Dataset** đã được tạo

```bash
# Tạo dataset nếu chưa có
python experiments/prepare_dataset.py --sample-only --output data/juliet_samples/dataset.json
```

---

## Models Configuration

### Model 1: Liquid LFM 2.5 1.2B (Nhỏ, nhanh)

```bash
# .env config
LOCAL_LLM_MODEL=liquid/lfm2.5-1.2b
```

### Model 2: Qwen 2.5 VL 7B (Lớn hơn, chính xác hơn)

```bash
# .env config
LOCAL_LLM_MODEL=qwen/qwen2.5-vl-7b
```

---

## Experiment Steps

### Bước 1: Chạy với Model 1 (liquid/lfm2.5-1.2b)

```bash
# 1.1 Cập nhật .env
echo 'LOCAL_LLM_MODEL=liquid/lfm2.5-1.2b' >> .env

# 1.2 Chạy tất cả approaches
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches static_only llm_only mcp_based mcp_batch \
  --output results/lfm2.5_1.2b/

# 1.3 Phân tích kết quả
python experiments/analyze_results.py \
  --input results/lfm2.5_1.2b/combined_*.json
```

### Bước 2: Chạy với Model 2 (qwen/qwen2.5-vl-7b)

```bash
# 2.1 Cập nhật .env (thay đổi model trong LM Studio hoặc .env)
# Đảm bảo LOCAL_LLM_MODEL=qwen/qwen2.5-vl-7b

# 2.2 Chạy tất cả approaches
python experiments/run_experiment.py \
  --dataset data/juliet_samples/dataset.json \
  --approaches static_only llm_only mcp_based mcp_batch \
  --output results/qwen2.5_vl_7b/

# 2.3 Phân tích kết quả
python experiments/analyze_results.py \
  --input results/qwen2.5_vl_7b/combined_*.json
```

---

## Approaches Comparison

| Approach | LLM Calls | Description |
|----------|-----------|-------------|
| `static_only` | 0 | Clang analyzer only |
| `llm_only` | 1 | Direct LLM analysis, no tools |
| `mcp_based` | 4-10 | Agentic (LLM decides tool calls) |
| `mcp_batch` | 1 | All tools → 1 LLM synthesis |

---

## Expected Results Structure

```
results/
├── lfm2.5_1.2b/
│   ├── static_only_*.json
│   ├── llm_only_*.json
│   ├── mcp_based_*.json
│   ├── mcp_batch_*.json
│   └── combined_*.json
└── qwen2.5_vl_7b/
    ├── static_only_*.json
    ├── llm_only_*.json
    ├── mcp_based_*.json
    ├── mcp_batch_*.json
    └── combined_*.json
```

---

## Key Metrics to Compare

| Metric | Description |
|--------|-------------|
| **Accuracy** | Correct / Total |
| **Precision** | TP / (TP + FP) |
| **Recall** | TP / (TP + FN) |
| **F1 Score** | 2 × (Prec × Rec) / (Prec + Rec) |
| **Avg Time** | Seconds per sample |
| **Confidence** | Model's confidence score |

---

## Quick Comparison Script

```bash
#!/bin/bash
# compare_models.sh

DATASET="data/juliet_samples/dataset.json"
APPROACHES="static_only llm_only mcp_based mcp_batch"

# Model 1: LFM 2.5 1.2B
export LOCAL_LLM_MODEL="liquid/lfm2.5-1.2b"
python experiments/run_experiment.py \
  --dataset $DATASET \
  --approaches $APPROACHES \
  --output results/lfm2.5_1.2b/

# Model 2: Qwen 2.5 VL 7B  
export LOCAL_LLM_MODEL="qwen/qwen2.5-vl-7b"
python experiments/run_experiment.py \
  --dataset $DATASET \
  --approaches $APPROACHES \
  --output results/qwen2.5_vl_7b/

# Compare
echo "=== LFM 2.5 1.2B Results ==="
python experiments/analyze_results.py --input results/lfm2.5_1.2b/combined_*.json

echo "=== Qwen 2.5 VL 7B Results ==="
python experiments/analyze_results.py --input results/qwen2.5_vl_7b/combined_*.json
```

---

## Notes

- **static_only** không cần LLM, kết quả giống nhau cho cả 2 models
- **mcp_based** chậm nhất nhưng linh hoạt nhất
- **mcp_batch** tốc độ/accuracy cân bằng tốt nhất
- Model 7B sẽ chính xác hơn nhưng chậm hơn model 1.2B
