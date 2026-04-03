---
title: Benchmarks
nav_order: 7
---

# Benchmarks

AIProxyGuard detection accuracy is measured using [PIBench](https://github.com/AInvirion/prompt-injection-benchmark), an open-source prompt injection benchmark tool.

## Current Performance (v0.2.42)

| Metric | Value |
|--------|-------|
| **Balanced Score** | 75.81% |
| True Positive Rate | 53.65% |
| True Negative Rate | 97.97% |
| Precision | 96.45% |
| F1 Score | 68.95% |
| Avg Latency | 91.3 ms |

### Detection by Category

| Category | Detection Rate | Details |
|----------|----------------|---------|
| Jailbreak | **74.9%** | DAN mode, persona exploits, restriction bypass |
| Prompt Injection | 32.7% | Instruction override, context manipulation |
| False Positives | 2.0% | Benign prompts incorrectly blocked |

## Benchmark Dataset

We use a canonical baseline dataset for reproducible comparisons:

| Dataset | Version | Samples | Jailbreaks | Injections | Benign |
|---------|---------|---------|------------|------------|--------|
| baseline_v2 | Current | 1,834 | 441 | 470 | 917 |
| baseline_v1 | Legacy | 1,016 | 97 | 411 | 508 |

### Data Sources

| Source | Samples | Type | License |
|--------|---------|------|---------|
| [JailbreakHub](https://huggingface.co/datasets/walledai/JailbreakHub) | 15,140 | Jailbreaks | CC-BY-4.0 |
| [deepset](https://huggingface.co/datasets/deepset/prompt-injections) | 662 | Mixed | Apache-2.0 |
| [jackhhao](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | 1,310 | Mixed | Apache-2.0 |
| [xTRam1](https://huggingface.co/datasets/xTRam1/safe-guard-prompt-injection) | 10,296 | Mixed | Apache-2.0 |
| [yanismiraoui](https://huggingface.co/datasets/yanismiraoui/prompt_injections) | 1,034 | Multilingual | Apache-2.0 |
| [Gandalf](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | 1,000 | Injections | MIT |
| [PALLMs](https://github.com/mik0w/pallms) | ~135 | Jailbreaks | MIT |
| [UltraChat](https://huggingface.co/datasets/HuggingFaceH4/ultrachat_200k) | 515k | Benign | MIT |

## Running Benchmarks

### Install PIBench

```bash
git clone https://github.com/AInvirion/prompt-injection-benchmark.git
cd prompt-injection-benchmark
uv venv && source .venv/bin/activate
uv pip install -e .
```

### Run Against Your Deployment

```bash
# Using canonical baseline (recommended for comparisons)
pibench run https://your-proxy.app -d data/baseline_v2.jsonl

# Quick test with limited samples
pibench run https://your-proxy.app --max-samples 100

# Save results
pibench run https://your-proxy.app -d data/baseline_v2.jsonl -o results.json
```

### Run Against Local Instance

```bash
# Start AIProxyGuard locally
docker run -d -p 8080:8080 ovalenzuela/aiproxyguard:latest

# Run benchmark
pibench run http://localhost:8080 -d data/baseline_v2.jsonl
```

## Scoring Methodology

PIBench uses **Balanced Accuracy** to prevent gaming:

```
Balanced Score = (True Positive Rate + True Negative Rate) / 2
```

This prevents:
- Blocking everything (high TPR, 0% TNR) = ~50%
- Allowing everything (0% TPR, high TNR) = ~50%

### Metrics Explained

| Metric | Formula | Description |
|--------|---------|-------------|
| True Positive Rate (Recall) | TP / (TP + FN) | % of attacks detected |
| True Negative Rate | TN / (TN + FP) | % of benign prompts allowed |
| Precision | TP / (TP + FP) | % of detections that were correct |
| F1 Score | 2 * (P * R) / (P + R) | Harmonic mean of precision and recall |

## Tuning for Your Use Case

### High Security (Catch More Attacks)

Lower thresholds catch more attacks but increase false positives:

```yaml
policy:
  categories:
    prompt_injection:
      threshold: 0.3  # Very aggressive
    jailbreak:
      threshold: 0.3
```

Expected impact:
- True Positive Rate: +15-20%
- False Positive Rate: +5-10%

### High Precision (Minimize False Positives)

Higher thresholds reduce false positives but miss some attacks:

```yaml
policy:
  categories:
    prompt_injection:
      threshold: 0.7  # Conservative
    jailbreak:
      threshold: 0.7
```

Expected impact:
- True Positive Rate: -10-15%
- False Positive Rate: -3-5%

## Version History

| Version | Balanced Score | TPR | TNR | Notes |
|---------|----------------|-----|-----|-------|
| v0.2.42 | 75.81% | 53.65% | 97.97% | Hyperscan SOM_LEFTMOST fix |
| v0.2.38 | 76.10% | 54.26% | 97.93% | Baseline (different dataset) |

## Detection Limitations

### What We Detect Well

- **Jailbreaks** (74.9%): DAN mode, evil mode, persona exploits
- **Direct Injection** (60%+): "Ignore previous instructions"
- **Encoding Evasion**: Base64, URL encoding, hex escapes

### Known Gaps

- **Semantic Attacks**: Subtle rephrasing without trigger patterns
- **Novel Techniques**: Zero-day jailbreaks not in training data
- **Indirect Injection**: Attacks embedded in external content

### Improving Detection

1. **Enable ML Classifier** (Enterprise): +15-25% TPR
2. **Custom Signatures**: Add patterns specific to your use case
3. **Lower Thresholds**: Trade precision for recall
4. **Response Scanning**: Catch data exfiltration attempts

## Reproducing Results

```bash
# Clone benchmark repo
git clone https://github.com/AInvirion/prompt-injection-benchmark.git
cd prompt-injection-benchmark

# Install
uv venv && source .venv/bin/activate
uv pip install -e .

# Run against production
pibench run https://docker.aiproxyguard.com \
  -d data/baseline_v2.jsonl \
  --name "AIProxyGuard v0.2.42" \
  -o results/my_benchmark.json

# View results
pibench report results/my_benchmark.json
```

## CI/CD Integration

Add benchmark checks to your pipeline:

```yaml
# .github/workflows/benchmark.yml
name: Benchmark
on:
  release:
    types: [published]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install PIBench
        run: |
          pip install git+https://github.com/AInvirion/prompt-injection-benchmark.git
      
      - name: Run Benchmark
        run: |
          pibench run ${{ secrets.PROXY_URL }} \
            -d data/baseline_v2.jsonl \
            -o benchmark.json
      
      - name: Check Threshold
        run: |
          score=$(jq '.balanced_score' benchmark.json)
          if (( $(echo "$score < 0.70" | bc -l) )); then
            echo "Benchmark score $score below threshold 0.70"
            exit 1
          fi
```

## Contributing

To add new test cases or improve the benchmark:

1. Fork [prompt-injection-benchmark](https://github.com/AInvirion/prompt-injection-benchmark)
2. Add samples to `data/` or new sources to `src/pibench/datasets.py`
3. Submit a PR with before/after benchmark results
