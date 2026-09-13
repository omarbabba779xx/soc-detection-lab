# LLM Alert Triage — SocForge

Local LLM integration for SOC alert triage using Ollama. Runs entirely offline — no data leaves the lab.

## Model

| Model | Size | Use case |
|-------|------|----------|
| `gemma2:9b` | 5.4 GB | Alert triage, summary generation |
| `qwen2.5:0.5b` | 380 MB | Lightweight triage on VM08-DFIR (low RAM) |

## Setup

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull models
ollama pull gemma2:9b
ollama pull qwen2.5:0.5b
```

## Usage

```bash
# Demo mode (built-in T1059.001 alert)
python scripts/llm_triage.py --demo

# From a Wazuh alert JSON export
python scripts/llm_triage.py alert.json

# Pipe from stdin
cat wazuh_alert.json | python scripts/llm_triage.py -

# Use lightweight model (VM08-DFIR)
python scripts/llm_triage.py --model qwen2.5:0.5b alert.json
```

## Example output

```
============================================================
  SocForge LLM Triage — 2026-08-07 14:23:52
  Model : gemma2:9b
  Agent : win01 (10.10.10.110)
  Rule  : 100121 — level 12
============================================================

SEVERITY: HIGH
VERDICT: Needs Investigation
SUMMARY: A PowerShell process executed a Base64 encoded command on win01.
IMMEDIATE ACTIONS:
- Investigate the Base64 encoded command for malicious activity.
- Monitor win01 for further suspicious activity.
MITRE: Execution, Base64 encoded commands
```

## Architecture

```
Wazuh alert (JSON)
      │
      ▼
llm_triage.py
      │  formats compact alert context
      ▼
Ollama API (localhost:11434)
      │  gemma2:9b or qwen2.5:0.5b
      ▼
Structured triage output
(SEVERITY / VERDICT / ACTIONS / MITRE)
```

## Design choices

- **Local only** — Ollama runs on the lab host, no internet required after model download
- **No dependencies** — pure Python stdlib + ollama (no langchain, no openai SDK)
- **Pluggable model** — `--model` flag lets you swap without code changes
- `qwen2.5:0.5b` fits in 512 MB RAM — usable on VM08-DFIR during live response
