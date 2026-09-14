# Real LLM Triage Run — 2026-09-14

Captured from a live run against a genuine Wazuh alert (not the built-in demo), pulled directly from the OpenSearch index while VM02-WAZUH was running.

## Source alert

Pulled via:
```bash
curl -k -u "admin:<password>" \
  "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=1&sort=@timestamp:desc" \
  -d '{"query":{"range":{"rule.level":{"gte":10}}}}'
```

Index held **667,061 alerts** at query time. The alert returned was triggered live during this session by an unrelated `sudo ss -tlnp` command run on VM07-NDR:

```
Sep 14 11:37:44 wazuh sudo[3940]: socadmin : PWD=/home/socadmin ; USER=root ; COMMAND=/usr/bin/ss -tlnp
```

Matched rule **100200** (level 10) — `Sigma T1548.003: Sudo privilege escalation - user executed sudo as ROOT`.

Saved as [`hunting/notebooks/sample-data/real_wazuh_alert_2026-09-14.json`](../../hunting/notebooks/sample-data/real_wazuh_alert_2026-09-14.json).

## Triage command

```bash
python scripts/llm_triage.py hunting/notebooks/sample-data/real_wazuh_alert_2026-09-14.json
```

## Real output

```
============================================================
  SocForge LLM Triage — 2026-09-14 12:40:22
  Model : gemma2:9b
  Agent : wazuh (internal)
  Rule  : 100200 — level 10
============================================================

SEVERITY: HIGH
VERDICT: Needs Investigation
SUMMARY: A user executed a command as root, potentially indicating privilege escalation.
IMMEDIATE ACTIONS:
- Review system logs for suspicious activity around the time of the alert.
- Examine the "ss -tlnp" command output for any anomalies.
MITRE: Privilege Escalation: Sudo Abuse

============================================================
```

## Assessment

The model correctly identified the MITRE technique (sudo privilege escalation) and flagged it for investigation rather than auto-closing it — an appropriate response given the alert is a routine admin command (`ss -tlnp`) that happens to match a sudo-to-root detection rule. This is the expected behavior: the LLM triage layer surfaces context and a preliminary verdict, it does not replace analyst judgment on ambiguous cases.
