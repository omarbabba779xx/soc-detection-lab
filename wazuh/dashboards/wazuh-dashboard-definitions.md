# SocForge — Définitions des Dashboards Wazuh

**Wazuh Dashboard**: https://10.10.10.10:443
**Version**: Wazuh 4.9.2 (OpenSearch Dashboards 2.x)
**Index**: `wazuh-alerts-4.x-*`

---

## Dashboard 1 — SocForge Security Overview

### Visualisations

#### VIZ-01: Total Alerts Last 24h
```json
{
  "title": "SocForge-Total-Alerts-24h",
  "type": "metric",
  "params": {
    "metric": { "percentageMode": false, "useRanges": false },
    "labels": { "show": true },
    "style": { "bgFill": "#000", "bgColor": false, "labelColor": false }
  },
  "aggs": [
    { "id": "1", "enabled": true, "type": "count", "schema": "metric", "params": {} }
  ]
}
```
**Filtre**: `@timestamp >= now-24h`

---

#### VIZ-02: Alerts by MITRE Technique (Bar)
```json
{
  "title": "SocForge-MITRE-Techniques",
  "type": "histogram",
  "params": {
    "type": "histogram",
    "grid": { "categoryLines": false },
    "categoryAxes": [{ "id": "CategoryAxis-1", "type": "category", "position": "left" }],
    "valueAxes": [{ "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value" }],
    "seriesParams": [{ "show": true, "type": "histogram", "mode": "normal" }]
  },
  "aggs": [
    { "id": "1", "type": "count", "schema": "metric" },
    { "id": "2", "type": "terms", "schema": "segment",
      "params": { "field": "rule.mitre.technique", "size": 15, "order": "desc", "orderBy": "1" } }
  ]
}
```

---

#### VIZ-03: Alert Severity Donut
```json
{
  "title": "SocForge-Severity-Distribution",
  "type": "pie",
  "params": {
    "type": "pie",
    "addTooltip": true,
    "addLegend": true,
    "legendPosition": "right",
    "isDonut": true
  },
  "aggs": [
    { "id": "1", "type": "count", "schema": "metric" },
    {
      "id": "2", "type": "range", "schema": "segment",
      "params": {
        "field": "rule.level",
        "ranges": [
          { "from": 0, "to": 7, "label": "Low (0-6)" },
          { "from": 7, "to": 10, "label": "Medium (7-9)" },
          { "from": 10, "to": 13, "label": "High (10-12)" },
          { "from": 13, "to": 16, "label": "Critical (13+)" }
        ]
      }
    }
  ]
}
```

---

#### VIZ-04: Timeline des alertes
```json
{
  "title": "SocForge-Alerts-Timeline",
  "type": "line",
  "params": {
    "type": "line",
    "grid": { "categoryLines": false },
    "categoryAxes": [{ "type": "category", "position": "bottom" }],
    "valueAxes": [{ "type": "value", "position": "left" }]
  },
  "aggs": [
    { "id": "1", "type": "count", "schema": "metric" },
    { "id": "2", "type": "date_histogram", "schema": "segment",
      "params": { "field": "@timestamp", "interval": "1h", "min_doc_count": 1 } }
  ]
}
```

---

#### VIZ-05: Top Agents
```json
{
  "title": "SocForge-Top-Agents",
  "type": "pie",
  "params": { "type": "pie", "isDonut": false },
  "aggs": [
    { "id": "1", "type": "count", "schema": "metric" },
    { "id": "2", "type": "terms", "schema": "segment",
      "params": { "field": "agent.name", "size": 10 } }
  ]
}
```

---

## Dashboard 2 — Purple Team Validation

### Saved Searches par technique

```bash
# T1059.001 — PowerShell
rule.id: "100120" OR rule.id: "100121" OR rule.id: "100131" OR rule.groups: "powershell"

# T1110 — Brute Force
rule.id: "100110" OR rule.id: "100111"

# T1046 — Network Scan
rule.id: "100101" OR rule.id: "100102"

# T1021.002 — SMB Lateral Movement
rule.id: "100139" OR rule.id: "100140"

# T1003 — Credential Dumping
rule.id: "100103"
```

---

## Procédure de restauration rapide

```bash
# Exporter toutes les visualisations + dashboards
curl -u admin:<WAZUH_PASSWORD> --insecure \
  -X POST "https://10.10.10.10:443/api/saved_objects/_export" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"type":["dashboard","visualization","search"],"includeReferencesDeep":true}' \
  -o wazuh-dashboards-backup-$(date +%Y%m%d).ndjson
```
