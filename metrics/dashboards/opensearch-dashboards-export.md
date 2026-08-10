# SocForge — Export Dashboards OpenSearch / Wazuh

**URL**: https://10.10.10.10:443 (Wazuh Dashboard)
**Identifiants**: admin / S0cF0rge.Lab2024
**Index patterns**: `wazuh-alerts-4.x-*`

---

## Dashboards configurés dans SocForge

### 1. Overview SOC — Tableau de bord principal

**Widgets**:
- Total alerts (last 24h) — compteur métrique
- Alerts by severity — Donut chart (low/med/high/critical)
- Top 10 MITRE techniques triggered — Bar horizontal
- Alerts timeline — Line chart (par heure)
- Top agents generating alerts — Pie chart

**Filtre par défaut**: `rule.groups: "socforge"`

---

### 2. Purple Team — Validation des scénarios

**Widgets**:
- T1059.001 PowerShell detections — Counter + timeline
- T1110 Brute Force events — Counter + IP source table
- T1046 Network Scan events — Counter + IP timeline
- T1021.002 Lateral Movement — Counter + host pair table
- T1003 Credential Dumping — Counter + process name table

**Sauvegardé sous**: `SocForge-PurpleTeam-Dashboard`

---

### 3. DFIR — Analyse forensique

**Widgets**:
- Velociraptor alerts in Wazuh — Counter
- LSASS access detections — Counter + process lineage
- Remote thread injection — Severity gauge
- Registry persistence keys — Table (key path + value)

---

### 4. Network — NDR Zeek/Suricata

**Widgets**:
- Suricata alerts by SID — Top 10 table
- Zeek DNS anomalies — Counter
- SMB connections by source — Heatmap (source IP × destination)
- OPNsense firewall blocks — Counter + rule table

---

## Requêtes OpenSearch sauvegardées

### Détections Purple Team actives (24h)

```json
{
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "terms": { "rule.groups": ["socforge", "purple-team"] } }
      ]
    }
  },
  "sort": [{ "@timestamp": { "order": "desc" } }]
}
```

### Top techniques MITRE par fréquence

```json
{
  "aggs": {
    "mitre_techniques": {
      "terms": {
        "field": "rule.mitre.technique",
        "size": 20
      }
    }
  },
  "size": 0,
  "query": {
    "range": { "@timestamp": { "gte": "now-7d" } }
  }
}
```

### MTTD par règle (temps moyen de détection)

```json
{
  "aggs": {
    "by_rule": {
      "terms": { "field": "rule.id", "size": 20 },
      "aggs": {
        "avg_response_time": {
          "avg": { "field": "rule.firedtimes" }
        }
      }
    }
  },
  "size": 0
}
```

---

## Procédure d'export/import

```bash
# Export depuis Wazuh Dashboard (Kibana-compatible)
curl -X POST "https://10.10.10.10:443/api/saved_objects/_export" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -u admin:S0cF0rge.Lab2024 \
  --insecure \
  -d '{"type":["dashboard","visualization","index-pattern"],"includeReferencesDeep":true}' \
  -o socforge-dashboards-backup.ndjson

# Import
curl -X POST "https://10.10.10.10:443/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -u admin:S0cF0rge.Lab2024 \
  --insecure \
  -F "file=@socforge-dashboards-backup.ndjson"
```
