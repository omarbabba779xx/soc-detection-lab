# Hunt-004 — Détection de mécanismes de persistance

**Hypothèse**: Un attaquant ayant accès à un système cherche à maintenir sa présence via des clés Run, des tâches planifiées ou des services installés.

**Tactique MITRE**: TA0003 Persistence
**Techniques**: T1547.001, T1053.005, T1543.003
**Priorité**: Haute
**Statut**: En attente de test

---

## Données sources

| Source | Champs clés |
|--------|-------------|
| Sysmon EventID 13/14 | Registry modifications Run keys |
| EventID 4698/4702 | Scheduled task created/modified |
| EventID 7045 | New service installed |

---

## Requête OpenSearch — Clés Run

```json
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"terms": {"data.win.system.eventID": ["13", "14"]}},
        {"regexp": {"data.win.eventdata.targetObject": ".*CurrentVersion\\\\Run.*"}},
        {"range": {"@timestamp": {"gte": "now-7d"}}}
      ],
      "must_not": [
        {"regexp": {"data.win.eventdata.image": ".*(msiexec|OneDrive|Teams|Slack).*"}}
      ]
    }
  }
}
```

## Requête OpenSearch — Tâches planifiées

```json
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"terms": {"data.win.system.eventID": ["4698", "4702"]}},
        {"range": {"@timestamp": {"gte": "now-7d"}}}
      ],
      "must_not": [
        {"regexp": {"data.win.eventdata.taskName": ".*\\\\Microsoft\\\\Windows\\\\.*"}}
      ]
    }
  }
}
```

---

## Résultats attendus

- Tests Atomic Red Team T1547.001 et T1053.005 à planifier
- Règles Wazuh 100147 et 100153 à valider
