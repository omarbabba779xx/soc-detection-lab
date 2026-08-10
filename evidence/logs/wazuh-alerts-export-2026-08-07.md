# Export des logs d'alertes — SocForge — 2026-08-07

**Source**: Wazuh OpenSearch `wazuh-alerts-*`
**Fenêtre**: 2026-08-07T14:00:00Z → 2026-08-07T17:30:00Z
**Exporté via**: OpenSearch Dashboards → Discover → Export CSV

---

## Procédure d'export

```bash
# Via API OpenSearch (sur VM02-WAZUH)
curl -k -u admin:S0cF0rge.Lab2024 \
  -X POST "https://localhost:9200/wazuh-alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "range": {
        "@timestamp": {
          "gte": "2026-08-07T14:00:00Z",
          "lte": "2026-08-07T17:30:00Z"
        }
      }
    },
    "sort": [{"@timestamp": "asc"}],
    "size": 10000
  }' > /tmp/alerts-2026-08-07.json
```

---

## Résumé des alertes exportées

| Heure UTC    | Agent  | Rule ID | Level | Description                                    |
|--------------|--------|---------|-------|------------------------------------------------|
| 14:23:11     | win01  | 100120  | 8     | PowerShell execution detected                  |
| 14:23:11     | win01  | 100121  | 12    | PowerShell encoded command                     |
| 14:23:11     | win01  | 100127  | 10    | Base64 obfuscation in commandline              |
| 14:23:58     | win01  | 100131  | 12    | Sigma T1059.001 — script block                 |
| 15:01:44     | dc01   | 60122   | 5     | Logon failure — Administrator (1/29)           |
| 15:01:51     | dc01   | 60122   | 5     | Logon failure — Administrator (2/29)           |
| 15:02:56     | dc01   | 100111  | 10    | Brute force threshold reached (5 in 60s)       |
| 16:45:02     | dc01   | 100140  | 10    | Admin share ADMIN$ access from 10.10.10.60     |
| 16:45:25     | dc01   | 100140  | 10    | Admin share ADMIN$ access (repeat)             |

**Total**: 7 alertes critiques + 651,566 événements 5140 sur la semaine

---

## Localisation des fichiers complets

Les exports complets (JSON/CSV) sont stockés hors du dépôt Git pour raisons de taille:
- `evidence/logs/alerts-2026-08-07.json` — export brut JSON (non commité)
- La version synthétique est dans `metrics/datasets/labeled-events-2026-08-07.csv`
