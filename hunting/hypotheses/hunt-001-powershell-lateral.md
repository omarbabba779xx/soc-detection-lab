# Hunt-001 — PowerShell utilisé pour mouvement latéral

**Hypothèse**: Un attaquant utilise PowerShell avec des paramètres encodés pour pivoter entre les machines du réseau en exécutant des commandes à distance.

**Tactique MITRE**: TA0008 Lateral Movement
**Techniques**: T1059.001, T1021.002, T1028 (WinRM)
**Priorité**: Haute
**Statut**: Terminé — VP confirmé

---

## Données sources

| Source | Champs clés |
|--------|-------------|
| Wazuh Sysmon EventID 1 | `commandLine`, `image`, `parentImage` |
| Wazuh EventID 4688 | `newProcessName`, `commandLine`, `subjectUserName` |
| Wazuh EventID 5985/5986 | WSMan/WinRM connexions |

---

## Requête OpenSearch

```json
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"rule.groups": "powershell"}},
        {"regexp": {"data.win.eventdata.commandLine": ".*(-enc|-EncodedCommand|IEX|DownloadString).*"}},
        {"range": {"@timestamp": {"gte": "now-7d"}}}
      ]
    }
  },
  "aggs": {
    "by_agent": {"terms": {"field": "agent.name", "size": 10}},
    "by_user": {"terms": {"field": "data.win.eventdata.subjectUserName", "size": 10}}
  }
}
```

---

## Résultats

- **4 événements** correspondant à la règle 100131 sur WIN01
- Tous liés à l'exercice Atomic Red Team T1059.001 le 2026-08-07
- Pas de mouvement latéral réel détecté (lab isolé)

**Conclusion**: Hypothèse validée — la détection fonctionne. Infrastructure de test.
