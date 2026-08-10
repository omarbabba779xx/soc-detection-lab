# Hunt-003 — Crawl massif de partages admin Windows

**Hypothèse**: Un attaquant ayant obtenu des credentials valides parcourt les partages admin (ADMIN$, C$) pour identifier des ressources à exfiltrer ou pour déposer des outils.

**Tactique MITRE**: TA0008 Lateral Movement, TA0009 Collection
**Techniques**: T1021.002, T1039
**Priorité**: Haute
**Statut**: Terminé — VP confirmé (651,566 hits)

---

## Données sources

| Source | Champs clés |
|--------|-------------|
| Wazuh EventID 5140 | `shareName`, `ipAddress`, `subjectUserName` |
| Wazuh EventID 5145 | Accès aux fichiers dans le share |
| Sysmon EventID 3 | Connexions SMB port 445 |

---

## Requête OpenSearch

```json
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"data.win.system.eventID": "5140"}},
        {"regexp": {"data.win.eventdata.shareName": ".*\\\\(ADMIN\\$|C\\$|IPC\\$)"}},
        {"range": {"@timestamp": {"gte": "now-7d"}}}
      ],
      "must_not": [
        {"match": {"data.win.eventdata.ipAddress": "-"}}
      ]
    }
  },
  "aggs": {
    "by_share": {"terms": {"field": "data.win.eventdata.shareName", "size": 10}},
    "by_source": {"terms": {"field": "data.win.eventdata.ipAddress", "size": 10}},
    "by_user": {"terms": {"field": "data.win.eventdata.subjectUserName", "size": 10}}
  }
}
```

---

## Résultats

- **651,566 hits** sur la règle 100140 en 7 jours
- 100% depuis 10.10.10.60 (VM12-PURPLE)
- Share principal: `\\DC01\ADMIN$`
- Compte utilisé: `Administrator`

**Conclusion**: Volume anormalement élevé confirmé. La règle 100140 fonctionne. Volume justifié par l'exercice continu Purple Team.
