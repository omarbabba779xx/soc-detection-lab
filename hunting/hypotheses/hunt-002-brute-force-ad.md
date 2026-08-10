# Hunt-002 — Brute Force contre comptes Active Directory

**Hypothèse**: Un attaquant effectue une attaque par dictionnaire contre les comptes AD en ciblant le compte Administrator via SMB/NTLM depuis le réseau interne.

**Tactique MITRE**: TA0006 Credential Access
**Techniques**: T1110, T1110.001
**Priorité**: Haute
**Statut**: Terminé — VP confirmé

---

## Données sources

| Source | Champs clés |
|--------|-------------|
| Wazuh EventID 4625 | `targetUserName`, `ipAddress`, `logonType`, `authenticationPackageName` |
| Wazuh EventID 4771 | Kerberos pre-auth failure |
| Zeek ntlm.log | `status=LOGON_FAILURE` |

---

## Requête OpenSearch

```json
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"data.win.system.eventID": "4625"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ],
      "must_not": [
        {"wildcard": {"data.win.eventdata.targetUserName": "*$"}}
      ]
    }
  },
  "aggs": {
    "by_target_user": {
      "terms": {"field": "data.win.eventdata.targetUserName", "size": 20}
    },
    "by_source_ip": {
      "terms": {"field": "data.win.eventdata.ipAddress", "size": 20}
    },
    "timeline": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "5m"
      }
    }
  }
}
```

---

## Résultats

- **29 événements 4625** sur le compte `Administrator`
- Source: `10.10.10.60` (VM12-PURPLE, Hydra)
- Pic d'activité: 15:01:44 UTC → 15:03:12 UTC (1 min 28 sec)
- Aucun succès d'authentification (4624) détecté après la séquence

**Conclusion**: Hypothèse confirmée — attaque brute force détectée et stoppée. MTTD < 2 minutes.
