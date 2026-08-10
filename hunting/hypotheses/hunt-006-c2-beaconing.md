# Hunt-006 — Détection de beaconing C2

**Hypothèse**: Un implant sur un endpoint effectue des connexions régulières (beaconing) vers un serveur C2 externe avec un intervalle de temps constant.

**Tactique MITRE**: TA0011 Command and Control
**Techniques**: T1071.001, T1071.004, T1573
**Priorité**: Haute
**Statut**: Hypothèse — nécessite test lab

---

## Données sources

| Source | Champs clés |
|--------|-------------|
| Zeek conn.log | Connexions avec intervalles réguliers |
| Sysmon EventID 3 | Connexions réseau par processus |
| Sysmon EventID 22 | DNS queries régulières |

---

## Méthode de chasse

### Détection par intervalle régulier (Zeek)

```python
# Script de détection de beaconing via statistiques
# Calculer l'écart-type des intervalles entre connexions par (src_ip, dst_ip, dst_port)
# Un écart-type faible + haute fréquence = beaconing probable

import pandas as pd
import numpy as np

def detect_beaconing(df, threshold_std=30, min_connections=10):
    groups = df.groupby(['src_ip', 'dst_ip', 'dst_port'])
    for name, group in groups:
        if len(group) < min_connections:
            continue
        intervals = group['ts'].diff().dropna().dt.total_seconds()
        if intervals.std() < threshold_std and intervals.mean() < 300:
            print(f"BEACON SUSPECT: {name}, interval_moy={intervals.mean():.1f}s, std={intervals.std():.1f}s")
```

### Requête OpenSearch — DNS réguliers

```json
GET /wazuh-alerts-*/_search
{
  "aggs": {
    "dns_by_domain_host": {
      "terms": {
        "script": "doc['data.win.eventdata.queryName'].value + '|' + doc['agent.name'].value",
        "size": 100
      },
      "aggs": {
        "count_per_hour": {
          "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "1h"
          }
        }
      }
    }
  }
}
```

---

## Indicateurs de beaconing

- Intervalle de connexion régulier (< 30 sec d'écart type)
- Fréquence élevée (>= 10 connexions/heure)
- Même dst_ip + dst_port
- User-Agent inhabituel ou vide
- Taille de payload constante (beaconing HTTP)

---

## Résultats attendus

- Test: configurer Meterpreter avec check-in toutes les 30s sur VM12
- Vérifier détection par Zeek + Suricata ET Malware
