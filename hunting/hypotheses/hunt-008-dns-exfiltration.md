# Hunt-008 — Exfiltration via DNS (DNS Tunneling)

**Hypothèse**: Un attaquant exfiltre des données en encodant les informations dans des requêtes DNS anormalement longues ou fréquentes vers un domaine externe contrôlé.

**Tactique MITRE**: TA0010 Exfiltration, TA0011 Command and Control
**Techniques**: T1048.003, T1071.004
**Priorité**: Moyenne
**Statut**: Hypothèse — environnement lab (accès DNS externe limité)

---

## Données sources

| Source | Champs clés |
|--------|-------------|
| Zeek dns.log | `query`, `qtype`, `answers`, `rtt` |
| Sysmon EventID 22 | `queryName`, longueur anormale |
| OPNsense filterlog | Requêtes DNS sortantes vers 8.8.8.8 / 1.1.1.1 |

---

## Indicateurs de DNS Tunneling

| Indicateur | Valeur suspecte |
|------------|-----------------|
| Longueur du nom de domaine | > 50 caractères |
| Sous-domaine encodé Base64 | Pattern alphanumérique long |
| Fréquence par domaine | > 100 requêtes/heure |
| Type de requête | TXT, NULL, CNAME (non standard) |
| Taille des réponses | Anormalement grande pour un DNS |

---

## Requête Zeek dns.log

```bash
# Détecter les requêtes DNS avec des noms longs (>50 chars)
cat dns.log | zeek-cut query | awk 'length($0) > 50' | sort | uniq -c | sort -rn | head -20

# Détecter les domaines avec haute fréquence
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head -20
```

## Requête OpenSearch — DNS longs (Sysmon 22)

```json
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"data.win.system.eventID": "22"}},
        {"script": {
          "script": "doc['data.win.eventdata.queryName'].value.length() > 50"
        }},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  }
}
```

---

## Résultats attendus

- Dans le lab: les requêtes DNS sont limitées par OPNsense
- Test possible: Iodine / dnscat2 entre VM12 et VM07-NDR (interne uniquement)
- Zeek doit logger les requêtes dns.log anormales
