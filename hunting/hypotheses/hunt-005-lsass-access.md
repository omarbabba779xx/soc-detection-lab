# Hunt-005 — Accès mémoire LSASS (Credential Dumping)

**Hypothèse**: Un attaquant tente de dumper les credentials en mémoire depuis le processus LSASS en utilisant des outils comme Mimikatz ou ses dérivés PowerShell.

**Tactique MITRE**: TA0006 Credential Access
**Techniques**: T1003, T1003.001
**Priorité**: Critique
**Statut**: En attente de test (Atomic T1003.001)

---

## Données sources

| Source | Champs clés |
|--------|-------------|
| Sysmon EventID 10 | `targetImage=lsass.exe`, `grantedAccess` |
| EventID 4656/4663 | Objet audit sur lsass |
| YARA | `SocForge_Mimikatz_Strings` |

---

## Requêtes OpenSearch

```json
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"data.win.system.eventID": "10"}},
        {"regexp": {"data.win.eventdata.targetImage": ".*lsass\\.exe"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ],
      "must_not": [
        {"regexp": {"data.win.eventdata.sourceImage": ".*(MsMpEng|csrss|wininit|lsass)\\.exe"}}
      ]
    }
  }
}
```

## Requête Velociraptor VQL

```vql
SELECT Pid, Ppid, Name, Exe, CommandLine,
       hash(path=Exe, hashselect="MD5,SHA256") AS Hashes
FROM pslist()
WHERE Name =~ "(?i)mimikatz|mimi|sekurlsa"
   OR CommandLine =~ "(?i)sekurlsa|lsadump|wdigest"
```

---

## Résultats attendus

- Règle Wazuh 100103 doit déclencher sur tout accès non-système à LSASS
- YARA doit détecter les strings Mimikatz dans les fichiers suspects
