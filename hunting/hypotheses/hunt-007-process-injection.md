# Hunt-007 — Injection de code dans des processus légitimes

**Hypothèse**: Un attaquant injecte du code malveillant dans des processus légitimes Windows (svchost, explorer, notepad) pour masquer son activité.

**Tactique MITRE**: TA0005 Defense Evasion, TA0004 Privilege Escalation
**Techniques**: T1055, T1055.001 (DLL injection), T1055.012 (Process Hollowing)
**Priorité**: Critique
**Statut**: Hypothèse — nécessite test

---

## Données sources

| Source | Champs clés |
|--------|-------------|
| Sysmon EventID 8 | `CreateRemoteThread` — sourceImage → targetImage |
| Sysmon EventID 10 | `ProcessAccess` — accès mémoire |
| Sysmon EventID 7 | `ImageLoad` — DLL non signée |

---

## Requête OpenSearch — CreateRemoteThread

```json
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"data.win.system.eventID": "8"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ],
      "must_not": [
        {"regexp": {"data.win.eventdata.sourceImage": ".*(csrss|wininit|svchost)\\.exe"}},
        {"regexp": {"data.win.eventdata.targetImage": ".*(csrss|wininit)\\.exe"}}
      ]
    }
  },
  "sort": [{"@timestamp": "desc"}]
}
```

## Requête Velociraptor VQL — Threads inhabituels

```vql
LET procs = SELECT Pid, Ppid, Name, Exe FROM pslist()

SELECT p.Name, p.Exe, t.ThreadId, t.StartAddress
FROM thread_list() AS t
JOIN procs AS p ON t.Pid = p.Pid
WHERE p.Name IN ("notepad.exe", "explorer.exe", "mspaint.exe")
AND t.StartAddress > 0x7fff00000000
```

---

## Résultats attendus

- Atomic Red Team T1055 → `Invoke-AtomicTest T1055`
- Règle Wazuh 100155 doit déclencher
- Velociraptor Hunt `SocForge.Hunt.LsassAccess` doit capturer
