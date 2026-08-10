# Requêtes OpenSearch — SocForge Threat Hunting

Requêtes pour l'interface Wazuh Threat Hunting (OpenSearch Dashboards) à `https://localhost:12443`.

---

## 1. Recherche par règle Wazuh

```
rule.id: "100121"
```
```
rule.id: ("100101" OR "100120" OR "100121" OR "100131" OR "100140" OR "100103")
```

---

## 2. T1059.001 — PowerShell encodé

```
rule.groups: "powershell" AND data.win.eventdata.commandLine: *enc*
```
```
data.win.eventdata.newProcessName: *powershell* AND data.win.eventdata.commandLine: *bypass*
```

---

## 3. T1110 — Brute Force

```
data.win.system.eventID: "4625" AND agent.name: "dc01"
```
```
rule.id: "60122" AND agent.name: "dc01"
```

Agrégation par utilisateur cible (via Dashboard → Visualize):
```json
{
  "aggs": {
    "target_users": {
      "terms": {"field": "data.win.eventdata.targetUserName", "size": 10}
    }
  }
}
```

---

## 4. T1021.002 — Admin Shares

```
data.win.system.eventID: "5140" AND data.win.eventdata.shareName: *ADMIN*
```
```
rule.id: "100140" AND agent.name: "dc01"
```

---

## 5. T1003 — Credential Dumping (Sysmon 10)

```
data.win.system.eventID: "10" AND data.win.eventdata.targetImage: *lsass*
```

---

## 6. T1046 — Network Scan (Sysmon 3)

```
data.win.system.eventID: "3" AND data.win.eventdata.destinationPort: (445 OR 3389 OR 22 OR 80 OR 443)
```

---

## 7. T1547.001 — Clés Run registry (Sysmon 13/14)

```
data.win.system.eventID: ("13" OR "14") AND data.win.eventdata.targetObject: *CurrentVersion\\Run*
```

---

## 8. T1055 — Process Injection (Sysmon 8)

```
data.win.system.eventID: "8"
```
Filtrer ensuite par `data.win.eventdata.targetImage` pour exclure les processus système.

---

## 9. Chercher tous les événements d'un agent (exemple DC01)

```
agent.name: "dc01" AND rule.level: [10 TO 15]
```

---

## 10. Timeline d'un incident (plage horaire)

Dans Threat Hunting → changer `Time Range` de "Last 1 year" à une plage personnalisée:
- From: `2026-08-07T14:00:00`
- To: `2026-08-07T17:00:00`

Puis filtrer:
```
agent.name: ("dc01" OR "win01") AND rule.level: [8 TO 15]
```

---

## 11. Chasse aux processus non signés (YARA + Wazuh)

```
rule.groups: "yara_malware" OR rule.id: ("87105" OR "87106")
```

---

## 12. Détection de compte privilégié suspect (T1078)

```
data.win.system.eventID: "4624" AND data.win.eventdata.logonType: "3" AND data.win.eventdata.targetUserName: *admin*
```
