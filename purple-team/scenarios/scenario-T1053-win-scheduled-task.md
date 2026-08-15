# SC-10 — T1053.005 : Scheduled Task (Windows)

**Session**: 3 — 2026-08-15  
**Attaquant**: WIN01 (10.10.10.110) — PowerShell admin  
**MITRE**: T1053.005 — Scheduled Task/Job: Scheduled Task  
**Tactique**: Persistence / Execution  

---

## Objectif

Créer une tâche planifiée Windows persistante via `schtasks.exe` pour simuler un mécanisme de persistence post-exploitation (T1053.005).

---

## Commande exécutée

```cmd
schtasks /create /tn SocForgeTest /tr notepad.exe /sc ONLOGON /f
```

**Résultat** : `SUCCESS: The scheduled task 'SocForgeTest' has successfully been created.`

**Heure d'exécution** : 2026-08-15 08:26:46 (UTC+1)

---

## Détection Wazuh

| Champ          | Valeur                                          |
|----------------|-------------------------------------------------|
| Règle          | 60642                                           |
| Description    | Software protection service scheduled successfully. |
| Niveau         | 3                                               |
| Agent          | win01                                           |
| Timestamp      | 2026-08-15 08:27:50 (UTC+1)                    |
| MTTD           | 84 secondes                                     |

---

## Preuve

![SC-10 Wazuh Detection](../../docs/screenshots/sc10-sc11-sc12-wazuh-detection.png)
![SC-10 WIN01 Attack](../../docs/screenshots/sc10-win01-attack-execution.png)

---

## Résultat

| Critère          | Valeur      |
|------------------|-------------|
| Détecté          | ✅ OUI      |
| Règle            | 60642       |
| MTTD             | 84 sec      |
| Faux positif     | Non         |
| Verdict          | VP          |
