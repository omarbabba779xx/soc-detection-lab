# SC-11 — T1078 : Valid Account Remote Logon

**Session**: 3 — 2026-08-15  
**Attaquant**: WIN01 (10.10.10.110) — PowerShell admin  
**MITRE**: T1078 — Valid Accounts  
**Tactique**: Initial Access / Lateral Movement  

---

## Objectif

Utiliser des identifiants valides pour établir une connexion réseau via `net use`, simulant un mouvement latéral ou une persistence via comptes légitimes (T1078).

---

## Commande exécutée

```cmd
net use \\localhost\C$ /user:socadmin <LAB_PASSWORD>
```

**Résultat** : `System error 5 has occurred. Access is denied.` (accès refusé attendu pour compte non-admin réseau)

**Heure d'exécution** : 2026-08-15 08:26:00 (UTC+1)

---

## Détection Wazuh

| Champ          | Valeur                                                          |
|----------------|-----------------------------------------------------------------|
| Règle          | 92037                                                           |
| Description    | A net.exe connection to a remote resource was started by C:\Windows\system32\cmd.exe |
| Niveau         | 3                                                               |
| Agent          | win01                                                           |
| Timestamp      | 2026-08-15 08:26:42 (UTC+1)                                    |
| MTTD           | 42 secondes                                                     |

---

## Preuve

![SC-11 Wazuh Detection](../../docs/screenshots/sc10-sc11-sc12-wazuh-detection.png)
![SC-11 WIN01 Net Use](../../docs/screenshots/sc11-win01-net-use.png)

---

## Résultat

| Critère          | Valeur      |
|------------------|-------------|
| Détecté          | ✅ OUI      |
| Règle            | 92037       |
| MTTD             | 42 sec      |
| Faux positif     | Non         |
| Verdict          | VP          |
