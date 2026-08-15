# SC-12 — T1546.013 : PowerShell Profile Persistence

**Session**: 3 — 2026-08-15  
**Attaquant**: WIN01 (10.10.10.110) — PowerShell admin  
**MITRE**: T1546.013 — Event Triggered Execution: PowerShell Profile  
**Tactique**: Persistence / Privilege Escalation  

---

## Objectif

Modifier le profil PowerShell global (`profile.ps1`) pour injecter du code persistant exécuté à chaque ouverture de session PowerShell (T1546.013).

---

## Commande exécutée

```cmd
cmd /c "echo SocForge-T1546 >> C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
```

**Résultat** : Succès silencieux (retour au prompt sans erreur)

**Heure d'exécution** : 2026-08-15 08:31:00 (UTC+1)

---

## Détection Wazuh

| Champ          | Valeur                                                 |
|----------------|--------------------------------------------------------|
| Règle          | 92004                                                  |
| Description    | Powershell process spawned Windows command shell instance |
| Niveau         | 4                                                      |
| Agent          | win01                                                  |
| Timestamp      | 2026-08-15 08:31:49 (UTC+1)                           |
| MTTD           | 49 secondes                                            |

---

## Preuve

![SC-12 Wazuh Detection](../../docs/screenshots/sc10-sc11-sc12-wazuh-detection.png)
![SC-12 WIN01 Profile Modification](../../docs/screenshots/sc12-win01-profile-modification.png)

---

## Résultat

| Critère          | Valeur      |
|------------------|-------------|
| Détecté          | ✅ OUI      |
| Règle            | 92004       |
| MTTD             | 49 sec      |
| Faux positif     | Non         |
| Verdict          | VP          |
