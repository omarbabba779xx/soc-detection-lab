# SC-13 — T1546.013 : PowerShell Profile Persistence

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

> **Root cause confirmée le 2026-09-16** : la règle 100186 ne peut pas se déclencher, par construction — elle dépend du FIM (syscheck) pour surveiller `C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1`, exactement le chemin modifié ci-dessus, mais `wazuh/agents/agent.conf` ne configure aucune directive `<directories>` couvrant `System32\WindowsPowerShell\` — seuls `System32\drivers\etc`, `System32\Tasks`, `%PROGRAMFILES%` et `%PROGRAMFILES(X86)%` sont surveillés. La règle 92004 observée ci-dessus a détecté le lancement du processus PowerShell/cmd, pas la modification du fichier. Corrigible en ajoutant une entrée FIM pour ce chemin dans `agent.conf`, non fait cette session. Voir `detections/windows/detection-sheet-windows.md`.

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
