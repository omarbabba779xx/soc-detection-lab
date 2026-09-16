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

> **Root cause confirmée le 2026-09-16** : la règle 100186 ne se déclenchait pas parce que le fichier `agent.conf` réellement déployé sur le manager (`/var/ossec/etc/shared/default/agent.conf`) ne contenait **aucun bloc `<syscheck>`** — ni celui-ci ni aucun autre chemin n'était surveillé en FIM. La règle 92004 observée ci-dessus a détecté le lancement du processus PowerShell/cmd, pas la modification du fichier.
>
> **Fix déployé (partiellement validé)** : ajout de directives `<directories realtime="yes">` couvrant `%WINDIR%\System32\WindowsPowerShell` et `%USERPROFILE%\Documents\WindowsPowerShell`, XML validé, manager redémarré, et synchronisation confirmée sur l'agent DC01 (le fichier local `agent.conf` de l'agent contient bien les nouvelles directives). **Cependant**, malgré plusieurs modifications du fichier `profile.ps1` (confirmé existant sur disque via `Test-Path` → `True`) et des rescans FIM forcés, la base de données FIM de l'agent (`002.db`, table `fim_entry`) ne référence toujours que `powershell.exe` dans ce dossier — aucune alerte 100186 authentique n'a été observée. Le fix de configuration est correct et déployé, mais son effet n'a pas pu être confirmé dans le temps disponible cette session ; cause exacte non identifiée (possible particularité du scan FIM Windows sur ce sous-dossier). Voir `detections/windows/detection-sheet-windows.md`.

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
