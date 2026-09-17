# Fiche de Détection — Windows (DC01 + WIN01)

> Reconstruit le 2026-09-17 sur un manager Wazuh propre (snapshot pré-config restauré).
> Chaque règle listée ici a été redéployée puis testée en direct sur ce socle vierge —
> aucune entrée n'est un report non vérifié de l'ancienne itération du projet.

## Sources de logs collectés

| Source                            | Canal EventLog                                    | EventIDs clés                                    |
|-----------------------------------|--------------------------------------------------|--------------------------------------------------|
| Windows Security                  | Security                                          | 4624, 4625, 4634, 4648, 4688, 4698, 4702, 4720-4726, 5140 |
| PowerShell Script Block           | Microsoft-Windows-PowerShell/Operational          | 4103, 4104, 4105, 4106                          |
| Sysmon                            | Microsoft-Windows-Sysmon/Operational              | 1,2,3,5,7,8,10,11,12-14,15,17-18,22             |
| Windows Defender                  | Microsoft-Windows-Windows Defender/Operational    | 1116, 1117, 1006, 1007                          |

---

## Techniques détectées

### T1053.005 — Scheduled Task
- **Source**: EventID 4698, 4702
- **Règle Wazuh**: 100153
- **Prérequis**: sous-catégorie d'audit "Other Object Access Events" activée (`auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`) — sans ce réglage, Windows ne génère jamais l'événement source.
- **Testé en direct le 2026-09-17** : `schtasks /create /tn SocForgeRebuildTest /tr calc.exe /sc once /st 23:59 /f` sur DC01 → alerte confirmée dans `alerts.log` : `Rule: 100153 (level 9) -> 'Sigma T1053: Scheduled task created/modified — \SocForgeRebuildTest'`. Capture : [`docs/screenshots/rule-100153-100178-live-rebuild.png`](../../docs/screenshots/rule-100153-100178-live-rebuild.png).
- **Faux positifs**: Windows Update crée/modifie très régulièrement `\Microsoft\Windows\UpdateOrchestrator\Reboot_AC` — observé plusieurs fois pendant ce test, à filtrer en production par exclusion sur `taskName`.

### T1078 — Valid Accounts
- **Source**: EventID 4624
- **Règle Wazuh**: 100178
- **Testé en direct le 2026-09-17** : logon réseau (`net use \\10.10.10.109\C$ /user:administrator ...`, LogonType 3) → alerte confirmée : `Rule: 100178 (level 9) -> 'Sigma T1078: Privileged account remote logon — Administrator from 10.10.10.109'`. Capture : [`docs/screenshots/rule-100153-100178-live-rebuild.png`](../../docs/screenshots/rule-100153-100178-live-rebuild.png).
- **Faux positifs**: Connexions admin légitimes planifiées.

### T1546.013 — PowerShell Profile
- **Source**: FIM (syscheck)
- **Règle Wazuh**: 100186
- **Prérequis**: FIM configuré sur `%WINDIR%\System32\WindowsPowerShell` et `%USERPROFILE%\Documents\WindowsPowerShell` (voir `wazuh/agents/agent.conf`) — sans ces directives, syscheck ne surveille jamais le fichier de profil.
- **Statut**: config déployée et synchronisée sur l'agent ; non re-testé en direct dans cette session de reconstruction (déjà validé lors d'une session antérieure).

### T1046 — Network Service Discovery
- **Source**: Sysmon EventID 3
- **Règle Wazuh**: 100101, 100102
- **Indicateurs**: Connexions vers des ports sensibles (RDP, SMB, DB) ; agrégation sur 10 connexions/5 min pour la détection de scan.

### T1059.001 — PowerShell Execution
- **Source**: EventID 4688, 4104, Sysmon-1
- **Règle Wazuh**: 100120, 100121, 100131
- **Indicateurs**: `-enc`, `-EncodedCommand`, `IEX`, `DownloadString`, `-bypass`.

### T1110 — Brute Force
- **Source**: EventID 4625
- **Règle Wazuh**: 100110, 100111
- **Indicateurs**: >5 échecs sur le même compte en 60 secondes.

### T1021.002 — SMB Admin Shares
- **Source**: EventID 5140
- **Règle Wazuh**: 100139 (bruit filtré), 100140 (alerte réelle)
- **Correction appliquée**: exclusion des comptes machine (`$`) et `ANONYMOUS LOGON`, root-causée lors d'une session précédente (651 566 faux positifs avant le fix).

### T1027 — Obfuscated Files or Information
- **Source**: Sysmon EventID 1
- **Règle Wazuh**: 100127
- **Indicateurs**: `commandLine` contenant un pattern Base64 (≥100 caractères) ou `FromBase64String`.

### T1003 — Credential Dumping
- **Source**: Sysmon EventID 10
- **Règle Wazuh**: 100103
- **Indicateurs**: Accès mémoire LSASS avec `GrantedAccess` 0x1010/0x1410.

### T1547.001 — Registry Run Keys
- **Source**: Sysmon EventID 13/14
- **Règle Wazuh**: 100147
- **Indicateurs**: Modification des clés `CurrentVersion\Run`, `Winlogon`.

### T1055 — Process Injection
- **Source**: Sysmon EventID 8
- **Règle Wazuh**: 100155
- **Indicateurs**: `CreateRemoteThread` vers n'importe quel processus cible.

---

## Niveaux de sévérité Wazuh

| Niveau | Règles                                    |
|--------|-------------------------------------------|
| 14     | 100103                                    |
| 13     | 100155                                    |
| 12     | 100121, 100131                            |
| 10     | 100102, 100111, 100127, 100140            |
| 9      | 100147, 100153, 100178                    |
| 8      | 100101, 100120, 100186                    |
| 6      | 100110                                    |
| 3      | 100139                                    |
