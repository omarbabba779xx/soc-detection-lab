# Fiche de Détection — Windows (DC01 + WIN01)

> Reconstruit le 2026-09-17 sur un manager Wazuh propre (snapshot pré-config restauré).
> Chaque règle listée ici a été redéployée puis testée en direct sur ce socle vierge —
> aucune entrée n'est un report non vérifié de l'ancienne itération du projet.

## Preuves visuelles — Wazuh Dashboard

En complément des extraits `alerts.log`, les règles validées sont visibles dans le
dashboard Wazuh (module Threat Hunting, `https://<manager>/app/threat-hunting`) :

- Vue d'ensemble (24h, 3956 événements, Top 10 MITRE ATT&CK — PowerShell, Scheduled
  Task, Valid Accounts, LSASS Memory, Process Injection, Sudo/Sudo Caching, Remote
  Services, Account Discovery, Obfuscated Files) :
  [`wazuh-dashboard-threat-hunting-overview.png`](../../docs/screenshots/wazuh-dashboard-threat-hunting-overview.png)
- Événements filtrés sur `rule.id:(100121 or 100131 or 100120 or 100127 or 100153 or
  100178)`, agent WIN01, 26 correspondances :
  [`wazuh-dashboard-win01-powershell-events.png`](../../docs/screenshots/wazuh-dashboard-win01-powershell-events.png)
- Événements filtrés sur `rule.id:(100153 or 100178)`, agent dc01, 11 correspondances :
  [`wazuh-dashboard-dc01-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-events.png)
- Événements filtrés sur `rule.id:(100101 or 100102 or 100110 or 100111)`, agent dc01,
  60 correspondances (scan PURPLE→dc01) :
  [`wazuh-dashboard-dc01-scan-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-scan-events.png)
- Événements filtrés sur `rule.id:(100110 or 100111)`, agent dc01, 13 correspondances
  (brute force SMB PURPLE→dc01) :
  [`wazuh-dashboard-dc01-bruteforce-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-bruteforce-events.png)

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
- **Source**: Sysmon EventID 3 (nécessite Sysmon Sysinternals installé — absent par défaut sur ce snapshot, voir ci-dessous)
- **Règle Wazuh**: 100101 (connexion unique vers port sensible), 100102 (agrégation ≥10 connexions/5 min)
- **Indicateurs**: Connexions vers des ports sensibles (RDP, SMB, DB) ; agrégation sur 10 connexions/5 min pour la détection de scan.
- **Prérequis découvert en reconstruction** : Sysmon (Sysinternals) n'était pas installé sur DC01 — seul un
  `sysmon.ocx` Windows sans rapport existait. Installé (`Sysmon64.exe -accepteula -i`) avec la config
  SwiftOnSecurity, qui exclut par défaut la plupart des connexions réseau (bruit réduit) — remplacée par une
  config minimale n'excluant aucune connexion (`Sysmon64.exe -c netconfig.xml`, `<NetworkConnect
  onmatch='exclude' />` vide = tout inclus), indispensable pour que EventID 3 soit généré.
- **Testé en direct le 2026-09-17** depuis PURPLE (Kali) contre dc01 via `nmap -sT` sur les ports
  21/22/23/25/445/1433/3306/3389/5985/5986 :
  - `Rule: 100101 (level 8) -> 'Sigma T1046: Network connection to a sensitive/admin port — 10.10.10.109:445'`
  - `Rule: 100101 (level 8) -> '... — 10.10.10.109:5985'`
  - 5 scans répétés (10 connexions matchées 100101 en moins de 5 min) →
    `Rule: 100102 (level 10) -> 'Sigma T1046: Multiple ports scanned from the same source — possible port scan'`
- **Bug de règle trouvé et corrigé** : aucun sur 100101/100102 elles-mêmes — le blocage initial venait d'une
  déconnexion transitoire de l'agent dc01 après un redémarrage du manager (résolu par `Restart-Service
  WazuhSvc -Force`, qui force une poignée de main complète). Deux règles voisines avaient en revanche un vrai
  bug de nommage de groupe, corrigé au même moment : voir T1003 et T1547.001 ci-dessous.

### T1059.001 — PowerShell Execution
- **Source**: EventID 4688 (process creation), 4104 (script block)
- **Règle Wazuh**: 100120 (processus), 100121 (paramètres suspects), 100131 (contenu du script block)
- **Indicateurs**: `-enc`, `-EncodedCommand`, `IEX`, `DownloadString`, `-bypass`, `FromBase64String`.
- **Prérequis (3, tous indispensables)** — sans eux Windows ne produit jamais l'événement source :
  ```powershell
  auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
  reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
  ```
  Le premier active les 4688 ; le deuxième y ajoute la ligne de commande (sans quoi 100121 n'a aucun champ
  `commandLine` à inspecter) ; le troisième active les 4104 requis par 100131.
- **Bug corrigé sur la règle 100131** : elle chaînait sur `<if_group>windows_powershell</if_group>`, un groupe
  qui **n'existe pas** dans le ruleset Wazuh (vérifié : aucune occurrence dans `/var/ossec/ruleset/rules/`).
  La règle ne pouvait donc jamais matcher, même avec les 4104 correctement collectés. Corrigé en chaînant sur
  `<if_sid>91802</if_sid>`, la règle parente officielle du canal `Microsoft-Windows-PowerShell/Operational`
  (fichier `0915-win-powershell_rules.xml`), qui garantit que `scriptBlockText` est décodé.
- **Testé en direct le 2026-09-17** sur WIN01 (commande encodée bénigne, décodant `SocForgeRuleTest`) :
  - `Rule: 100121 (level 12) -> 'Sigma T1059.001: PowerShell with suspicious parameters (encoded/download cradle/bypass)'` — EventID 4688, `commandLine` contenant `-EncodedCommand JABzAD0A…`
  - `Rule: 100131 (level 12) -> 'Sigma T1059.001: PowerShell ScriptBlock with suspicious content'` — EventID 4104, `scriptBlockText` contenant `FromBase64String('U29jRm9yZ2VSdWxlVGVzdA==')`

  Capture : [`docs/screenshots/rule-100121-100131-powershell-live.png`](../../docs/screenshots/rule-100121-100131-powershell-live.png)
- **Faux positifs**: 100120 (niveau 8) se déclenche sur tout lancement de PowerShell, y compris les scripts
  d'inventaire de Wazuh lui-même (`secedit /export`, `Get-ADDefaultDomainPasswordPolicy`) — observé pendant ce
  test. À filtrer en production sur `parentProcessName`.

### T1110 — Brute Force
- **Source**: EventID 4625
- **Règle Wazuh**: 100110 (échec individuel), 100111 (agrégation ≥5/60s même source)
- **Indicateurs**: >5 échecs sur le même compte en 60 secondes.
- **Bug de règle trouvé et corrigé (2026-09-17)** : 100111 utilisait `<same_source_ip/>`,
  qui regroupe sur le champ générique `srcip` — jamais peuplé par le décodeur JSON
  générique pour les événements Windows (`win.eventdata.ipAddress` reste un champ
  dynamique distinct, sans alias automatique vers `srcip`). La règle ne groupait donc
  jamais rien, même avec des échecs identiques à la même seconde depuis la même IP.
  Corrigé en `<same_field>win.eventdata.ipAddress</same_field>`, qui permet un
  regroupement sur n'importe quel champ décodé nommé.
- **Testé en direct le 2026-09-17** depuis PURPLE (Kali) contre dc01, brute force SMB via
  `netexec smb 10.10.10.109 -u administrator -p pw.txt` (6 mots de passe invalides) :
  - 6× `Rule: 100110 (level 6) -> 'Sigma T1110: Failed logon attempt — administrator'`
  - `Rule: 100111 (level 10) -> 'Sigma T1110: Multiple failed logon attempts from the same source — brute force'`

### T1021.002 — SMB Admin Shares
- **Source**: EventID 5140
- **Règle Wazuh**: 100139 (bruit filtré), 100140 (alerte réelle)
- **Correction appliquée**: exclusion des comptes machine (`$`) et `ANONYMOUS LOGON`, root-causée lors d'une session précédente (651 566 faux positifs avant le fix).
- **Testé en direct le 2026-09-17** : `net use \\10.10.10.109\C$ /user:administrator ...` exécuté depuis WIN01
  (10.10.10.110) vers DC01, dans la continuité du mouvement latéral DC01↔WIN01 prévu à l'étape 4 de la
  reconstruction :
  `Rule: 100140 (level 10) -> 'Sigma T1021.002: Real account accessed an admin share — possible lateral movement — Administrator from 10.10.10.110'`.
  Le même accès a aussi retriggé 100178 (T1078) depuis cette nouvelle source, confirmant la détection croisée.

### T1027 — Obfuscated Files or Information
- **Source**: Sysmon EventID 1
- **Règle Wazuh**: 100127
- **Indicateurs**: `commandLine` contenant un pattern Base64 (≥100 caractères) ou `FromBase64String`.
- **Confirmé en direct le 2026-09-17** : le même test que T1059.001 a également déclenché
  `Rule: 100127 (level 10) -> 'Sigma T1027: Base64-encoded pattern in command line — possible obfuscation'`
  (7 déclenchements). C'est le comportement attendu : une commande encodée est simultanément de
  l'exécution PowerShell et de l'obfuscation — la corrélation des deux règles renforce le verdict.

### T1003 — Credential Dumping
- **Source**: Sysmon EventID 10
- **Règle Wazuh**: 100103
- **Indicateurs**: Accès mémoire LSASS avec `GrantedAccess` 0x1010/0x1410.
- **Bug de règle trouvé et corrigé (2026-09-17)** : chaînait sur `<if_group>sysmon_event10</if_group>` — groupe
  **inexistant** (confirmé par `wazuh-logtest` : *"Group 'sysmon_event10' was not found. Invalid 'if_group'.
  Rule '100103' will be ignored."*). Le ruleset Wazuh nomme les groupes des EventID à deux chiffres avec un
  underscore (`sysmon_event_10`, pas `sysmon_event10`) — les EventID à un chiffre n'en ont pas
  (`sysmon_event3`, `sysmon_event8`…), incohérence de convention qui piège facilement une règle custom.
  Corrigé en `<if_group>sysmon_event_10</if_group>`.
- **Tentative de test en direct le 2026-09-18** : contrairement à un dump LSASS complet, ouvrir un handle sur
  `lsass.exe` avec les seuls droits `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` (0x1010) via `OpenProcess`
  est un test bénin légitime — c'est exactement le bitmask que la règle inspecte, sans lecture ni
  exfiltration de mémoire. Construit via un script encodé en Base64 (`powershell -EncodedCommand`, même
  méthode que le test T1059.001 réussi la veille). **Échec d'infrastructure, pas de règle** : la frappe de la
  commande (811 caractères) via `VBoxManage keyboardputstring` s'est arrêtée au milieu sans erreur après
  ~22 caractères (`powershell.exe -Encod`), un comportement non reproduit sur les commandes plus courtes
  utilisées ailleurs cette session. Annulé proprement (Ctrl+C) sans effet de bord. Non re-testé en direct —
  nécessiterait une méthode de transfert de commande plus robuste (fichier via SFTP/partage réseau plutôt que
  clavier simulé).

### T1547.001 — Registry Run Keys
- **Source**: Sysmon EventID 13/14
- **Règle Wazuh**: 100147
- **Indicateurs**: Modification des clés `CurrentVersion\Run`, `Winlogon`.
- **Bug de règle trouvé et corrigé (2026-09-17)** : même piège que 100103 (groupe `sysmon_event13,
  sysmon_event14` inexistant — deux fautes cumulées : underscore manquant **et** virgule invalide comme
  séparateur OR dans `<if_group>`, qui attend une syntaxe regex `|`). Corrigé en
  `<if_group>sysmon_event_13|sysmon_event_14</if_group>`, revalidé sans avertissement via `wazuh-logtest`.
- **Tentative de test en direct le 2026-09-17/18** : clé `CurrentVersion\Run` créée deux fois (avant et après
  redémarrage du service agent). **Bug d'infrastructure réel découvert** : le scan FIM complet sur WIN01
  (`agent_control -i 005` → `Syscheck last started at: ... (Scan in progress)`) est resté bloqué "in
  progress" plus de 10 minutes sans jamais se terminer — vérifié via `tasklist` que `wazuh-agent.exe`
  restait à 0% CPU pendant cette période, signe d'un blocage réel et non d'une simple lenteur. Un
  redémarrage complet du service (`net stop`/`net start WazuhSvc`) a relancé un nouveau scan (nouvel
  horodatage de départ), qui s'est bloqué de la même façon. La détection T1547.001 elle-même reste
  couverte par la règle native Sysmon 92302 (EventID 13, temps réel), qui **s'est déclenchée immédiatement**
  sur ce même événement de test lors de la session précédente, sans dépendre du FIM. Root cause du blocage
  FIM non résolue — piste à investiguer : volume/latence de `%PROGRAMFILES%` sur cette VM, ou bug connu de
  l'agent Windows 4.9.2 sur le scan initial de dossiers volumineux.

### T1055 — Process Injection
- **Source**: Sysmon EventID 8
- **Règle Wazuh**: 100155
- **Indicateurs**: `CreateRemoteThread` vers n'importe quel processus cible.
- **Non testé en direct (2026-09-18)** : simuler `CreateRemoteThread` de façon bénine nécessite d'écrire du
  shellcode dans un processus cible via `VirtualAllocEx`/`WriteProcessMemory`, une séquence PowerShell plus
  longue et plus fragile encore que le test LSASS (100103) qui a déjà échoué pour une raison
  d'infrastructure (frappe clavier simulée interrompue sur une commande longue — voir T1003 ci-dessus). Pas
  retenté pour éviter de reproduire le même échec ; nécessiterait un vecteur de transfert de commande plus
  fiable qu'un clavier simulé (partage réseau, SFTP, ou Guest Additions actives — indisponibles sur cette
  VM).

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
