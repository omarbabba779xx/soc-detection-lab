# Fiche de Détection : Windows (DC01 + WIN01)

> Reconstruit le 2026-09-17 sur un manager Wazuh propre (snapshot pré-config restauré).
> Chaque règle listée ici a été redéployée puis testée en direct sur ce socle vierge :
> aucune entrée n'est un report non vérifié de l'ancienne itération du projet.

## Preuves visuelles : Wazuh Dashboard

En complément des extraits `alerts.log`, les règles validées sont visibles dans le
dashboard Wazuh (module Threat Hunting, `https://<manager>/app/threat-hunting`) :

- Vue d'ensemble (24h, 3956 événements, Top 10 MITRE ATT&CK, PowerShell, Scheduled
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
- Événements filtrés sur `rule.id:(100139 or 100140 or 100186)`, 23/09 14:10–15:20 UTC, 12 correspondances
  (validation en direct après les corrections du 23/09) :
  [`wazuh-rules-100139-100140-100186-live.png`](../../docs/screenshots/wazuh-rules-100139-100140-100186-live.png)

## Sources de logs collectés

| Source                            | Canal EventLog                                    | EventIDs clés                                    |
|-----------------------------------|--------------------------------------------------|--------------------------------------------------|
| Windows Security                  | Security                                          | 4624, 4625, 4634, 4648, 4688, 4698, 4702, 4720-4726, 5140 |
| PowerShell Script Block           | Microsoft-Windows-PowerShell/Operational          | 4103, 4104, 4105, 4106                          |
| Sysmon                            | Microsoft-Windows-Sysmon/Operational              | 1,2,3,5,7,8,10,11,12-14,15,17-18,22             |
| Windows Defender                  | Microsoft-Windows-Windows Defender/Operational    | 1116, 1117, 1006, 1007                          |

---

## Techniques détectées

### T1053.005 : Scheduled Task
- Source: EventID 4698, 4702
- Règle Wazuh: 100153
- Prérequis: sous-catégorie d'audit "Other Object Access Events" activée (`auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`), sans ce réglage, Windows ne génère jamais l'événement source.
- Testé en direct le 2026-09-17 : `schtasks /create /tn SocForgeRebuildTest /tr calc.exe /sc once /st 23:59 /f` sur DC01 → alerte confirmée dans `alerts.log` : `Rule: 100153 (level 9) -> 'Sigma T1053: Scheduled task created/modified — \SocForgeRebuildTest'`. Capture : [`docs/screenshots/rule-100153-100178-live-rebuild.png`](../../docs/screenshots/rule-100153-100178-live-rebuild.png).
- Faux positifs: Windows Update crée/modifie très régulièrement `\Microsoft\Windows\UpdateOrchestrator\Reboot_AC`, observé plusieurs fois pendant ce test, à filtrer en production par exclusion sur `taskName`.
- Tâches du dossier système (2026-10-07) : Windows réécrit lui-même des tâches sous `\Microsoft\Windows\`
  (mises à jour, maintenance), ce qui faisait de `100153` la règle la plus bavarde de la fiche (118 alertes de
  niveau 9 sur l'historique du lab). La règle `100152` (niveau 3) enregistre désormais ces tâches sans alerter, et
  `100153` ne garde que les autres. Piège rencontré : l'agent rapporte le chemin avec des antislashs doublés
  (`\\Microsoft\\Windows\\...`), d'où le `\\+` dans l'expression. Test en direct sur WIN01 :
  `schtasks /create /tn "\Microsoft\Windows\SocForgeTest\Sys"` donne `100152`, `schtasks /create /tn SocForgeTestPlain`
  donne `100153` (niveau 9) ; une vraie tâche `\Microsoft\Windows\WindowsUpdate\...` a aussi été classée `100152`
  sur DC01. Une tâche malveillante placée dans ce dossier resterait visible au niveau 3, sans alerte.

### T1078 : Valid Accounts
- Source: EventID 4624
- Règle Wazuh: 100178
- Testé en direct le 2026-09-17 : logon réseau (`net use \\10.10.10.109\C$ /user:administrator ...`, LogonType 3) → alerte confirmée : `Rule: 100178 (level 9) -> 'Sigma T1078: Privileged account remote logon — Administrator from 10.10.10.109'`. Capture : [`docs/screenshots/rule-100153-100178-live-rebuild.png`](../../docs/screenshots/rule-100153-100178-live-rebuild.png).
- Faux positifs: Connexions admin légitimes planifiées.

### T1546.013 : PowerShell Profile
- Source: FIM (syscheck), temps réel
- Règle Wazuh: 100186
- La règle était juste, la surveillance FIM ne couvrait pas le fichier. Quatre défauts de config trouvés
  le 2026-09-23 (`wazuh/agents/agent.conf`) :
  1. la config locale par défaut de l'agent déclare déjà `%WINDIR%\System32\WindowsPowerShell\v1.0` avec
     `restrict="powershell.exe$"`, sans temps réel. Le chemin le plus précis l'emporte : l'entrée `realtime`
     posée sur le dossier parent ne couvrait donc jamais `profile.ps1` ;
  2. `%USERPROFILE%` désigne le profil du compte SYSTEM, sous lequel tourne l'agent, pas celui des
     utilisateurs. Remplacé par `C:\Users\*\Documents\WindowsPowerShell` (étendu à `labuser` et `Public`) ;
  3. `report_changes` sur `Program Files` remplissait `queue\diff` jusqu'au quota par défaut (exactement
     1 024 Mo). Le scan FIM s'enlisait (1 s de CPU en 20 s) et le temps réel, qui ne démarre qu'après le
     premier scan, ne démarrait jamais. Program Files reste surveillé en intégrité, sans `report_changes` :
     le scan passe à 5 minutes ;
  4. un `restrict=` redéclaré sur ce même chemin dans `agent.conf` n'est pas pris en compte (test témoin :
     un fichier dans `drivers\etc` est détecté, le profil non). Chemin `v1.0` surveillé en temps réel,
     `recursion_level="0"`, sans `restrict` : les profils machine sont à la racine de `v1.0`.
- Testé en direct le 2026-09-23 sur WIN01 (profil machine, T1546.013), 3 alertes, à la seconde près :
  `added` 15:15:12, `modified` 15:15:46, `deleted` 15:16:14 UTC →
  `Rule: 100186 (level 8) -> 'Sigma T1546.013: PowerShell profile modified — possible persistence'`.
  La suppression sert aussi de nettoyage : les `profile.ps1` laissés par les tests d'août sur WIN01
  (`SocForge-T1546`) et DC01 (`SocForge-T1546-final`) ont été retirés.
  Capture : [`wazuh-rules-100139-100140-100186-live.png`](../../docs/screenshots/wazuh-rules-100139-100140-100186-live.png)

### T1046 : Network Service Discovery
- Source: Sysmon EventID 3 (nécessite Sysmon Sysinternals installé, absent par défaut sur ce snapshot, voir ci-dessous)
- Règle Wazuh: 100101 (connexion unique vers port sensible), 100102 (agrégation ≥10 connexions/5 min depuis la même source)
- Indicateurs: Connexions vers des ports sensibles (RDP, SMB, DB) ; agrégation sur 10 connexions/5 min pour la détection de scan.
- Prérequis découvert en reconstruction : Sysmon (Sysinternals) n'était pas installé sur DC01, seul un
  `sysmon.ocx` Windows sans rapport existait. Installé (`Sysmon64.exe -accepteula -i`) avec la config
  SwiftOnSecurity, qui exclut par défaut la plupart des connexions réseau (bruit réduit), remplacée par une
  config minimale n'excluant aucune connexion (`Sysmon64.exe -c netconfig.xml`, `<NetworkConnect
  onmatch='exclude' />` vide = tout inclus), indispensable pour que EventID 3 soit généré.
- Testé en direct le 2026-09-17 depuis PURPLE (Kali) contre dc01 via `nmap -sT` sur les ports
  21/22/23/25/445/1433/3306/3389/5985/5986 :
  - `Rule: 100101 (level 8) -> 'Sigma T1046: Network connection to a sensitive/admin port — 10.10.10.109:445'`
  - `Rule: 100101 (level 8) -> '... — 10.10.10.109:5985'`
  - 5 scans répétés (10 connexions matchées 100101 en moins de 5 min) →
    `Rule: 100102 (level 10) -> 'Sigma T1046: Multiple ports scanned from the same source — possible port scan'`
- Regroupement par source (2026-10-07) : `100102` ne regroupait pas par adresse, alors que sa description parle de « même source » ; des connexions de machines différentes s'additionnaient. Le champ `win.eventdata.sourceIp` est maintenant imposé (`same_field`). Test : 12 connexions vers `10.10.20.10:445` depuis une seule machine (`10.10.10.61`) donnent 11 alertes `100101` et une alerte `100102` pour cette source.
- Bug de règle trouvé et corrigé : aucun sur 100101/100102 elles-mêmes, le blocage initial venait d'une
  déconnexion transitoire de l'agent dc01 après un redémarrage du manager (résolu par `Restart-Service
  WazuhSvc -Force`, qui force une poignée de main complète). Deux règles voisines avaient en revanche un vrai
  bug de nommage de groupe, corrigé au même moment : voir T1003 et T1547.001 ci-dessous.

### T1059.001 : PowerShell Execution
- Source: EventID 4688 (process creation), 4104 (script block)
- Règle Wazuh: 100120 (processus), 100121 (paramètres suspects), 100131 (contenu du script block)
- Indicateurs: `-enc`, `-EncodedCommand`, `IEX`, `DownloadString`, `-bypass`, `FromBase64String`.
- Prérequis (3, tous indispensables), sans eux Windows ne produit jamais l'événement source :
  ```powershell
  auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
  reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
  ```
  Le premier active les 4688 ; le deuxième y ajoute la ligne de commande (sans quoi 100121 n'a aucun champ
  `commandLine` à inspecter) ; le troisième active les 4104 requis par 100131.
- Bug corrigé sur la règle 100131 : elle chaînait sur `<if_group>windows_powershell</if_group>`, un groupe
  qui n'existe pas dans le ruleset Wazuh (vérifié : aucune occurrence dans `/var/ossec/ruleset/rules/`).
  La règle ne pouvait donc jamais matcher, même avec les 4104 correctement collectés. Corrigé en chaînant sur
  `<if_sid>91802</if_sid>`, la règle parente officielle du canal `Microsoft-Windows-PowerShell/Operational`
  (fichier `0915-win-powershell_rules.xml`), qui garantit que `scriptBlockText` est décodé.
- Testé en direct le 2026-09-17 sur WIN01 (commande encodée bénigne, décodant `SocForgeRuleTest`) :
  - `Rule: 100121 (level 12) -> 'Sigma T1059.001: PowerShell with suspicious parameters (encoded/download cradle/bypass)'`, EventID 4688, `commandLine` contenant `-EncodedCommand JABzAD0A…`
  - `Rule: 100131 (level 12) -> 'Sigma T1059.001: PowerShell ScriptBlock with suspicious content'`, EventID 4104, `scriptBlockText` contenant `FromBase64String('U29jRm9yZ2VSdWxlVGVzdA==')`

  Capture : [`docs/screenshots/rule-100121-100131-powershell-live.png`](../../docs/screenshots/rule-100121-100131-powershell-live.png)
- Faux positifs: 100120 (niveau 8) se déclenche sur tout lancement de PowerShell, y compris les scripts
  d'inventaire de Wazuh lui-même (`secedit /export`, `Get-ADDefaultDomainPasswordPolicy`), observé pendant ce
  test. À filtrer en production sur `parentProcessName`.

### T1110 : Brute Force
- Source: EventID 4625
- Règle Wazuh: 100110 (échec individuel), 100111 (agrégation ≥5/60s même source)
- Indicateurs: >5 échecs sur le même compte en 60 secondes.
- Bug de règle trouvé et corrigé (2026-09-17) : 100111 utilisait `<same_source_ip/>`,
  qui regroupe sur le champ générique `srcip`, jamais peuplé par le décodeur JSON
  générique pour les événements Windows (`win.eventdata.ipAddress` reste un champ
  dynamique distinct, sans alias automatique vers `srcip`). La règle ne groupait donc
  jamais rien, même avec des échecs identiques à la même seconde depuis la même IP.
  Corrigé en `<same_field>win.eventdata.ipAddress</same_field>`, qui permet un
  regroupement sur n'importe quel champ décodé nommé.
- Testé en direct le 2026-09-17 depuis PURPLE (Kali) contre dc01, brute force SMB via
  `netexec smb 10.10.10.109 -u administrator -p pw.txt` (6 mots de passe invalides) :
  - 6× `Rule: 100110 (level 6) -> 'Sigma T1110: Failed logon attempt — administrator'`
  - `Rule: 100111 (level 10) -> 'Sigma T1110: Multiple failed logon attempts from the same source — brute force'`

### T1021.002 : SMB Admin Shares
- Source: EventID 5140
- Règle Wazuh: 100139 (bruit filtré), 100140 (alerte réelle)
- Correction appliquée: exclusion des comptes machine (`$`) et `ANONYMOUS LOGON`, root-causée lors d'une session précédente (651 566 faux positifs avant le fix).
- Testé en direct le 2026-09-17 : `net use \\10.10.10.109\C$ /user:administrator ...` exécuté depuis WIN01
  (10.10.10.110) vers DC01, dans la continuité du mouvement latéral DC01↔WIN01 prévu à l'étape 4 de la
  reconstruction :
  `Rule: 100140 (level 10) -> 'Sigma T1021.002: Real account accessed an admin share — possible lateral movement — Administrator from 10.10.10.110'`.
  Le même accès a aussi retriggé 100178 (T1078) depuis cette nouvelle source, confirmant la détection croisée.
  Rejoué le 2026-09-23 : `IPC$` 14:15:35 et `C$` 14:15:36 UTC, même verdict.
- Bug trouvé et corrigé sur 100139 (2026-09-23) : la règle de bruit n'avait jamais sonné (aucune
  occurrence dans l'historique des alertes). Les 5140 des comptes machine (41 en 40 minutes sur DC01) étaient
  tous pris par la règle officielle 67017 (WEF, niveau 3, fille de 60103), sœur de 100139 au même niveau
  et chargée avant. Son exclusion `IPC$|NetLogon` ne marche pas non plus : en syntaxe OS_Regex, `IPC$` veut
  dire « IPC en fin de chaîne », alors que la valeur réelle est `\\*\IPC$`. Corrigé en chaînant 100139 sur
  `<if_sid>67017</if_sid>`. En direct après rechargement : 7 alertes 100139 (`DESKTOP-75LAKDV$` et
  `WIN-FJ8RP03U8FK$` sur `IPC$`, dont un accès déclenché exprès via une tâche SYSTEM à 15:17:16 UTC).
  Les accès des comptes machine à `SYSVOL` restent sur 67017, ce qui est correct : ce n'est pas un partage
  d'administration.
  Capture : [`wazuh-rules-100139-100140-100186-live.png`](../../docs/screenshots/wazuh-rules-100139-100140-100186-live.png)

- Règle 100141, escalade de 100140 : trois accès à un partage d'administration depuis la même IP en
  deux minutes (`frequency="3" timeframe="120"`, `<same_field>win.eventdata.ipAddress</same_field>`) passent en
  niveau 12. Pourquoi : 100140 (niveau 10) porte l'IP de l'attaquant mais reste sous le seuil de
  confinement automatique de la chaîne SOAR (sévérité TheHive 3, soit niveau ≥ 12), alors que les règles de
  niveau ≥ 12 existantes (100121, 100131, 100155, 100103) sont des événements locaux Sysmon sans aucune IP
  source : aucune alerte ne pouvait à la fois déclencher le confinement et désigner l'adresse à bloquer.
  Prérequis : sous-catégorie d'audit « File Share » activée sur l'hôte
  (`auditpol /set /subcategory:"File Share" /success:enable /failure:enable`) ; elle était sur
  « No Auditing » sur WIN01, donc aucun 5140 n'aurait été journalisé.
- Testé en direct le 2026-10-07, depuis PURPLE, sur WIN01 (`10.10.30.110`) : trois connexions SMB à
  `IPC$` avec le compte local `labuser` (`smbclient -n SOCFORGE-PURPLE`), à 10:01:55, 10:02:11 et 10:02:21
  UTC → `100140 (level 10)` à 10:02:02 et 10:02:12, puis `Rule: 100141 (level 12) -> 'Sigma T1021.002:
  Repeated admin-share access from the same source — lateral movement escalation — 10.10.50.10'` à
  10:02:22 (`win.eventdata.ipAddress` = `10.10.50.10`, agent `WIN01`, MITRE `T1021.002`), soit 27 s après la
  première connexion. Capture : [`wazuh-rule-100141-live.png`](../../docs/screenshots/wazuh-rule-100141-live.png).
  Suite de la chaîne : [SC-14](../../purple-team/scenarios/SC-14-shuffle-soar-workflow.md).

### T1133 : External Remote Services (accès initial depuis la zone non fiable)
- Source: EventID 4624 (Security), types de session 3 et 10
- Règle Wazuh: 100179 (niveau 12)
- Indicateurs: ouverture de session à distance réussie, pour n'importe quel compte, depuis `10.10.50.0/24` (zone
  attaquant). Aucune session légitime ne part de cette zone ; la règle `100178` (comptes privilégiés
  seulement) ne couvrait pas un compte ordinaire comme `labuser`.
- Testé en direct le 2026-10-07 : les trois connexions de l'attaque ci-dessus ont chacune déclenché
  `Rule: 100179 (level 12) -> 'Sigma T1133: Successful remote logon from the untrusted zone — labuser from
  10.10.50.10'` (10:02:02, 10:02:12, 10:02:22), dès la première connexion. Même capture.

### T1027 : Obfuscated Files or Information
- Source: Sysmon EventID 1
- Règle Wazuh: 100127
- Indicateurs: `commandLine` contenant un pattern Base64 (≥100 caractères) ou `FromBase64String`.
- Confirmé en direct le 2026-09-17 : le même test que T1059.001 a également déclenché
  `Rule: 100127 (level 10) -> 'Sigma T1027: Base64-encoded pattern in command line — possible obfuscation'`
  (7 déclenchements). C'est le comportement attendu : une commande encodée est simultanément de
  l'exécution PowerShell et de l'obfuscation, la corrélation des deux règles renforce le verdict.

### T1003 : Credential Dumping
- Source: Sysmon EventID 10
- Règle Wazuh: 100103
- Indicateurs: Accès mémoire LSASS avec `GrantedAccess` 0x1010/0x1410.
- Bug de règle trouvé et corrigé (2026-09-17) : chaînait sur `<if_group>sysmon_event10</if_group>`, groupe
  inexistant (confirmé par `wazuh-logtest` : *"Group 'sysmon_event10' was not found. Invalid 'if_group'.
  Rule '100103' will be ignored."*). Le ruleset Wazuh nomme les groupes des EventID à deux chiffres avec un
  underscore (`sysmon_event_10`, pas `sysmon_event10`), les EventID à un chiffre n'en ont pas
  (`sysmon_event3`, `sysmon_event8`…), incohérence de convention qui piège facilement une règle custom.
  Corrigé en `<if_group>sysmon_event_10</if_group>`.
- Deuxième bug trouvé et corrigé le 2026-09-18 : même après la correction du nom de groupe, la règle ne se
  déclenchait toujours pas. Root cause identique à 100147 (voir T1547.001 ci-dessous) :
  `<if_group>sysmon_event_10</if_group>` ne déclenche pas cette règle custom sur ce manager, même avec le
  groupe correctement tagué. Confirmé par comparaison avec la règle officielle équivalente 92900
  (`0945-sysmon_id_10.xml`), qui filtre déjà `targetImage=lsass.exe` et `grantedAccess` (0x1010|0x40) et
  exclut les sources `Program Files`/`wmiprvse.exe`. Corrigé en chaînant directement sur
  `<if_sid>92900</if_sid>`, rendant les champs `targetImage`/`grantedAccess` de 100103 redondants.
- Testé en direct le 2026-09-18 : `OpenProcess` sur `lsass.exe` avec les droits `PROCESS_QUERY_INFORMATION
  | PROCESS_VM_READ` (0x1010) exécuté depuis un cmd élevé sur WIN01 → `Handle: 0`, `False` (accès refusé par
  l'OS). Découverte réelle, pas une limitation : `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v
  RunAsPPL` confirme `RunAsPPL = 0x2`, la protection LSA (Credential Guard-lite) est active sur WIN01.
  Vérification par `wevtutil` sur les 15 derniers événements Sysmon EventID 10 : aucun ne correspond à notre
  tentative (le plus récent date d'avant le test). RunAsPPL rejette l'accès à un stade du noyau
  (vérification du niveau de signature du processus protégé, `PsOpenProcess`) antérieur au callback
  `ObRegisterCallbacks` que Sysmon utilise pour générer l'EventID 10, la tentative n'est donc jamais visible
  par Sysmon, quel que soit le compte appelant (même testé en Administrator). C'est le comportement attendu
  d'un vrai outil de credential dumping (Mimikatz, etc.) contre cette protection : elle bloque l'attaque
  avant même que la télémétrie puisse l'observer.
- Validée en direct le 2026-09-23, sur DC01 (Windows Server n'active pas `RunAsPPL` par défaut, vérifié
  avant tout test : les trois clés `RunAsPPL`/`RunAsPPLBoot`/`LsaCfgFlags` sont absentes). Défaut trouvé en
  chemin : la config Sysmon de DC01, installée pour le scénario réseau, n'avait aucune règle
  `ProcessAccess`, corrigé en ajoutant un groupe ciblant `lsass.exe`. Premier essai avec le masque
  `0x0410` (`QUERY_INFORMATION|VM_READ`) : Windows y ajoute automatiquement `QUERY_LIMITED_INFORMATION`,
  Sysmon journalise `0x1410`, que la règle officielle 92900 ne reconnaît pas (elle attend `0x1010` ou
  `0x40`). Corrigé en utilisant le masque `0x1010` (`QUERY_LIMITED_INFORMATION|VM_READ`), celui réellement
  utilisé par les outils de dump type Mimikatz →
  `Rule: 100103 (level 14) -> sourceImage=powershell.exe, targetImage=lsass.exe, grantedAccess=0x1010`,
  2 s après la tentative. Les journaux montrent aussi Windows Defender (`MsMpEng.exe`) accéder à `lsass.exe`
  avec `0x101000`, capté par la même règle, un vrai comportement d'antivirus, pas une menace, qui confirme
  sa sensibilité. Capture : [`wazuh-dashboard-rule-100103-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100103-live.png).
  Voir `purple-team/scenarios/SC-11-T1003-lsass-access.md` pour le détail complet des deux tentatives.

### T1547.001 : Registry Run Keys
- Source: Sysmon EventID 13/14
- Règle Wazuh: 100147
- Indicateurs: Modification des clés `CurrentVersion\Run`, `Winlogon`.
- Trois bugs successifs trouvés et corrigés (2026-09-17/18), du plus superficiel au plus profond :
  1. Groupe `sysmon_event13,sysmon_event14` inexistant (underscore manquant, virgule invalide comme
     séparateur OR), corrigé en `sysmon_event_13|sysmon_event_14`.
  2. Faux départ d'infrastructure : le scan FIM sur WIN01 restait bloqué "in progress" (0% CPU en continu)
     à cause de fichiers `.gz` orphelins dans `queue\diff\file\`, laissés par des redémarrages forcés
     antérieurs pendant qu'un scan tournait. Nettoyé (`queue\diff\file\` + `queue\fim\db\fim.db`
     supprimés). Ce n'était en réalité pas le bon chemin : 100147 dépend de Sysmon EventID 13, pas du
     FIM/syscheck, tout ce travail a confirmé un vrai bug d'infrastructure séparé, mais n'était pas la
     cause du non-déclenchement de la règle. Le 2026-09-23, la vraie cause de ce blocage FIM a été
     trouvée : `report_changes` activé sur tout `Program Files` remplissait `queue\diff` jusqu'au quota
     de 1 Go, et le scan s'enlisait. Le nettoyage de l'époque n'avait fait que repousser le problème
     (voir T1546.013 ci-dessus).
  3. Root cause réelle : sur ce manager et à ce moment précis, `<if_group>sysmon_event_13</if_group>`
     ne déclenchait pas cette règle custom, alors que le groupe était bien tagué (la règle officielle 92300,
     qui en dépend, matchait). Confirmé par test A/B : une règle de debug chaînée sur
     `<if_sid>92300</if_sid>` matchait immédiatement, la même règle avec `<if_group>sysmon_event_13</if_group>`
     jamais, sans le moindre avertissement au chargement. Point de prudence : d'autres règles de ce fichier
     (100127, 100153, 100178…) utilisent `if_group` avec succès et ont été validées en direct la même
     session, donc `if_group` n'est pas cassé en général sur ce manager ; quelque chose de spécifique à ce
     cas (peut-être un état résiduel du crash `wazuh-db` rencontré juste avant, voir plus haut) a empêché
     ce chaînage précis de fonctionner. Corrigé en chaînant 100147 directement sur
     `<if_sid>92300</if_sid>` (`0860-sysmon_id_13.xml`), qui filtre déjà sur `CurrentVersion\Run` et ses
     variantes WOW6432Node, rendant le field regex superflu, et plus robuste dans tous les cas.
- Testé en direct le 2026-09-18 : `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v
  SocForgeTest12 ...` sur WIN01 →
  `Rule: 100147 (level 9) -> 'Sigma T1547.001: Registry autostart persistence — HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SocForgeTest12'`.
  Capture (dashboard Wazuh, 2 correspondances) :
  [`wazuh-dashboard-rule-100147-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100147-live.png)

### T1055 : Process Injection
- Source: Sysmon EventID 8
- Règle Wazuh: 100155
- Indicateurs: `CreateRemoteThread` vers n'importe quel processus cible.
- Même bug `if_group` que 100103/100147, trouvé et corrigé le 2026-09-18 : chaînait sur
  `<if_group>sysmon_event8</if_group>`, qui ne déclenchait jamais cette règle custom. Aucune règle officielle
  générique n'existe pour EventID 8 (92400/92401/92402/92403 sont chacune limitées à un processus cible
  précis : explorer.exe, mstsc.exe, svchost.exe, lsass.exe), corrigé en chaînant sur `<if_sid>185006</if_sid>`,
  la règle de base niveau 0 (`0330-sysmon_rules.xml`) qui tague tout EventID 8 avec `sysmon_event8`.
- Testé en direct le 2026-09-18 : script PowerShell encodé en Base64 lançant `notepad.exe` puis injectant
  un thread distant via `OpenProcess` + `CreateRemoteThread` pointant sur `kernel32!Sleep` (technique bénine
  standard de test EDR, ne charge aucun shellcode, appelle juste une fonction Win32 légitime déjà mappée
  dans le processus cible). Résultat console : `Target handle: True` / `Remote thread handle: True` / `Done` :
  l'injection a réellement réussi (notepad.exe n'est pas protégé par PPL, contrairement à lsass.exe). Alerte
  confirmée sur le manager :
  `Rule: 100155 (level 13) -> 'Sigma T1055: CreateRemoteThread into another process — possible process injection — C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -> ...\Notepad.exe'`
  avec `StartFunction: Sleep` correspondant exactement à notre test. Capture (dashboard Wazuh, 17 correspondances) :
  [`wazuh-dashboard-rule-100155-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100155-live.png)

---

## Niveaux de sévérité Wazuh

| Niveau | Règles                                    |
|--------|-------------------------------------------|
| 14     | 100103                                    |
| 13     | 100155                                    |
| 12     | 100121, 100131, 100141, 100179            |
| 10     | 100102, 100111, 100127, 100140            |
| 9      | 100147, 100153, 100178                    |
| 8      | 100101, 100120, 100186                    |
| 6      | 100110                                    |
| 3      | 100139, 100152 (bruit enregistré sans alerte) |
