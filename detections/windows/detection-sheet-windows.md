# Fiche de détection : Windows (DC01 et WIN01)

Les règles Windows du lab, avec pour chacune sa source de journaux, ses prérequis, le test fait en direct et les
défauts trouvés en la testant. Toutes ont été redéployées sur un manager Wazuh remis à neuf le 2026-09-17, puis
testées une à une : aucune entrée n'est reprise de la première version du projet sans vérification.

Le fichier de règles est [`wazuh/rules/socforge_sigma_rules.xml`](../../wazuh/rules/socforge_sigma_rules.xml) ; la
forme Sigma des détections principales est dans [`detections/sigma/`](../sigma/).

## Vue d'ensemble

| Technique | Règles | Niveau | Source | Fiche |
|---|---|---|---|---|
| T1053.005 Tâche planifiée | 100153 (100152 pour le dossier système) | 9 (3) | Security 4698, 4702 | SC-01 |
| T1078 Compte privilégié à distance | 100178 | 9 | Security 4624 | SC-02, SC-08 |
| T1133 Session depuis la zone attaquant | 100179 | 12 | Security 4624 | SC-14 |
| T1021.002 Partages d'administration | 100140, 100141 (100139 pour le bruit) | 10, 12 (3) | Security 5140 | SC-03, SC-08, SC-14 |
| T1059.001 PowerShell | 100120, 100121, 100131 | 8, 12, 12 | Security 4688, PowerShell 4104 | SC-04 |
| T1027 Commande encodée | 100127 | 10 | Sysmon 1 | SC-04 |
| T1046 Scan de ports | 100101, 100102 | 8, 10 | Sysmon 3 | SC-05 |
| T1110 Force brute | 100110, 100111 | 6, 10 | Security 4625 | SC-06 |
| T1547.001 Clé Run | 100147 | 9 | Sysmon 13 | SC-09 |
| T1055 Injection de processus | 100155 | 13 | Sysmon 8 | SC-10 |
| T1003 Accès à LSASS | 100103 | 14 | Sysmon 10 | SC-11 |
| T1546.013 Profil PowerShell | 100186 | 8 | surveillance d'intégrité | ci-dessous |

## Journaux collectés

| Source | Canal | Événements utiles |
|---|---|---|
| Windows Security | Security | 4624, 4625, 4634, 4648, 4688, 4698, 4702, 4720-4726, 5140 |
| PowerShell | Microsoft-Windows-PowerShell/Operational | 4103, 4104, 4105, 4106 |
| Sysmon | Microsoft-Windows-Sysmon/Operational | 1, 2, 3, 5, 7, 8, 10, 11, 12-14, 15, 17-18, 22 |
| Windows Defender | Microsoft-Windows-Windows Defender/Operational | 1116, 1117, 1006, 1007 |

## Captures du tableau de bord Wazuh

- Vue d'ensemble sur 24 h (3 956 événements, dix premières techniques MITRE) :
  [`wazuh-dashboard-threat-hunting-overview.png`](../../docs/screenshots/wazuh-dashboard-threat-hunting-overview.png)
- WIN01, règles `100120`, `100121`, `100127`, `100131`, `100153`, `100178`, 26 correspondances :
  [`wazuh-dashboard-win01-powershell-events.png`](../../docs/screenshots/wazuh-dashboard-win01-powershell-events.png)
- DC01, règles `100153` et `100178`, 11 correspondances :
  [`wazuh-dashboard-dc01-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-events.png)
- DC01, scan depuis PURPLE (`100101`, `100102`, `100110`, `100111`), 60 correspondances :
  [`wazuh-dashboard-dc01-scan-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-scan-events.png)
- DC01, force brute SMB depuis PURPLE (`100110`, `100111`), 13 correspondances :
  [`wazuh-dashboard-dc01-bruteforce-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-bruteforce-events.png)
- Règles `100139`, `100140`, `100186`, le 23/09 de 14:10 à 15:20 UTC, 12 correspondances :
  [`wazuh-rules-100139-100140-100186-live.png`](../../docs/screenshots/wazuh-rules-100139-100140-100186-live.png)
- Attaque du 07/10, règles `100179`, `100140`, `100141` :
  [`wazuh-rule-100141-live.png`](../../docs/screenshots/wazuh-rule-100141-live.png)

---

## T1053.005 : tâche planifiée

- Source : Security 4698 et 4702. Règles : 100153 (niveau 9), 100152 (niveau 3).
- Prérequis : sous-catégorie d'audit « Other Object Access Events » activée
  (`auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`). Sans elle, Windows
  n'écrit pas l'événement.
- Test du 2026-09-17, sur DC01 : `schtasks /create /tn SocForgeRebuildTest /tr calc.exe /sc once /st 23:59 /f`
  donne `Rule: 100153 (level 9) -> 'Sigma T1053: Scheduled task created/modified — \SocForgeRebuildTest'`.
  Capture : [`rule-100153-100178-live-rebuild.png`](../../docs/screenshots/rule-100153-100178-live-rebuild.png).
- Bruit : Windows réécrit lui-même des tâches sous `\Microsoft\Windows\` (mises à jour, maintenance). Sur
  l'historique du lab, cela faisait de 100153 la règle Windows la plus bavarde, avec 118 alertes de niveau 9.
- Réglage du 2026-10-07 : la règle 100152 (niveau 3) enregistre ces tâches sans alerter, et 100153 garde les
  autres. Piège rencontré : l'agent rapporte le chemin avec des antislashs doublés
  (`\\Microsoft\\Windows\\...`), d'où le `\\+` dans l'expression. Test sur WIN01 :
  `schtasks /create /tn "\Microsoft\Windows\SocForgeTest\Sys"` donne 100152,
  `schtasks /create /tn SocForgeTestPlain` donne 100153. Une vraie tâche `\Microsoft\Windows\WindowsUpdate\...` a
  aussi été classée 100152 sur DC01. Conséquence à connaître : une tâche placée dans ce dossier reste enregistrée,
  mais au niveau 3.

## T1078 : compte privilégié à distance

- Source : Security 4624, types de session 3 et 10. Règle : 100178 (niveau 9).
- Condition : le nom du compte contient `administrator`, `admin` ou `svc_`.
- Test du 2026-09-17 : `net use \\10.10.10.109\C$ /user:administrator ...` donne
  `Rule: 100178 (level 9) -> 'Sigma T1078: Privileged account remote logon — Administrator from 10.10.10.109'`.
  Capture : [`rule-100153-100178-live-rebuild.png`](../../docs/screenshots/rule-100153-100178-live-rebuild.png).
- Bruit attendu : les sessions d'administration légitimes.

## T1133 : session depuis la zone attaquant

- Source : Security 4624, types 3 et 10. Règle : 100179 (niveau 12).
- Condition : une ouverture de session à distance réussit depuis `10.10.50.0/24`, pour n'importe quel compte.
  Aucune session légitime ne part de cette zone. La règle 100178 ne couvrait pas un compte ordinaire comme
  `labuser`.
- Test du 2026-10-07 : les trois connexions de l'attaque de SC-14 ont chacune donné
  `Rule: 100179 (level 12) -> 'Sigma T1133: Successful remote logon from the untrusted zone — labuser from
  10.10.50.10'` (10:02:02, 10:02:12, 10:02:22), dès la première connexion.

## T1021.002 : partages d'administration

- Source : Security 5140. Règles : 100140 (niveau 10), 100141 (niveau 12), 100139 (niveau 3, bruit).
- Prérequis : sous-catégorie d'audit « File Share » activée
  (`auditpol /set /subcategory:"File Share" /success:enable /failure:enable`). Elle était sur « No Auditing » sur
  WIN01.
- Séparation du bruit : les comptes machine (`NOM$`) et `ANONYMOUS LOGON` accèdent en permanence à ces partages.
  La première version de la règle avait produit 651 566 alertes. Ces accès vont maintenant dans 100139, les autres
  dans 100140. Détail dans SC-03.
- Test du 2026-09-17, de WIN01 vers DC01 : `net use \\10.10.10.109\C$ /user:administrator ...` donne
  `Rule: 100140 (level 10) -> 'Sigma T1021.002: Real account accessed an admin share — possible lateral movement —
  Administrator from 10.10.10.110'`. Le même accès déclenche aussi 100178. Rejoué le 2026-09-23 : `IPC$` à
  14:15:35 et `C$` à 14:15:36 UTC.
- Défaut trouvé sur 100139 (2026-09-23) : elle n'avait jamais sonné. Les accès des comptes machine étaient tous
  pris par la règle officielle 67017, de même niveau et chargée avant. 100139 est maintenant rattachée à 67017.
  Après rechargement : 7 alertes 100139. Détail dans SC-03.
  Capture : [`wazuh-rules-100139-100140-100186-live.png`](../../docs/screenshots/wazuh-rules-100139-100140-100186-live.png)
- Règle 100141 : trois accès depuis la même adresse en deux minutes (`frequency="3" timeframe="120"`,
  `<same_field>win.eventdata.ipAddress</same_field>`) passent au niveau 12. Raison : 100140 porte l'adresse de
  l'attaquant mais reste sous le seuil de réponse automatique de la chaîne SOAR (niveau 12), et les autres règles
  de niveau 12 ou plus (100121, 100131, 100155, 100103) décrivent des événements locaux, sans adresse source.
  Aucune alerte ne pouvait à la fois déclencher la réponse et désigner l'adresse à bloquer.
- Test du 2026-10-07, depuis PURPLE vers WIN01 (`10.10.30.110`) : trois connexions SMB à `IPC$` avec le compte
  local `labuser` (`smbclient -n SOCFORGE-PURPLE`), à 10:01:55, 10:02:11 et 10:02:21 UTC. Résultat : 100140 à
  10:02:02 et 10:02:12, puis `Rule: 100141 (level 12) -> 'Sigma T1021.002: Repeated admin-share access from the
  same source — lateral movement escalation — 10.10.50.10'` à 10:02:22, soit 27 s après la première connexion.
  Capture : [`wazuh-rule-100141-live.png`](../../docs/screenshots/wazuh-rule-100141-live.png). La suite est dans
  [SC-14](../../purple-team/scenarios/SC-14-shuffle-soar-workflow.md).

## T1059.001 : PowerShell

- Sources : Security 4688 (création de processus), PowerShell 4104 (contenu du script).
  Règles : 100120 (tout lancement, niveau 8), 100121 (paramètres suspects, niveau 12), 100131 (contenu du script,
  niveau 12).
- Motifs : `-enc`, `-EncodedCommand`, `IEX`, `DownloadString`, `-bypass`, `FromBase64String`.
- Prérequis, tous nécessaires :
  ```powershell
  auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
  reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
  ```
  Le premier active les 4688, le deuxième y ajoute la ligne de commande, le troisième active les 4104.
- Défaut corrigé sur 100131 : elle dépendait du groupe `windows_powershell`, qui n'existe pas dans le jeu de
  règles de Wazuh. Elle ne pouvait donc jamais sonner. Elle est maintenant rattachée à la règle officielle 91802
  (`0915-win-powershell_rules.xml`).
- Test du 2026-09-17 sur WIN01, avec une commande encodée bénigne qui décode `SocForgeRuleTest` :
  - `Rule: 100121 (level 12) -> 'Sigma T1059.001: PowerShell with suspicious parameters (encoded/download cradle/bypass)'`
  - `Rule: 100131 (level 12) -> 'Sigma T1059.001: PowerShell ScriptBlock with suspicious content'`

  Capture : [`rule-100121-100131-powershell-live.png`](../../docs/screenshots/rule-100121-100131-powershell-live.png)
- Bruit : 100120 sonne sur tout lancement de PowerShell, y compris les scripts d'inventaire de Wazuh
  (`secedit /export`, `Get-ADDefaultDomainPasswordPolicy`). À filtrer en production sur le processus parent.

## T1027 : commande encodée

- Source : Sysmon 1. Règle : 100127 (niveau 10).
- Condition : la ligne de commande contient `FromBase64String` ou une suite Base64 d'au moins 100 caractères.
- Test du 2026-09-17 : le test de T1059.001 a aussi déclenché
  `Rule: 100127 (level 10) -> 'Sigma T1027: Base64-encoded pattern in command line — possible obfuscation'`
  (7 fois). C'est attendu : une commande encodée relève des deux techniques, et les deux alertes se confirment.

## T1046 : scan de ports

- Source : Sysmon 3. Règles : 100101 (une connexion vers un port sensible, niveau 8), 100102 (dix connexions en
  cinq minutes depuis la même source, niveau 10).
- Prérequis : Sysmon n'était pas installé sur DC01. La configuration SwiftOnSecurity exclut la plupart des
  connexions réseau ; elle a été remplacée par une configuration qui les garde toutes
  ([`sysmon/sysmon-config-dc01.xml`](../../sysmon/sysmon-config-dc01.xml)).
- Test du 2026-09-17, depuis PURPLE : `nmap -sT` sur les ports 21, 22, 23, 25, 445, 1433, 3306, 3389, 5985, 5986
  de DC01 donne 100101 pour les ports 445 et 5985 ; cinq scans répétés donnent
  `Rule: 100102 (level 10) -> 'Sigma T1046: Multiple ports scanned from the same source — possible port scan'`.
- Correction du 2026-10-07 : 100102 ne regroupait pas par adresse, alors que sa description parle de « même
  source » ; des connexions de machines différentes s'additionnaient. Le champ `win.eventdata.sourceIp` est
  maintenant imposé (`same_field`). Test : 12 connexions vers `10.10.20.10:445` depuis une seule machine
  (`10.10.10.61`) donnent 11 alertes 100101 et une alerte 100102 pour cette source.

## T1110 : force brute

- Source : Security 4625. Règles : 100110 (un échec, niveau 6), 100111 (cinq échecs en soixante secondes depuis
  la même adresse, niveau 10).
- Défaut corrigé le 2026-09-17 : 100111 utilisait `<same_source_ip/>`, qui lit le champ `srcip`. Le décodeur des
  événements Windows ne le remplit pas, donc la règle ne regroupait rien. Remplacé par
  `<same_field>win.eventdata.ipAddress</same_field>`.
- Test du 2026-09-17, depuis PURPLE : `netexec smb 10.10.10.109 -u administrator -p pw.txt` avec six mots de passe
  faux donne six alertes 100110 puis
  `Rule: 100111 (level 10) -> 'Sigma T1110: Multiple failed logon attempts from the same source — brute force'`.

## T1547.001 : clé Run

- Source : Sysmon 13. Règle : 100147 (niveau 9), rattachée à la règle officielle 92300.
- Test du 2026-09-18 sur WIN01 : `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v SocForgeTest12 ...`
  donne `Rule: 100147 (level 9) -> 'Sigma T1547.001: Registry autostart persistence —
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SocForgeTest12'`.
  Capture : [`wazuh-dashboard-rule-100147-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100147-live.png)
- Trois corrections ont été nécessaires (détail dans SC-09) : un nom de groupe faux, un scan d'intégrité bloqué
  qui s'est révélé une fausse piste, puis la cause, un rattachement par groupe qui ne déclenchait pas la règle. La
  cause du scan bloqué a été trouvée le 2026-09-23 : `report_changes` activé sur tout `Program Files` remplissait
  `queue\diff` jusqu'au quota de 1 Go.
- Point de prudence : d'autres règles du même fichier (100127, 100153, 100178) utilisent `if_group` et
  fonctionnent. Le rattachement par groupe n'est donc pas défaillant en général sur ce manager ; il l'était pour
  ces règles Sysmon. Le rattachement direct à la règle officielle évite la question.

## T1055 : injection de processus

- Source : Sysmon 8. Règle : 100155 (niveau 13), rattachée à la règle de base 185006.
- Condition : tout thread créé dans un autre processus, sans filtre.
- Défaut corrigé le 2026-09-18 : même problème de rattachement par groupe que 100147. Aucune règle officielle ne
  couvre l'événement 8 en général (92400 à 92403 visent chacune un processus précis), d'où le rattachement à
  185006.
- Test du 2026-09-18 sur WIN01 : un script lance `notepad.exe` puis y crée un thread qui appelle
  `kernel32!Sleep`, sans écrire de code dans la cible. Résultat :
  `Rule: 100155 (level 13) -> 'Sigma T1055: CreateRemoteThread into another process — possible process injection —
  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -> ...\Notepad.exe'`, avec `StartFunction: Sleep`.
  Capture (17 correspondances) :
  [`wazuh-dashboard-rule-100155-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100155-live.png)

## T1003 : accès à LSASS

- Source : Sysmon 10. Règle : 100103 (niveau 14), rattachée à la règle officielle 92900.
- Deux corrections : le groupe cité s'appelait `sysmon_event10` au lieu de `sysmon_event_10` (confirmé par
  `wazuh-logtest`), puis le rattachement par groupe ne déclenchait pas la règle. La règle officielle 92900 filtre
  déjà la cible `lsass.exe` et les masques d'accès `0x1010` et `0x40`.
- Sur WIN01 (2026-09-18) : la demande d'accès est refusée par Windows (`Handle: 0`). `RunAsPPL` vaut `0x2` : la
  protection de LSASS est active, et le refus a lieu avant que Sysmon soit prévenu. Aucune alerte, et c'est
  correct.
- Sur DC01 (2026-09-23), où la protection n'est pas activée : après ajout d'une règle `ProcessAccess` à la
  configuration Sysmon et avec le masque `0x1010`, la règle sonne 2 s après la tentative
  (`sourceImage=powershell.exe, targetImage=lsass.exe, grantedAccess=0x1010`).
  Capture : [`wazuh-dashboard-rule-100103-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100103-live.png)
- Détail des deux tentatives : [SC-11](../../purple-team/scenarios/SC-11-T1003-lsass-access.md).

## T1546.013 : profil PowerShell

- Source : surveillance d'intégrité en temps réel. Règle : 100186 (niveau 8).
- La règle était correcte, mais la surveillance ne couvrait pas le fichier. Quatre défauts de configuration,
  trouvés le 2026-09-23 dans [`wazuh/agents/agent.conf`](../../wazuh/agents/agent.conf) :
  1. la configuration locale de l'agent déclare déjà `%WINDIR%\System32\WindowsPowerShell\v1.0` avec
     `restrict="powershell.exe$"`, sans temps réel. Le chemin le plus précis l'emporte : l'entrée posée sur le
     dossier parent ne couvrait donc jamais `profile.ps1` ;
  2. `%USERPROFILE%` désigne le profil du compte SYSTEM, sous lequel tourne l'agent, pas celui des utilisateurs.
     Remplacé par `C:\Users\*\Documents\WindowsPowerShell` ;
  3. `report_changes` sur `Program Files` remplissait `queue\diff` jusqu'au quota (1 024 Mo). Le scan
     s'enlisait, et le temps réel, qui ne démarre qu'après le premier scan, ne démarrait jamais. `Program Files`
     reste surveillé, sans `report_changes` : le scan dure 5 minutes ;
  4. un `restrict=` redéclaré sur ce chemin dans `agent.conf` n'est pas pris en compte. Le dossier `v1.0` est
     surveillé en temps réel, sans `restrict`, avec `recursion_level="0"`.
- Test du 2026-09-23 sur WIN01 (profil machine) : trois alertes à la seconde près, `added` à 15:15:12,
  `modified` à 15:15:46, `deleted` à 15:16:14 UTC, toutes
  `Rule: 100186 (level 8) -> 'Sigma T1546.013: PowerShell profile modified — possible persistence'`.
  La suppression a aussi servi de nettoyage : les `profile.ps1` laissés par les tests d'août sur WIN01 et DC01 ont
  été retirés.
  Capture : [`wazuh-rules-100139-100140-100186-live.png`](../../docs/screenshots/wazuh-rules-100139-100140-100186-live.png)

---

## Niveaux

| Niveau | Règles |
|---|---|
| 14 | 100103 |
| 13 | 100155 |
| 12 | 100121, 100131, 100141, 100179 |
| 10 | 100102, 100111, 100127, 100140 |
| 9 | 100147, 100153, 100178 |
| 8 | 100101, 100120, 100186 |
| 6 | 100110 |
| 3 | 100139, 100152 (bruit enregistré sans alerte) |

Les alertes de niveau 10 ou plus partent vers la chaîne SOAR ; celles de niveau 12 ou plus peuvent déclencher la
réponse automatique (voir SC-14).
