# SC-04 : T1059.001, PowerShell encodé (EncodedCommand)

| | |
|---|---|
| Date | 2026-09-17 (reconstruction) |
| Lancé depuis | console locale de WIN01, compte `labuser`, PowerShell élevée |
| Cible | WIN01 (agent Wazuh 005) |
| Technique MITRE | T1059.001, Command and Scripting Interpreter: PowerShell |
| Tactiques | Execution, Defense Evasion |
| Résultat | détecté par 100121 et 100131 (niveau 12), après correction d'un défaut sur 100131 |

## Objectif

Vérifier que PowerShell est surveillé par deux sources qui se complètent :

- la ligne de commande du processus (événement 4688), lue par la règle 100121 ;
- le contenu du script réellement exécuté (événement 4104), lu par la règle 100131.

Avec `-EncodedCommand`, la charge n'apparaît pas en clair dans la ligne de commande. La première source voit donc
l'option d'encodage, la seconde voit le code une fois décodé.

## Prérequis

Trois réglages ont dû être activés sur WIN01. Sans eux, Windows ne produit pas les événements sources et les
règles restent muettes, sans aucune erreur.

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

Le premier active les 4688, le deuxième y ajoute la ligne de commande, le troisième active les 4104.

Contrôle côté poste :

```powershell
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 6 | Select-Object Id,TimeCreated
```

Six événements `4104`, datés de la seconde du test.

## Test

La charge est volontairement bénigne : elle décode une chaîne Base64 et l'affiche. Elle a la forme technique d'une
commande encodée (encodage et `FromBase64String`) sans rien faire d'offensif.

Commande décodée :

```powershell
$s=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('U29jRm9yZ2VSdWxlVGVzdA==')); Write-Output $s
```

Commande exécutée (UTF-16LE puis Base64, 328 caractères) :

```powershell
powershell.exe -EncodedCommand JABzAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgA…
```

Sortie : `SocForgeRuleTest`. La charge s'est bien décodée et exécutée.

## Détection

| Règle | Niveau | Événement | Champ lu | Heure (UTC) |
|---|---|---|---|---|
| 100120 | 8 | 4688 | `newProcessName` | 18:05:58 |
| 100121 | 12 | 4688 | `commandLine` | 18:05:58 |
| 100131 | 12 | 4104 | `scriptBlockText` | 18:06:08 |
| 100127 | 10 | Sysmon 1 | `commandLine` | - |

Extraits d'`alerts.log` :

```
2026 Sep 17 18:05:58 (WIN01) any->EventChannel
Rule: 100121 (level 12) -> 'Sigma T1059.001: PowerShell with suspicious parameters (encoded/download cradle/bypass)'

2026 Sep 17 18:06:08 (WIN01) any->EventChannel
Rule: 100131 (level 12) -> 'Sigma T1059.001: PowerShell ScriptBlock with suspicious content'
```

Capture : [`rule-100121-100131-powershell-live.png`](../../docs/screenshots/rule-100121-100131-powershell-live.png)

## Défaut trouvé et corrigé sur 100131

Au premier passage, 100121 a sonné mais pas 100131. Pourtant les 4104 existaient sur le poste et l'agent les
collectait (`agent.conf`, `Event[System[(EventID=4104 or …)]]`).

Cause : la règle dépendait de `<if_group>windows_powershell</if_group>`, un groupe qui n'existe pas dans le jeu de
règles de Wazuh (aucune occurrence dans `/var/ossec/ruleset/rules/`). Une règle qui cite un groupe inconnu ne
provoque aucune erreur au chargement : elle ne se déclenche simplement jamais. C'est une panne silencieuse, et la
raison pour laquelle chaque règle du lab est testée en conditions réelles.

Correction : la règle est rattachée à `<if_sid>91802</if_sid>`, la règle officielle du canal
`Microsoft-Windows-PowerShell/Operational` (`0915-win-powershell_rules.xml`), qui garantit la présence du champ
`scriptBlockText`. Après redémarrage du manager, le test rejoué a déclenché 100131.

## Méthode de vérification

Les recherches dans `alerts.log` portent sur le texte de la description, avec une classe de caractères
(`susp[i]cious`), et non sur le numéro de règle. Raison : toute commande tapée sur le manager est journalisée par
`sudo` et peut revenir dans `alerts.log` par la règle 100200. Une recherche naïve retrouve alors sa propre
commande. Ce piège a été observé (alertes de 16:12 contenant la commande de recherche) ; le motif protégé l'évite.

Chaque alerte est validée sur son contexte complet (agent, événement, champ lu), jamais sur un simple comptage.

## Lecture côté défense

Le 4688 montre la ligne de commande, donc l'option d'encodage. Le 4104 montre le script une fois décodé,
c'est-à-dire ce qui s'exécute vraiment. Avoir les deux évite de dépendre d'un seul réglage d'audit. La règle
`100120` (niveau 8) signale tout lancement de PowerShell et sert de contexte ; l'alerte utile est `100121` ou
`100131`, au niveau 12. Le test est lancé sur la console de WIN01 : il suppose un accès déjà obtenu.

## Nettoyage

Aucun artefact : la charge n'écrit rien sur le disque et ne crée aucune persistance. Les trois réglages d'audit
sont conservés, ils font partie de la configuration de détection du poste.
