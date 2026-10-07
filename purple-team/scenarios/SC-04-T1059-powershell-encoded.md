# SC-04 : T1059.001, PowerShell encodé (EncodedCommand)

Session : Reconstruction, 2026-09-17
Attaquant : Console locale WIN01 (`labuser`, PowerShell élevée)
Cible : WIN01 (agent Wazuh ID 005)
MITRE : T1059.001, Command and Scripting Interpreter: PowerShell
Tactiques : Execution / Defense Evasion

---

## Objectif

Vérifier que la chaîne de détection PowerShell fonctionne de bout en bout sur les deux
sources complémentaires :

- la ligne de commande du processus (EventID 4688) → règle 100121
- le contenu du script réellement exécuté (EventID 4104) → règle 100131

Un attaquant utilise `-EncodedCommand` précisément pour que la charge utile n'apparaisse
pas en clair dans la ligne de commande. Les deux sources sont donc nécessaires : la
première voit l'indicateur d'encodage, la seconde voit le code décodé.

## Pré-requis (établis pendant ce test)

Les trois réglages ci-dessous ont dû être activés sur WIN01, sans eux Windows ne génère
jamais l'événement source, et les règles restent muettes sans qu'aucune erreur n'apparaisse.

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

Vérification que les 4104 sont bien produits côté hôte :

```powershell
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 6 | Select-Object Id,TimeCreated
```

→ 6 événements `4104` horodatés à la seconde du test.

## Charge utile

Charge volontairement bénigne : elle décode une chaîne Base64 et l'affiche. Elle
reproduit la signature technique d'un *download cradle* (encodage + `FromBase64String`)
sans aucune action offensive.

Commande décodée :

```powershell
$s=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('U29jRm9yZ2VSdWxlVGVzdA==')); Write-Output $s
```

Commande exécutée (UTF-16LE → Base64, 328 caractères) :

```powershell
powershell.exe -EncodedCommand JABzAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgA…
```

Sortie observée : `SocForgeRuleTest`, la charge s'est bien décodée et exécutée.

## Détections obtenues

| Règle  | Niveau | EventID | Champ déclencheur  | Heure (UTC) |
|--------|--------|---------|--------------------|-------------|
| 100120 | 8      | 4688    | `newProcessName`   | 18:05:58    |
| 100121 | 12     | 4688    | `commandLine`      | 18:05:58    |
| 100131 | 12     | 4104    | `scriptBlockText`  | 18:06:08    |
| 100127 | 10     | 1       | `commandLine`      |,           |

Extraits exacts d'`alerts.log` :

```
2026 Sep 17 18:05:58 (WIN01) any->EventChannel
Rule: 100121 (level 12) -> 'Sigma T1059.001: PowerShell with suspicious parameters (encoded/download cradle/bypass)'

2026 Sep 17 18:06:08 (WIN01) any->EventChannel
Rule: 100131 (level 12) -> 'Sigma T1059.001: PowerShell ScriptBlock with suspicious content'
```

Capture : [`docs/screenshots/rule-100121-100131-powershell-live.png`](../../docs/screenshots/rule-100121-100131-powershell-live.png)

## Bug de règle trouvé et corrigé

Au premier passage, 100121 s'est déclenchée mais pas 100131, alors que les 4104
existaient bien sur l'hôte et que le canal était correctement collecté par l'agent
(`agent.conf`, `Event[System[(EventID=4104 or …)]]`).

Cause racine : la règle chaînait sur `<if_group>windows_powershell</if_group>`, un groupe
inexistant dans le ruleset Wazuh, confirmé par l'absence de toute occurrence dans
`/var/ossec/ruleset/rules/`. Une règle qui référence un groupe inconnu ne lève aucune
erreur au chargement : elle ne matche simplement jamais. C'est un mode de défaillance
silencieux, d'où l'importance de tester chaque règle en conditions réelles.

Correction : chaînage sur `<if_sid>91802</if_sid>`, la règle parente officielle du canal
`Microsoft-Windows-PowerShell/Operational` (`0915-win-powershell_rules.xml`), qui garantit
la présence du champ `scriptBlockText` décodé.

Après correction et redémarrage du manager, le test rejoué a déclenché 100131.

## Méthodologie de vérification

Les recherches dans `alerts.log` se font sur le texte de description avec une classe de
caractères (`susp[i]cious`) plutôt que sur un numéro de règle. Raison : toute commande
tapée sur le manager est journalisée via sudo/journald et peut être réinjectée dans
`alerts.log` par la règle 100200, une recherche naïve retrouve alors sa propre commande et
produit un faux positif. Ce piège a été observé sur cette instance (alertes de 16:12
contenant la commande de recherche elle-même) ; le motif protégé l'évite.

Chaque alerte est validée sur son contexte complet (agent émetteur, EventID, champ
déclencheur), jamais sur un simple comptage.

## Résultats

| Critère          | Valeur      |
|------------------|-------------|
| Détecté          | oui      |
| Règles           | 100120 (niveau 8), 100121 (niveau 12), 100131 (niveau 12), 100127 (niveau 10) |
| Verdict          | VP (vrai positif) |

## Lecture côté défense

Deux sources se complètent ici. Le 4688 montre la ligne de commande et donc l'option d'encodage ; le 4104 montre le
script une fois décodé, c'est-à-dire ce qui s'exécute vraiment. Avoir les deux évite de dépendre d'un seul réglage
d'audit. La règle `100120` (niveau 8) signale tout lancement de PowerShell et sert de contexte ; l'alerte utile est
`100121` ou `100131`, au niveau 12. Le test est lancé sur la console de WIN01 : il suppose un accès déjà obtenu.

## Nettoyage

Aucun artefact persistant : la charge n'écrit rien sur le disque et ne crée aucune
persistance. Les trois réglages d'audit sont volontairement conservés, ils font partie
de la configuration de détection attendue du poste.
