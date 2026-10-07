# SC-01 : T1053.005, tâche planifiée (Windows)

| | |
|---|---|
| Date | 2026-09-17 (reconstruction) |
| Lancé depuis | console locale de DC01, compte Administrator |
| Technique MITRE | T1053.005, Scheduled Task/Job: Scheduled Task |
| Tactiques | Persistence, Execution |
| Résultat | détecté, règle 100153 (niveau 9) |

## Objectif

Créer une tâche planifiée, comme le ferait un attaquant qui veut garder un accès après une intrusion, et vérifier
que Wazuh le signale.

## Prérequis

La sous-catégorie d'audit « Other Object Access Events » doit être activée sur DC01 :

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

Sans ce réglage, Windows n'écrit jamais les événements 4698 et 4702, et la règle n'a rien à lire. Ce point avait
été établi lors d'une session précédente.

## Test

```powershell
schtasks /create /tn SocForgeRebuildTest /tr calc.exe /sc once /st 23:59 /f
```

Réponse de Windows : `SUCCESS: The scheduled task "SocForgeRebuildTest" has successfully been created.`
Heure d'exécution : 2026-09-17 15:31 UTC.

## Détection

| Champ | Valeur |
|---|---|
| Règle | 100153 |
| Niveau | 9 |
| Description | Sigma T1053: Scheduled task created/modified — \SocForgeRebuildTest |
| Événement source | 4698 |
| Agent | DC01 |

Captures : [commandes exécutées sur DC01](../../docs/screenshots/rule-100153-100178-live-rebuild.png),
[alertes dans Wazuh](../../docs/screenshots/wazuh-dashboard-dc01-events.png).

## Lecture côté défense

La règle s'appuie sur les événements 4698 et 4702 du journal Security, que Windows n'écrit que si la sous-catégorie
d'audit ci-dessus est activée : c'est le premier point à contrôler sur un nouveau poste. Deux autres sources du lab
regardent le même comportement : Sysmon enregistre le lancement de `schtasks.exe`, et la surveillance d'intégrité
de l'agent Wazuh suit `%WINDIR%\System32\Tasks` en temps réel.

Le test est lancé sur la console de DC01 : il valide la règle et sa source de journaux, pas un scénario d'intrusion
complet. Depuis le 07/10, les tâches que Windows réécrit lui-même sous `\Microsoft\Windows\` sont enregistrées au
niveau 3 (règle `100152`), pour que l'alerte de niveau 9 reste lisible.

## Nettoyage

```powershell
schtasks /delete /tn SocForgeRebuildTest /f
```
