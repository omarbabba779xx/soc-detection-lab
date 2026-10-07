# SC-01 : T1053.005, tâche planifiée (Windows)

Session : Reconstruction, 2026-09-17
Attaquant : Console locale DC01 (Administrator)
MITRE : T1053.005, Scheduled Task/Job: Scheduled Task
Tactique : Persistence / Execution

---

## Objectif

Créer une tâche planifiée pour simuler un mécanisme de persistance post-exploitation.

## Pré-requis

- Sous-catégorie d'audit "Other Object Access Events" activée sur DC01 :
  ```powershell
  auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
  ```
  Sans ce réglage, Windows ne génère jamais les EventID 4698/4702 requis, root cause
  confirmée lors d'une session d'investigation antérieure.

## Commande exécutée

```powershell
schtasks /create /tn SocForgeRebuildTest /tr calc.exe /sc once /st 23:59 /f
```

Résultat : `SUCCESS: The scheduled task "SocForgeRebuildTest" has successfully been created.`

Heure d'exécution : 2026-09-17 15:31 UTC

## Détection Wazuh

| Champ          | Valeur                                          |
|----------------|--------------------------------------------------|
| Règle          | 100153                                          |
| Niveau         | 9                                                |
| Description    | Sigma T1053: Scheduled task created/modified — \SocForgeRebuildTest |
| EventID source | 4698                                             |
| Agent          | DC01                                             |

## Résultats

| Critère          | Valeur      |
|------------------|-------------|
| Détecté          | oui      |
| Règle            | 100153      |
| Verdict          | VP (vrai positif) |

Captures : [commandes exécutées sur DC01](../../docs/screenshots/rule-100153-100178-live-rebuild.png), [alertes dans Wazuh](../../docs/screenshots/wazuh-dashboard-dc01-events.png)

## Lecture côté défense

La règle s'appuie sur les événements 4698 et 4702 du journal Security, que Windows n'écrit que si la sous-catégorie
d'audit « Other Object Access Events » est activée : c'est le premier point à contrôler sur un nouveau poste. Deux
autres sources du lab regardent le même comportement : Sysmon enregistre le lancement de `schtasks.exe`, et la
surveillance d'intégrité de l'agent Wazuh suit `%WINDIR%\System32\Tasks` en temps réel. Le test est lancé sur la
console de DC01 : il valide la règle et sa source de journaux, pas un scénario d'intrusion complet. Depuis le 07/10,
les tâches que Windows réécrit lui-même sous `\Microsoft\Windows\` sont enregistrées au niveau 3 (règle `100152`),
pour que l'alerte de niveau 9 reste lisible.

## Nettoyage

```powershell
schtasks /delete /tn SocForgeRebuildTest /f
```
