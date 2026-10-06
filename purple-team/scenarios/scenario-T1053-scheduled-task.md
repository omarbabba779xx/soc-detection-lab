# SC-01 — T1053.005 : Scheduled Task (Windows)

**Session** : Reconstruction — 2026-09-17
**Attaquant** : Console locale DC01 (Administrator)
**MITRE** : T1053.005 — Scheduled Task/Job: Scheduled Task
**Tactique** : Persistence / Execution

---

## Objectif

Créer une tâche planifiée pour simuler un mécanisme de persistance post-exploitation.

## Pré-requis

- Sous-catégorie d'audit "Other Object Access Events" activée sur DC01 :
  ```powershell
  auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
  ```
  Sans ce réglage, Windows ne génère jamais les EventID 4698/4702 requis — root cause
  confirmée lors d'une session d'investigation antérieure.

## Commande exécutée

```powershell
schtasks /create /tn SocForgeRebuildTest /tr calc.exe /sc once /st 23:59 /f
```

**Résultat** : `SUCCESS: The scheduled task "SocForgeRebuildTest" has successfully been created.`

**Heure d'exécution** : 2026-09-17 15:31 UTC

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
| Détecté          | ✅ OUI      |
| Règle            | 100153      |
| Verdict          | VP (vrai positif) |

Captures : [commandes exécutées sur DC01](../../docs/screenshots/rule-100153-100178-live-rebuild.png), [alertes dans Wazuh](../../docs/screenshots/wazuh-dashboard-dc01-events.png)

## Nettoyage

```powershell
schtasks /delete /tn SocForgeRebuildTest /f
```
