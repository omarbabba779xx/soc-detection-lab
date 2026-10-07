# SC-02 : T1078 : Valid Account Remote Logon

Session : Reconstruction, 2026-09-17
Attaquant : Console locale DC01 (Administrator)
MITRE : T1078, Valid Accounts
Tactique : Initial Access / Lateral Movement

---

## Objectif

Utiliser des identifiants valides pour établir une connexion réseau, simulant un
mouvement latéral via comptes légitimes.

## Commande exécutée

```powershell
net use \\10.10.10.109\C$ /user:administrator <mot de passe du lab>
```

Résultat : `The command completed successfully.`

Heure d'exécution : 2026-09-17 15:32 UTC

## Détection Wazuh

| Champ          | Valeur                                                          |
|----------------|-----------------------------------------------------------------|
| Règle          | 100178                                                           |
| Niveau         | 9                                                                 |
| Description    | Sigma T1078: Privileged account remote logon, Administrator from 10.10.10.109 |
| EventID source | 4624 (LogonType 3)                                               |
| Agent          | DC01                                                              |

## Résultats

| Critère          | Valeur      |
|------------------|-------------|
| Détecté          | validé OUI      |
| Règle            | 100178      |
| Verdict          | VP (vrai positif) |

Captures : [commandes exécutées sur DC01](../../docs/screenshots/rule-100153-100178-live-rebuild.png), [alertes dans Wazuh](../../docs/screenshots/wazuh-dashboard-dc01-events.png)

## Nettoyage

```powershell
net use \\10.10.10.109\C$ /delete /y
```
