# SC-02 : T1078, compte valide et ouverture de session réseau

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
| Description    | Sigma T1078: Privileged account remote logon — Administrator from 10.10.10.109 |
| EventID source | 4624 (LogonType 3)                                               |
| Agent          | DC01                                                              |

## Résultats

| Critère          | Valeur      |
|------------------|-------------|
| Détecté          | oui      |
| Règle            | 100178      |
| Verdict          | VP (vrai positif) |

Captures : [commandes exécutées sur DC01](../../docs/screenshots/rule-100153-100178-live-rebuild.png), [alertes dans Wazuh](../../docs/screenshots/wazuh-dashboard-dc01-events.png)

## Lecture côté défense

Le test ouvre une session réseau depuis DC01 vers lui-même : l'adresse source de l'alerte est donc celle du
serveur. Il valide la règle et le champ qu'elle lit, pas une arrivée depuis une autre machine ; ce cas est couvert par
SC-08 (WIN01 vers DC01) et par l'attaque de SC-14 (PURPLE vers WIN01). La règle `100178` reconnaît un compte
privilégié à son nom (`administrator`, `admin`, `svc_`) : elle est simple à lire, mais dépend de la convention de
nommage. La règle `100179`, ajoutée le 07/10, regarde l'origine de la session et alerte pour tout compte qui se
connecte depuis la zone attaquant.

## Nettoyage

```powershell
net use \\10.10.10.109\C$ /delete /y
```
