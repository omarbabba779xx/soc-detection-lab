# SC-03 : T1021.002 : Remote Services : SMB/Admin Shares

Session : Reconstruction, correction initiale 2026-09-14/16, re-validation en direct 2026-09-23
MITRE : T1021.002, Remote Services: SMB/Windows Admin Shares
Tactique : Lateral Movement

---

## Objectif

Détecter l'accès à des partages administratifs (`ADMIN$`, `C$`, `IPC$`) par un compte
réel, en filtrant le bruit généré par le trafic Windows légitime (GPO, Netlogon).

## Root cause investiguée et corrigée (historique)

Le déploiement initial de la règle générait 651 566 faux positifs : Windows accède
en permanence à `IPC$`/`ADMIN$` via son propre compte machine (`HOSTNAME$`) et via
`ANONYMOUS LOGON` (SID `S-1-5-7`) pour la résolution de nom / Netlogon, trafic
normal, pas une attaque.

Fix : séparation en deux règles selon `subjectUserName` :

- 100139 (niveau 3, bruit) : `subjectUserName` correspond à `\$$` (compte machine)
  ou `ANONYMOUS LOGON`, filé, pas d'alerte.
- 100140 (niveau 10, détection réelle) : `subjectUserName` ne correspond pas
  à ce filtre, c'est ce que ressemble un mouvement latéral réel via identifiants
  volés/abusés.

## Détection Wazuh

| Règle | Niveau | Rôle |
|-------|--------|------|
| 100139 | 3  | Bruit filtré (compte machine / ANONYMOUS LOGON) |
| 100140 | 10 | Alerte réelle (compte réel accédant à un partage admin) |

## Re-validation en direct (2026-09-23) : et un bug trouvé sur 100139

100140 : accès de `Administrator` depuis WIN01 (10.10.10.110) à `IPC$` puis `C$` de DC01,
14:15:35 et 14:15:36 UTC → deux alertes niveau 10 (détail du test dans SC-08).

100139 n'avait jamais sonné. Le bruit existait bien (41 événements 5140 de comptes machine en
40 minutes sur DC01), mais il était entièrement pris par la règle officielle 67017 (WEF,
« A network share was accessed », niveau 3). Elle est sœur de 100139 sous la même règle parente,
au même niveau, et chargée avant. Son exclusion `IPC$|NetLogon` ne fonctionne pas : en syntaxe
OS_Regex, `IPC$` signifie « IPC en fin de chaîne », alors que la valeur réelle est `\\*\IPC$`.

Correction : 100139 est chaînée sur `<if_sid>67017</if_sid>` (voir
`wazuh/rules/socforge_sigma_rules.xml`). Résultat en direct après rechargement :

| Heure (UTC) | Compte | Partage | Règle |
|---|---|---|---|
| 14:52:17 (×2), 15:05:59 | `WIN-FJ8RP03U8FK$` (DC01) | `IPC$` | 100139 |
| 15:07:17 (×2), 15:08:14 | `DESKTOP-75LAKDV$` (WIN01) | `IPC$` | 100139 |
| 15:17:16 | `DESKTOP-75LAKDV$`, accès déclenché exprès (tâche SYSTEM `net view`) | `IPC$` | 100139 |

Les accès des comptes machine à `SYSVOL` restent sur 67017, ce qui est correct : `SYSVOL` n'est pas
un partage d'administration.

Capture : [`docs/screenshots/wazuh-rules-100139-100140-100186-live.png`](../../docs/screenshots/wazuh-rules-100139-100140-100186-live.png)

## Résultats

| Critère          | Valeur      |
|------------------|-------------|
| Détecté          | validé OUI      |
| Règle d'alerte   | 100140 (niveau 10), escaladée en 100141 (niveau 12) après trois accès depuis la même IP, voir SC-14 |
| Bruit filtré     | 100139 (comptes machine et `ANONYMOUS LOGON`), corrigée le 23/09 |
| Verdict          | VP (vrai positif) |

## Nettoyage

Aucun artefact : les accès aux partages n'écrivent rien. Les règles 100139 et 100140 restent déployées.
