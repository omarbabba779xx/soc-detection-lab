# SC-03 : T1021.002, partages d'administration SMB

| | |
|---|---|
| Dates | correction initiale les 14 et 16/09/2026, nouvelle validation en direct le 23/09 |
| Technique MITRE | T1021.002, Remote Services: SMB/Windows Admin Shares |
| Tactique | Lateral Movement |
| Résultat | détecté par 100140 (niveau 10) ; bruit rangé sous 100139 (niveau 3) |

## Objectif

Détecter l'accès d'un compte réel à un partage d'administration (`ADMIN$`, `C$`, `IPC$`), sans être noyé par le
trafic normal de Windows.

## Le problème de départ : 651 566 faux positifs

La première version de la règle alertait sur tout accès à ces partages. Or Windows y accède en permanence avec son
propre compte machine (`NOM$`) et avec `ANONYMOUS LOGON` (SID `S-1-5-7`), pour la résolution de noms et Netlogon.
Ce trafic est normal. La règle a produit 651 566 alertes.

La correction sépare les deux cas selon le champ `subjectUserName` :

| Règle | Niveau | Ce qu'elle retient |
|---|---|---|
| 100139 | 3 | compte machine (nom terminé par `$`) ou `ANONYMOUS LOGON` : enregistré, sans alerte |
| 100140 | 10 | tout autre compte : c'est à cela que ressemble un déplacement avec des identifiants volés |

## Validation en direct (23/09)

Règle 100140 : `Administrator` accède depuis WIN01 (10.10.10.110) à `IPC$` puis à `C$` de DC01, à 14:15:35 et
14:15:36 UTC. Deux alertes de niveau 10. Le détail du test est dans SC-08.

### Un défaut trouvé sur 100139

En vérifiant l'historique, la règle de bruit 100139 n'avait jamais sonné. Le bruit existait bien : 41 événements
5140 de comptes machine en 40 minutes sur DC01. Mais ils étaient tous pris par la règle officielle 67017
(« A network share was accessed », niveau 3). Cette règle a le même parent que 100139 et le même niveau, et elle
est chargée avant.

Son exclusion `IPC$|NetLogon` ne fonctionne pas non plus. Dans la syntaxe OS_Regex de Wazuh, `IPC$` veut dire
« IPC en fin de chaîne », alors que la valeur réelle est `\\*\IPC$`.

Correction : 100139 est maintenant rattachée à 67017 (`<if_sid>67017</if_sid>`, voir
`wazuh/rules/socforge_sigma_rules.xml`). Résultat après rechargement :

| Heure (UTC) | Compte | Partage | Règle |
|---|---|---|---|
| 14:52:17 (×2), 15:05:59 | `WIN-FJ8RP03U8FK$` (DC01) | `IPC$` | 100139 |
| 15:07:17 (×2), 15:08:14 | `DESKTOP-75LAKDV$` (WIN01) | `IPC$` | 100139 |
| 15:17:16 | `DESKTOP-75LAKDV$`, accès déclenché exprès (tâche SYSTEM `net view`) | `IPC$` | 100139 |

Les accès des comptes machine à `SYSVOL` restent sous 67017, ce qui est correct : `SYSVOL` n'est pas un partage
d'administration.

Capture : [`wazuh-rules-100139-100140-100186-live.png`](../../docs/screenshots/wazuh-rules-100139-100140-100186-live.png)

## Résultats

| Critère | Valeur |
|---|---|
| Détecté | oui |
| Règle d'alerte | 100140 (niveau 10) ; trois accès depuis la même adresse en deux minutes donnent 100141 (niveau 12), voir SC-14 |
| Bruit | 100139 (comptes machine et `ANONYMOUS LOGON`), corrigée le 23/09 |
| Verdict | vrai positif |

## Nettoyage

Aucun artefact : un accès à un partage n'écrit rien. Les règles 100139 et 100140 restent déployées.
