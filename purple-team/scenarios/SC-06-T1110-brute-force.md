# SC-06 : T1110, force brute SMB

| | |
|---|---|
| Date | 2026-09-17 (reconstruction) |
| Lancé depuis | PURPLE (Kali 2026.2, `10.10.10.60` à cette date) |
| Cible | DC01 (agent Wazuh 007, `10.10.10.109` à cette date) |
| Technique MITRE | T1110, Brute Force |
| Tactique | Credential Access |
| Résultat | détecté par 100110 (niveau 6) et 100111 (niveau 10), après correction d'un défaut sur 100111 |

> Adresses : ce test date d'avant le 24/09/2026, quand PURPLE avait encore une carte sur le réseau de gestion
> (`10.10.10.60`). Depuis, PURPLE n'existe plus que dans sa zone filtrée (`10.10.50.10`) : voir SC-16,
> « Isolement de l'attaquant ».

## Objectif

Vérifier la détection d'une série d'échecs d'authentification lancée depuis la machine attaquante, dans la
continuité de SC-05.

## Test

Hydra (module `smb`) a échoué avec `[ERROR] invalid reply from target` : il ne gère pas le SMB récent, et SMBv1
est désactivé sur Windows Server 2022. Il a été remplacé par `netexec`, qui gère SMBv2 et SMBv3.

```bash
printf 'wrongpass1\nwrongpass2\nwrongpass3\nwrongpass4\nwrongpass5\nwrongpass6\n' > pw.txt
nxc smb 10.10.10.109 -u administrator -p pw.txt
```

Résultat : six `STATUS_LOGON_FAILURE` pour `socforge.lab\administrator`.

## Détection

| Règle | Niveau | Rôle |
|---|---|---|
| 100110 | 6 | un échec d'ouverture de session (événement 4625) |
| 100111 | 10 | cinq échecs en soixante secondes depuis la même adresse |

```
Rule: 100110 (level 6) -> 'Sigma T1110: Failed logon attempt — administrator'
(x6)
Rule: 100111 (level 10) -> 'Sigma T1110: Multiple failed logon attempts from the same source — brute force'
```

Capture (tableau de bord Wazuh, 13 correspondances) :
[`wazuh-dashboard-dc01-bruteforce-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-bruteforce-events.png)

## Défaut trouvé et corrigé sur 100111

La règle regroupait les tentatives avec `<same_source_ip/>`. Cette option lit le champ générique `srcip`, que
seuls certains décodeurs (syslog, par exemple) remplissent. Le décodeur JSON utilisé pour les événements Windows ne
le remplit pas. Résultat : six échecs à la même seconde depuis la même adresse ne déclenchaient pas le
regroupement, sans aucune erreur au chargement. C'est une panne silencieuse, comme les erreurs de groupe trouvées
dans les règles Sysmon lors de la même session.

L'alerte brute contenait bien l'adresse (`eventdata.ipAddress: "10.10.10.60"`, identique sur les six événements) :
la donnée existait, seul le mécanisme de regroupement était mal choisi. Correction :
`<same_field>win.eventdata.ipAddress</same_field>`, qui regroupe sur n'importe quel champ décodé.

## Résultats

| Critère | Valeur |
|---|---|
| Détecté | oui |
| Règles | 100110, 100111 |
| Verdict | vrai positif |
| Source | PURPLE (10.10.10.60) |

## Lecture côté défense

Le seuil de `100111` (cinq échecs en soixante secondes depuis la même adresse) est réglé pour une attaque rapide
depuis une seule source. Chaque échec reste visible séparément au niveau 6 (`100110`), ce qui permet de revoir
après coup une série plus lente. La politique de verrouillage des comptes n'est pas activée dans le lab : en
production, elle agirait en même temps que la détection.

## Nettoyage

Rien à retirer : des tentatives échouées, aucun compte verrouillé.
