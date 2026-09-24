# SC-06 — T1110 : Brute Force (SMB)

**Session** : Reconstruction — 2026-09-17
**Attaquant** : PURPLE (Kali 2026.2, 10.10.10.60)

> **Adresse de l'attaquant** : ce test date d'avant le 24/09/2026, quand PURPLE avait encore une
> patte sur le réseau mgmt (`10.10.10.60`). Depuis, PURPLE n'existe plus que dans sa zone
> filtrée (`10.10.50.10`) : voir SC-16, « Isolement de l'attaquant ».

**Cible** : dc01 (agent Wazuh ID 007, 10.10.10.109)
**MITRE** : T1110 — Brute Force
**Tactique** : Credential Access

---

## Objectif

Valider la détection d'un brute force réseau réaliste, lancé depuis la machine
d'attaque (PURPLE) plutôt que depuis la console de la victime, dans la continuité de
SC-05 (T1046).

## Commande exécutée (depuis PURPLE)

Hydra (module `smb`) a échoué avec `[ERROR] invalid reply from target` — incompatibilité
avec le SMB moderne (SMBv1 désactivé sur Windows Server 2022). Remplacé par `netexec`
(successeur de crackmapexec), qui gère correctement SMBv2/v3 :

```bash
printf 'wrongpass1\nwrongpass2\nwrongpass3\nwrongpass4\nwrongpass5\nwrongpass6\n' > pw.txt
nxc smb 10.10.10.109 -u administrator -p pw.txt
```

**Résultat** : 6× `STATUS_LOGON_FAILURE` pour `socforge.lab\administrator`.

## Détection Wazuh

| Règle  | Niveau | Rôle                                              |
|--------|--------|-----------------------------------------------------|
| 100110 | 6      | Échec de logon individuel (EventID 4625)            |
| 100111 | 10     | ≥5 échecs même IP source en 60 s — brute force       |

**Testé en direct le 2026-09-17** :

```
Rule: 100110 (level 6) -> 'Sigma T1110: Failed logon attempt — administrator'
(x6)
Rule: 100111 (level 10) -> 'Sigma T1110: Multiple failed logon attempts from the same source — brute force'
```

## Bug de règle trouvé et corrigé

100111 utilisait `<same_source_ip/>` pour regrouper les tentatives par IP source. Ce
mécanisme dépend du champ générique `srcip`, qui n'est renseigné automatiquement que par
certains décodeurs legacy (syslog, etc.) — **jamais** par le décodeur JSON générique
utilisé pour les événements `eventchannel` Windows. Résultat : 6 échecs à la même
seconde depuis la même IP ne déclenchaient jamais l'agrégation, sans aucune erreur de
chargement pour le signaler (échec silencieux, comme les bugs de groupe trouvés dans les
règles Sysmon la même session).

Vérifié sur l'alerte brute (champ `eventdata.ipAddress: "10.10.10.60"` présent et
identique sur les 6 événements) que la donnée existait bel et bien — seul le mécanisme
d'agrégation était mal choisi. Corrigé en `<same_field>win.eventdata.ipAddress</same_field>`,
qui permet de grouper sur n'importe quel champ décodé nommé, pas seulement les alias
génériques `srcip`/`dstip` hérités des décodeurs syslog classiques.

## Résultats

| Critère    | Valeur              |
|------------|----------------------|
| Détecté    | ✅ OUI               |
| Règles     | 100110, 100111       |
| Verdict    | VP (vrai positif)    |
| Source     | PURPLE (10.10.10.60) |

Capture (dashboard Wazuh, 13 correspondances) :
[`docs/screenshots/wazuh-dashboard-dc01-bruteforce-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-bruteforce-events.png)

## Nettoyage

Aucun artefact persistant — tentatives de connexion échouées, pas de compte verrouillé
(politique de verrouillage non activée dans ce lab).
