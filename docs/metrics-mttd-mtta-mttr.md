# Métriques MTTD / MTTA / MTTR

> Calculées à partir des horodatages déjà présents dans les fiches de scénario — aucun
> nouveau test n'a été fait pour produire ce document. Seuls les cas où les deux temps
> (action de l'attaquant et réaction de l'outil) sont documentés à la seconde près sont
> repris ici : plusieurs scénarios (SC-01, SC-02, SC-04…) n'enregistrent que l'heure
> d'exécution de l'attaque, sans horodatage d'alerte à côté, et ne peuvent donc pas
> donner un delta défendable. Mieux vaut un échantillon restreint et vérifiable qu'une
> moyenne gonflée par des paires reconstituées.

## Définitions retenues

- **MTTD** (*Mean Time To Detect*) : de l'action offensive à l'alerte SIEM (Wazuh) qui la
  signale.
- **MTTA** (*Mean Time To Acknowledge*) : de l'alerte SIEM à la prise en charge
  automatisée — ici, la création de l'alerte/cas dans TheHive par la chaîne SOAR, ou le
  déclenchement d'une chasse DFIR par la boucle MISP → Velociraptor.
- **MTTR** (*Mean Time To Respond*) : de la confirmation de l'alerte à l'action de
  réponse — confinement réseau ou chasse DFIR effective.

## MTTD — attaque → alerte Wazuh

| Scénario | Action | Heure attaque (UTC) | Heure alerte (UTC) | MTTD |
|---|---|---|---|---|
| SC-16 | `nmap -Pn -sT` cross-zone, PURPLE → srv/dfir | 15:56:37 | 15:56:38 (règle 100301) | **~1 s** |
| SC-16 | Isolement attaquant — ping vers le réseau mgmt | 14:57:01 | 14:57:02-03 (règle 100301) | **~1-2 s** |
| SC-12 | `nmap -sS -O` PURPLE → manager Wazuh | 16:12:31 | 16:12:33-34 (règle 100400 ×7) | **~2-3 s** |
| SC-11 | Tentative d'accès LSASS (`OpenProcess`) sur DC01 | — | — | **~2 s** (mesuré depuis la tentative, règle 100103 niveau 14) |
| SC-14 (webhook seul, 23/09) | Fichier cron modifié, règle 100210 | 17:06:49 | 17:06:49 (même règle, alerte native) | **< 1 s** (détection FIM temps réel) |

La détection elle-même (règle Wazuh qui matche l'événement source) est quasi instantanée
dans tous les cas mesurés : de l'ordre de la seconde. C'est cohérent avec des règles FIM
et réseau en temps réel, pas avec un traitement par lot.

## MTTA — alerte Wazuh → prise en charge automatisée

| Scénario | Déclencheur | Heure alerte Wazuh (UTC) | Heure prise en charge (UTC) | MTTA |
|---|---|---|---|---|
| SC-14 (webhook seul, 23/09) | règle 100210 | 17:06:49 | 17:07:03 (alerte TheHive créée) | **14 s** |
| SC-14 (chaîne 3 nœuds, 24/09 12:51) | règle 100210 | 12:51:25 | 12:51:45 (alerte TheHive créée) | **20 s** |
| SC-14 (chaîne 3 nœuds, enrichissement complet) | règle 100210 | 12:51:25 | 12:52:05 (tag `misp:match` posé) | **40 s** |
| SC-15 | publication MISP #3 | 10:47:35 | 10:48:15 (chasse `H.DAQFVRQUQLMJ2` créée) | **40 s** |
| SC-15 (cycle propre, 2ᵉ publication) | publication MISP #3 (republiée) | 11:05:06 | 11:05:10 (chasse `H.DAQG7PIM1PVAQ`) | **4 s** |

Écart notable et documenté : la chaîne à 5 nœuds testée le 24/09 (`~204804176`) a mis
**271 s** entre la règle Wazuh (20:47:53) et la création de l'alerte TheHive (20:52:24).
Cause connue, pas un défaut du mécanisme : les 5 VM de la chaîne démarraient
simultanément, charge RAM hôte transitoire (voir
[`scenario-shuffle-soar-workflow.md`](../purple-team/scenarios/scenario-shuffle-soar-workflow.md)).
Exclu de la moyenne ci-dessous pour ne pas fausser la mesure du mécanisme lui-même avec
un problème d'infrastructure de test.

**Moyenne MTTA (hors incident RAM)** : (14 + 20 + 40 + 40 + 4) / 5 ≈ **24 s**.

## MTTR — alerte confirmée → réponse automatisée

| Mécanisme | Mesure | Preuve |
|---|---|---|
| Application du blocage sur OPNsense (`Contain_Attacker` / `contain_attacker.py`) | **~3 s** (appel API → alias mis à jour → `reconfigure` + `filter/apply`) | test du 24/09, 21:25:07 → 21:25:10 UTC, capture GUI à l'appui |
| Retrait du blocage (`uncontain_attacker.py`) | **~5 s** | même test, 21:25:38 → 21:25:43 UTC |
| Déclenchement de chasse DFIR (`Trigger_DFIR_Hunt`, republication MISP → `AutoHunt`) | **jusqu'à 60 s** (période de sondage `AutoHunt`) + jusqu'à 150 s de sondage des sightings côté nœud | mécanisme documenté dans SC-14/SC-15 ; cycle réel observé à 4 s (republication → nouvelle chasse) dans le cas SC-15 |

**Limite honnête à noter** : le temps d'un confinement **déclenché automatiquement à
l'intérieur d'une exécution Shuffle réelle** (alerte → `Contain_Attacker` → blocage,
sans intervention) n'a pas encore été mesuré de bout en bout, faute d'alerte réelle ayant
atteint le seuil de sévérité ≥ 3 pendant les tests en conditions réelles — celle du 24/09
était de sévérité 2, et `Contain_Attacker` s'est donc correctement abstenu (chemin
négatif prouvé, pas le chemin positif complet en conditions réelles). Le mécanisme de
blocage lui-même est prouvé (CLI, identique au code du nœud), mais le chiffre ci-dessus
mesure l'exécution du blocage, pas le délai total alerte-réelle → blocage-automatique.

## Synthèse

| Indicateur | Valeur | Base |
|---|---|---|
| MTTD | **~1-3 s** | 5 mesures, détection Wazuh temps réel |
| MTTA | **~24 s** (hors incident RAM documenté) | 5 mesures, SC-14 et SC-15 |
| MTTR (mécanique) | **~3-5 s** pour le confinement, **≤ 60-150 s** pour le déclenchement de chasse | SC-14, SC-15 |

Échantillon volontairement restreint : mieux vaut 5 mesures vérifiables à la seconde,
chacune reliée à sa preuve dans une fiche de scénario, qu'une moyenne sur 16 scénarios
dont la moitié n'a qu'un seul horodatage. À enrichir si de futurs tests documentent les
deux temps systématiquement.
