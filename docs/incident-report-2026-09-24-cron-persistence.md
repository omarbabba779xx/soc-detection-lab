# Rapport d'incident — persistance cron suspectée sur le manager Wazuh

**Référence interne** : alerte TheHive `~204804176`
**Date** : 2026-09-24
**Sévérité déclarée** : Moyenne (2/4)
**Statut** : Clos — activité bénigne confirmée (test contrôlé), chaîne de réponse validée
**Cas TheHive** : #10 (`~245764176`), modèle « SOAR-triggered incident », 5 tâches closes, `TruePositive`

> Ce rapport documente un incident réel traité de bout en bout par la chaîne SOAR du
> lab, du déclenchement à la clôture. L'activité source est un test contrôlé et bénigne
> (modification d'un fichier cron inerte) — le choix délibéré pour valider la chaîne sans
> risque sur le lab, cohérent avec la pratique du reste du projet (voir
> [`scenario-shuffle-soar-workflow.md`](../purple-team/scenarios/scenario-shuffle-soar-workflow.md)).
> Le déroulé, les décisions et les preuves ci-dessous sont ceux d'une exécution réelle,
> pas d'un scénario rejoué pour l'illustration.

## 1. Résumé exécutif

Une modification du fichier `/etc/cron.d/socforge-soar-chain-test` sur le manager Wazuh
a déclenché la règle FIM `100210` (technique MITRE T1053.003 — persistance par cron).
L'alerte a traversé automatiquement la chaîne SOAR (Wazuh → Shuffle → TheHive → Cortex →
MISP), a été corrélée à un événement de threat intelligence connu, puis a suivi les deux
branches de réponse automatisée : évaluation du confinement réseau et déclenchement
d'une chasse DFIR. Aucune intervention humaine n'a été nécessaire jusqu'à la clôture des
tags d'audit sur l'alerte. Un incident d'infrastructure (redémarrage du backend SOAR par
manque de RAM) est survenu pendant le traitement et est documenté en section 6 — sans
impact sur le résultat final.

## 2. Chronologie (UTC, 2026-09-24)

| Heure | Événement | Source |
|---|---|---|
| 20:47:53 | Fichier `/etc/cron.d/socforge-soar-chain-test` modifié sur le manager | Wazuh, règle 100210, niveau 10 |
| 20:47:53 | Intégration native `shuffle.py` envoie la charge utile au webhook Shuffle | `integrations.log` |
| 20:52:24 | Alerte TheHive `~204804176` créée par `soar-bot` (nœud `Create_TheHive_Alert`) | TheHive API, `sourceRef` = ID alerte Wazuh |
| — | Observables extraits : fichier, hachage SHA-256, hôte | nœud `Build_TheHive_Alert` |
| — | Analyse Cortex `MISP_SocForge` lancée sur les observables (nœud `Enrich_With_Cortex`) | Cortex, jobs liés à l'alerte |
| — | Tag `misp:match` posé — l'attribut `filename` correspond à l'événement MISP #4 | rapport Cortex, `report.full.results[].result[].id` |
| — | `Contain_Attacker` évalue l'alerte : sévérité 2 < seuil 3 → **abstention**, aucune action réseau | nœud `Contain_Attacker`, pas de tag ajouté |
| 21:01:13 | `Trigger_DFIR_Hunt` republie l'événement MISP #4, sonde les sightings pendant 150 s, ne trouve rien dans la fenêtre, pose `dfir:hunt-triggered` | note d'audit sur l'alerte, capture `thehive-alert-dfir-hunt-triggered.png` |

Délai brut règle → alerte TheHive : 271 s. Cause identifiée : les 5 VM de la chaîne
(WAZUH, SHUFFLE, THEHIVE, CORTEX, MISP) démarraient simultanément pour ce test, charge
RAM hôte transitoire — pas un défaut du mécanisme (voir section 6 et
[`metrics-mttd-mtta-mttr.md`](metrics-mttd-mtta-mttr.md), qui exclut ce point de la
moyenne pour cette raison).

## 3. Analyse

**Déclencheur** : modification d'un fichier sous `/etc/cron.d/`, surveillé en temps réel
par le module FIM de l'agent Wazuh installé sur le manager lui-même.

**Décision de sévérité** : le nœud `Build_TheHive_Alert` fixe la sévérité à 2 (moyenne)
pour un niveau de règle Wazuh < 12 — cette alerte, niveau 10, reste donc sous le seuil de
confinement automatique (3). C'est une décision de conception délibérée : le confinement
réseau ne s'active que sur une combinaison sévérité + corrélation CTI, pas sur la seule
présence d'un tag `misp:match`.

**Corrélation CTI** : l'attribut republié correspond à l'événement MISP #4, dont l'IOC de
référence est le chemin `/etc/cron.d/socforge-soar-chain-test` lui-même (type
`filename`) — cohérent avec le fait que ce fichier est le marqueur de test délibérément
inscrit dans MISP pour cette validation.

**Chasse DFIR** : aucun sighting Velociraptor trouvé dans la fenêtre de 150 s. Résultat
honnête et attendu : cet IOC est un chemin de test sur le manager Wazuh (Linux), hors du
périmètre couvert par la chasse `Windows.EventLogs.EvtxHunter` sur WIN01/DC01. Le nœud ne
force pas un faux positif — il pose `dfir:hunt-triggered` (chasse relancée, rien trouvé),
distinct de `dfir:hunted` (sighting confirmé), ce que confirme le test croisé fait plus
tôt avec l'événement MISP #3 (IOC présent sur WIN01, sighting retrouvé).

## 4. Actions de réponse

| Action | Déclenchée ? | Justification |
|---|---|---|
| Confinement réseau (`Contain_Attacker`) | Non | Sévérité 2 < seuil 3 — abstention correcte, pas une panne |
| Chasse DFIR (`Trigger_DFIR_Hunt`) | Oui | `misp:match` présent, republication + sondage effectués |
| Promotion en cas TheHive | Non (hors périmètre de ce test) | L'alerte reste au statut `New`, aucune action manuelle demandée pour ce test de chaîne |

## 5. Indicateurs

- Fichier : `/etc/cron.d/socforge-soar-chain-test`
- Événement MISP corrélé : #4
- Alerte Wazuh source : règle 100210, niveau 10, ID `1790282873.…`
- Alerte TheHive : `~204804176`, tags finaux `wazuh`, `rule-100210`, `T1053.003`,
  `misp:match`, `dfir:hunt-triggered`

## 6. Incident d'infrastructure pendant le traitement

Le conteneur `shuffle-backend` a été tué par manque de RAM hôte en cours d'exécution,
puis redémarré automatiquement par Docker une minute plus tard. Le worker de
l'exécution Shuffle a repris le fil en rejouant `Build_TheHive_Alert` et
`Create_TheHive_Alert` avant d'atteindre les nœuds de réponse. Impact réel : **aucun** —
`Create_TheHive_Alert` s'appuie sur `sourceRef` (l'ID de l'alerte Wazuh), que TheHive
traite en écrasement d'une alerte existante plutôt qu'en création d'un doublon. Un
worker orphelin de la même panne a été identifié (tempête de conteneurs Docker à l'état
`Dead`) et nettoyé manuellement après coup, sans avoir écrit quoi que ce soit dans
TheHive. Résultat final vérifié : une seule alerte, un seul jeu de tags cohérent.

Cet incident vient de l'exécution de plusieurs VM sur un seul hôte, pas d'un
défaut de la chaîne SOAR elle-même — voir
[`README.md`](../README.md#limites-connues) et le détail complet dans
[`scenario-shuffle-soar-workflow.md`](../purple-team/scenarios/scenario-shuffle-soar-workflow.md).

## 7. Clôture et recommandations

- **Clôture** : incident traité conformément au comportement attendu de la chaîne ; pas
  d'action corrective nécessaire sur les scripts ou les workflows.
- **Recommandation retenue** : documenter explicitement, dans le code du nœud
  `Contain_Attacker`, le seuil de sévérité comme un point de configuration révisable
  (actuellement codé en dur à 3) — fait pour ce rapport, à considérer pour une prochaine
  itération du nœud.
- **Recommandation retenue** : sur le lab, garder trace des incidents d'infrastructure
  liés à la RAM directement dans le rapport de l'incident métier qu'ils ont affecté,
  plutôt que dans un journal séparé — ce que fait ce document (section 6), pour que la
  chronologie complète reste lisible en un seul endroit.
- **Preuves associées** :
  [`thehive-alert-dfir-hunt-triggered.png`](screenshots/thehive-alert-dfir-hunt-triggered.png),
  [`opnsense-blocked-attackers-alias.png`](screenshots/opnsense-blocked-attackers-alias.png)
  (mécanisme de confinement, revalidé séparément le même jour, voir section 3),
  [`thehive-case10-ir-playbook-closed.png`](screenshots/thehive-case10-ir-playbook-closed.png)
  (cas #10, 5 tâches du modèle IR closes, `TruePositive`, résolu en 55 s une fois ouvert).
