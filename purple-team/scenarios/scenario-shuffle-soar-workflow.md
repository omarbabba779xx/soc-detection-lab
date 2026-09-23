# SC-14 — Étape 7 : SOAR — Wazuh → Shuffle → TheHive → Cortex → MISP

**Sessions** : 2026-09-19 (reconstruction de VM06, workflow d'enrichissement) et
2026-09-23 (déclenchement automatique depuis Wazuh)
**Objectif** (plan de reconstruction) : alerte → TheHive → action Shuffle.

---

## Vue d'ensemble

| Workflow Shuffle | Déclencheur | Rôle |
|---|---|---|
| `Wazuh alert to TheHive (webhook)` | **webhook**, appelé par l'intégration native Wazuh (alertes de niveau ≥ 10) | Transforme l'alerte Wazuh en alerte TheHive : titre, sévérité, tags MITRE, IP source en observable |
| `Wazuh Alert to TheHive - Cortex Enrichment` | à la demande | Prend la dernière alerte TheHive, extrait l'IP observable, lance l'analyseur Cortex `MISP_SocForge` |

## Reconstruction de VM06-SHUFFLE (19/09)

Un disque plein pendant le téléchargement d'une image Docker a corrompu le système de
fichiers de la VM. Le snapshot de base restauré était antérieur à l'installation de
Docker : la stack a été réinstallée, avec cinq corrections :

- mapping des ports du frontend : nginx écoute en interne sur 80/443, pas sur 3001/3443
  (`"3001:80"`, `"3443:443"`) ;
- variable `SHUFFLE_OPENSEARCH_URL` et non `OPENSEARCH_URL` : la seconde était ignorée
  en silence, et le backend retombait sur une URL `https://` par défaut (erreur TLS) ;
- heap OpenSearch ramené à 512 Mo, RAM de la VM portée de 2 à 4 Go (minimum officiel) ;
- carte réseau interne remise en statique (10.10.10.30/24), perdue avec le snapshot ;
- `--paravirtprovider legacy` sur VM04-CORTEX, touchée par le même crash au démarrage
  que VM03 et VM07.

## Workflow 1 — déclenchement automatique par Wazuh (23/09)

**Côté Wazuh** : intégration native `shuffle` (`/var/ossec/integrations/shuffle.py`),
activée par le bloc `<integration>` de
[`wazuh/manager/integration-shuffle.xml`](../../wazuh/manager/integration-shuffle.xml)
(niveau ≥ 10, format JSON). L'identifiant du webhook reste hors du dépôt : il sert de
secret partagé.

**Côté Shuffle** : workflow créé par
[`soar/create_wazuh_webhook_workflow.py`](../../soar/create_wazuh_webhook_workflow.py) :

```
Wazuh_Webhook  (trigger)
   ▼
Build_TheHive_Alert   execute_python : lit $exec (alerte Wazuh complète), fixe le titre,
   │                  la sévérité (3 si niveau ≥ 12, sinon 2), les tags (wazuh, rule-<id>,
   │                  techniques MITRE), sourceRef = ID de l'alerte Wazuh, IP source en observable
   ▼
Create_TheHive_Alert  POST http://10.10.10.20:9000/api/v1/alert (compte de service soar-bot)
```

**Test réel** : persistance cron simulée sur le manager (T1053.003, fichier inerte
`/etc/cron.d/socforge-soar-test`, même technique que SC-07). Surveillance FIM en temps
réel ajoutée sur `/etc/cron.d`, `/etc/crontab` et `/var/spool/cron` du manager.

| Étape | Heure (UTC) | Preuve |
|---|---|---|
| Wazuh : règle 100210 (niveau 10), fichier supprimé | 17:06:49 | alerte `1790183209.20648818` |
| Intégration → webhook Shuffle | 17:06:49 | `integrations.log` |
| Shuffle : exécution `9bf0c903…`, source `webhook` | 17:06:49 → 17:07:04 | 2/2 nœuds `SUCCESS`, `Create_TheHive_Alert` → **HTTP 201** |
| TheHive : alerte `~163848256`, créée par `soar-bot` | 17:07:03 | `sourceRef` = ID de l'alerte Wazuh, tags `rule-100210`, `T1053.003` |

Les 14 secondes entre Shuffle et TheHive correspondent au démarrage du conteneur Python
de Shuffle Tools. Un premier passage, 2 minutes plus tôt (modification du fichier, alerte
`1790183062.20644757`), avait donné le même résultat. L'alerte TheHive y était datée de
6 minutes trop tôt : l'horloge de VM03 dérivait. Cause corrigée :
`PollIntervalMaxSec=300` dans `/etc/systemd/timesyncd.conf.d/socforge.conf` (sur THEHIVE,
SHUFFLE et WAZUH), puis resynchronisation (+6 min 9 s).

Un premier déclencheur plus bruyant, une force brute SSH sur le manager, avait été
envisagé. La persistance cron a été retenue : elle est bénigne, et c'est une règle
SocForge déjà validée.

## Workflow 2 — enrichissement Cortex + MISP (19/09)

```
Change Me → Get_TheHive_Alert (listAlert trié par date : la dernière alerte réelle)
          → Extract_Alert_ID (execute_python) → Get_TheHive_Observable (filtre sur l'_id extrait)
          → Extract_IP (execute_python) → Run_Cortex_Analyzer (POST /api/analyzer/<MISP_SocForge>/run)
```

Défauts corrigés pour obtenir une chaîne réellement dynamique :

1. **Nœuds reliés par l'API** : l'éditeur canevas ne relie deux nœuds qu'au dépôt d'un
   nouveau nœud. Le workflow a été relié via `PUT /api/v1/workflows/{id}` (tableau
   `branches`).
2. **Cortex** : URL en `https://` alors que le service écoute en HTTP (`SSLError`), et
   en-tête d'authentification absent (`401`).
3. **Templating** : Shuffle ne résout pas les chemins imbriqués (`$node.body[0].data`).
   Les nœuds `execute_python` extraient donc l'ID et l'IP du JSON brut.
4. **Faux dynamisme** : dans une première version, `Get_TheHive_Alert` et
   `Get_TheHive_Observable` utilisaient deux ID d'alerte différents codés en dur. La donnée
   ne circulait donc pas vraiment d'un nœud à l'autre. Ils ont été remplacés par la
   requête triée et l'ID extrait.
5. **MISP** : réseau interne de VM05 perdu (IP statique remise), clé API invalide
   (régénérée avec `cake user change_authkey`, puis mise à jour dans l'analyseur Cortex).
6. **Renseignement réel** : sans IOC en base, le `Success` de Cortex ne prouvait qu'une
   exécution technique. Un événement MISP publié (`ip-dst 10.10.10.110`, `to_ids`) donne
   maintenant une vraie corrélation dans le rapport :
   `"level":"suspicious","namespace":"MISP","value":"1 event(s)"`.

Exécution finale : 6 nœuds sur 6 en succès, IP `10.10.10.110` extraite en direct, job
Cortex `Success`. Un contre-test avec une IP jamais analysée (`8.8.8.8`) écarte l'effet
du cache Cortex. Cette validation a demandé 4 VM à la fois (SHUFFLE, THEHIVE, CORTEX,
MISP ≈ 9,5 Go), une dérogation ponctuelle au budget de 3 VM, validée avant le test.
CORTEX et MISP ont été éteintes juste après.

## Limites

- **Cas TheHive** : l'instance tourne sans licence (`/api/v1/license/current` :
  `plan "No"`, aucune capacité). La licence d'essai d'août a expiré. Depuis la version
  5.3, même l'édition Community gratuite demande une clé, obtenue par inscription sur le
  portail StrangeBee. Création d'alertes : OK. Création ou promotion en cas : `403`.
- **Enrichissement à la demande** : les deux workflows ne sont pas enchaînés dans une même
  exécution. Il faudrait WAZUH, SHUFFLE, THEHIVE, CORTEX et MISP en même temps
  (≈ 14,8 Go), au-delà de ce que tient l'hôte.

## Captures

- [`docs/screenshots/shuffle-wazuh-webhook-execution.png`](../../docs/screenshots/shuffle-wazuh-webhook-execution.png) — exécution déclenchée par Wazuh : charge utile reçue (règle 100210, ID d'alerte, horodatage), `Build_TheHive_Alert` en succès, `Create_TheHive_Alert` → 201
- [`docs/screenshots/thehive-alerts-from-wazuh-webhook.png`](../../docs/screenshots/thehive-alerts-from-wazuh-webhook.png) — l'alerte arrivée dans TheHive, avec l'ID de l'alerte Wazuh en référence
- [`docs/screenshots/shuffle-dynamic-trigger-misp-match.png`](../../docs/screenshots/shuffle-dynamic-trigger-misp-match.png) — workflow d'enrichissement : IP extraite en direct, Cortex 200

## Nettoyage

Fichier `/etc/cron.d/socforge-soar-test` supprimé : sa suppression a servi de second
déclencheur. Les workflows et les alertes TheHive restent comme preuve.

## Résultats

| Critère | Valeur |
|---|---|
| Alerte Wazuh → Shuffle sans action humaine | ✅ (intégration native, webhook) |
| Shuffle → alerte TheHive (ID Wazuh en référence, tags MITRE) | ✅ (201, 14 s de bout en bout) |
| Enrichissement TheHive → Cortex → MISP, données dynamiques | ✅ (corrélation MISP réelle) |
| Création de cas TheHive | ❌ licence TheHive requise (voir Limites) |
