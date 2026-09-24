# SC-14 — Étape 7 : SOAR — Wazuh → Shuffle → TheHive → Cortex → MISP

**Sessions** : 2026-09-19 (reconstruction de VM06, workflow d'enrichissement),
2026-09-23 (déclenchement automatique depuis Wazuh) et 2026-09-24 (observables, licence
TheHive, cas, chaîne complète Wazuh → MISP en une seule exécution)
**Objectif** (plan de reconstruction) : alerte → TheHive → action Shuffle.

---

## Vue d'ensemble

| Workflow Shuffle | Déclencheur | Rôle |
|---|---|---|
| `Wazuh alert to TheHive (webhook)` | **webhook**, appelé par l'intégration native Wazuh (alertes de niveau ≥ 10) | Transforme l'alerte Wazuh en alerte TheHive : titre, sévérité, tags MITRE, IP source en observable |
| `Wazuh Alert to TheHive - Cortex Enrichment` | à la demande | Prend la dernière alerte TheHive, extrait l'IP observable, lance l'analyseur Cortex `MISP_SocForge` |

Depuis le 24/09, le premier workflow enchaîne aussi l'enrichissement (nœud
`Enrich_With_Cortex`) : alerte, observables, analyse Cortex et corrélation MISP se font
dans la même exécution. Le second reste disponible pour relancer une analyse à la main.

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
   │                  techniques MITRE), sourceRef = ID de l'alerte Wazuh, observables
   ▼                  (IP, hôte, fichier, SHA-256, processus, registre, compte — 24/09)
Create_TheHive_Alert  POST http://10.10.10.20:9000/api/v1/alert (compte de service soar-bot)
   ▼
Enrich_With_Cortex    TheHive lance Cortex MISP_SocForge sur les observables (24/09)
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
MISP ≈ 9,5 Go), une dérogation ponctuelle au budget de 3 VM, décidée avant le test.
CORTEX et MISP ont été éteintes juste après.

## Licence TheHive et création de cas (24/09)

L'instance tournait sans licence depuis l'expiration de l'essai d'août (`plan "No"`) :
les alertes arrivaient, mais toute création de cas renvoyait `403`. Licence obtenue sur le
portail StrangeBee et activée par challenge (`GET /api/v1/license/challenge`, puis clé
installée) : `Platinum`, `Trial`, du 24/09 au 08/10/2026, 2 organisations, 5 utilisateurs.
À renouveler par une licence Community pour que le lab reste utilisable après cette date.

Deux défauts de rôles, trouvés en créant le premier cas :

- **`admin@socforge.local` avait le profil `admin` de plateforme** dans l'organisation
  SocForge. Ce profil administre TheHive mais ne donne aucun droit sur les incidents
  (`403 … you don't have the permission manageAlert/import`). Passé en `org-admin` : il
  gère les utilisateurs de l'organisation **et** les incidents. L'administration de la
  plateforme reste au super-admin `admin@thehive.local`.
- **TheHive se connectait à Cortex avec le compte `admin` de Cortex (rôle `superadmin`)**.
  Dans Cortex, ce rôle gère la plateforme mais ne peut pas lancer d'analyseur : le
  connecteur était en `AUTH_ERROR` et TheHive ne voyait aucun analyseur. Un compte de
  service dédié `thehive` (rôles `read`, `analyze`, sans mot de passe) a été créé ; sa clé
  remplace l'ancienne dans `application.conf`. Connecteur `OK`, analyseur `MISP_SocForge`
  visible.

Premier cas : l'alerte `~163848256`, arrivée automatiquement le 23/09 (règle 100210), est
promue en **cas #8** (`HTTP 201`), alerte passée en `Imported` et liée au cas.

## Observables dans les alertes (24/09)

Le nœud `Build_TheHive_Alert` ne joignait que l'IP source, et seulement si l'alerte en
avait une : le cas #8 (alerte FIM, sans IP) est arrivé **vide**, sans rien à analyser. Il
extrait maintenant tout ce que l'alerte Wazuh contient, avec le type TheHive adapté et
sans doublon : IP source, hôte, fichier et SHA-256 (FIM), image, SHA-256 et ligne de
commande du processus (Sysmon), clé de registre, compte. Les adresses locales
(`127.0.0.1`) sont ignorées. Code testé hors Shuffle sur quatre formes d'alerte (FIM,
Sysmon, force brute, localhost), puis déployé sur le workflow en service par
`SHUFFLE_WORKFLOW_ID=… python create_wazuh_webhook_workflow.py` (mise à jour du nœud sans
toucher au webhook).

Test réel : fichier cron inerte `/etc/cron.d/socforge-soar-obs-test` modifié sur le
manager à 12:11:22, alerte TheHive `~204808368` à 12:11:40 avec **3 observables** :
`filename` (le fichier), `hash` (`3d7b09e6…`, identique au `sha256sum` calculé sur le
manager) et `hostname` (`wazuh`). Promue en **cas #9**, qui reprend les 3 observables.

## Chaîne complète en une seule exécution (24/09)

```
Wazuh_Webhook → Build_TheHive_Alert → Create_TheHive_Alert → Enrich_With_Cortex
```

`Enrich_With_Cortex` (execute_python) lit l'ID de l'alerte créée
(`$create_thehive_alert.body._id`), retrouve l'analyseur `MISP_SocForge` par son nom,
fait lancer par TheHive une analyse Cortex sur chaque observable d'un type supporté,
attend les rapports, et pose le tag `misp:match` sur l'alerte si MISP connaît au moins un
observable. Les rapports sont rattachés aux observables dans TheHive.

IOC de référence : événement MISP #4, attribut `filename`
`/etc/cron.d/socforge-soar-chain-test`. Déclencheur : modification de ce fichier inerte
sur le manager.

| Heure (UTC) | Maillon | Preuve |
|---|---|---|
| 12:51:25 | Wazuh : règle 100210, `modified`, MITRE `T1053.003` | alerte `1790254285.130693` |
| 12:51:27 → 12:52:00 | Shuffle : exécution `fe482bcf…`, source `webhook`, 3 nœuds `SUCCESS` | 33 s de bout en bout |
| 12:51:45 | TheHive : alerte `~245788712`, 3 observables | tags `wazuh`, `rule-100210`, `T1053.003` |
| 12:51:50 | Cortex (via TheHive) : `MISP_SocForge` sur le fichier et sur le SHA-256 | tâches `~163860560`, `~122921088` |
| 12:51:59 | Rapports : fichier `MISP:Search="1 event(s)"`, SHA-256 `0 events` | `misp_hits` 1 et 0 |
| 12:52:05 | TheHive : tag **`misp:match`** posé sur l'alerte | sortie du nœud : `"misp_match": true` |

Sortie de l'exécution Shuffle `fe482bcf-e3d7-4512-8ee3-81d0de3a55d2` (`FINISHED`,
source `webhook`), lue par l'API :

```
Build_TheHive_Alert   SUCCESS | tags ['wazuh', 'rule-100210', 'T1053.003'] | observables ['hostname', 'filename', 'hash']
Create_TheHive_Alert  SUCCESS | HTTP 201 | alert ~245788712
Enrich_With_Cortex    SUCCESS | {"alert": "~245788712", "analyzer": "MISP_SocForge",
  "jobs": [{"observable": "46d55965…cab71b", "dataType": "hash", "job": "~122921088", "status": "Success", "misp_hits": 0},
           {"observable": "/etc/cron.d/socforge-soar-chain-test", "dataType": "filename", "job": "~163860560", "status": "Success", "misp_hits": 1}],
  "misp_match": true}
```

Conditions : les 5 VM allumées ensemble (WAZUH, SHUFFLE, THEHIVE, CORTEX, MISP), une
dérogation ponctuelle au budget de 3 VM, décidée avant le test. Pour tenir dans 16 Go, WAZUH et
SHUFFLE sont passées temporairement à 2 560 Mo, MISP à 1 536 Mo, et le tableau de bord
Wazuh a été arrêté. L'hôte est descendu à 0,7 Go libre, sans échec. La RAM d'origine a
été rétablie juste après.

**Défaut vu pendant ce test** : une première exécution, à 12:46, a donné une alerte sans
tag MITRE. Au démarrage de Wazuh dans cette configuration réduite, `wazuh-analysisd` n'a
pas pu joindre `wazuh-db` (« Unable to connect to Wazuh-DB for Mitre matrix information »,
12:37:14). Il ne charge la table MITRE qu'une fois : toutes les alertes de la session en
étaient privées. Ce n'est arrivé qu'à ce démarrage sous forte charge (aucune erreur de ce
type le 23/09, ni au démarrage de 12:05). Un redémarrage du manager a rechargé la table,
et l'exécution de 12:51 porte bien `T1053.003`.

## Captures

- [`docs/screenshots/shuffle-wazuh-webhook-execution.png`](../../docs/screenshots/shuffle-wazuh-webhook-execution.png) — exécution déclenchée par Wazuh : charge utile reçue (règle 100210, ID d'alerte, horodatage), `Build_TheHive_Alert` en succès, `Create_TheHive_Alert` → 201
- [`docs/screenshots/thehive-alerts-from-wazuh-webhook.png`](../../docs/screenshots/thehive-alerts-from-wazuh-webhook.png) — l'alerte arrivée dans TheHive, avec l'ID de l'alerte Wazuh en référence
- [`docs/screenshots/shuffle-dynamic-trigger-misp-match.png`](../../docs/screenshots/shuffle-dynamic-trigger-misp-match.png) — workflow d'enrichissement : IP extraite en direct, Cortex 200

- [`docs/screenshots/thehive-case9-wazuh-alert-observables.png`](../../docs/screenshots/thehive-case9-wazuh-alert-observables.png) — cas #9 créé depuis une alerte Wazuh automatique : 3 observables (hôte, SHA-256, fichier)
- [`docs/screenshots/thehive-alert-soar-chain-cortex-misp.png`](../../docs/screenshots/thehive-alert-soar-chain-cortex-misp.png) — chaîne complète : alerte `~245788712`, rapports Cortex sur les observables, `MISP:Search="1 event(s)"` sur le fichier

## Nettoyage

Fichiers `/etc/cron.d/socforge-soar-test`, `socforge-soar-obs-test` et
`socforge-soar-chain-test` supprimés du manager (leur suppression a servi de déclencheur
supplémentaire). Les workflows, les alertes, les cas #8 et #9 et l'événement MISP #4
restent comme preuve.

## Résultats

| Critère | Valeur |
|---|---|
| Alerte Wazuh → Shuffle sans action humaine | ✅ (intégration native, webhook) |
| Shuffle → alerte TheHive (ID Wazuh en référence, tags MITRE) | ✅ (201, 14 s de bout en bout) |
| Enrichissement TheHive → Cortex → MISP, données dynamiques | ✅ (corrélation MISP réelle) |
| Création de cas TheHive | ✅ (cas #8 et #9, depuis des alertes Wazuh automatiques) |
| Observables extraits de l'alerte Wazuh | ✅ (fichier, SHA-256, hôte ; SHA-256 vérifié) |
| Chaîne Wazuh → Shuffle → TheHive → Cortex → MISP en une exécution | ✅ (33 s, tag `misp:match`) |
