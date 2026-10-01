# SC-14 — Étape 7 : SOAR — Wazuh → Shuffle → TheHive → Cortex → MISP

**Sessions** : 2026-09-19 (reconstruction de VM06, workflow d'enrichissement),
2026-09-23 (déclenchement automatique depuis Wazuh) et 2026-09-24 (observables, licence
TheHive, cas, chaîne complète Wazuh → MISP en une seule exécution, puis confinement
automatique et déclenchement de chasse DFIR)
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
du cache Cortex. Cette validation a mobilisé 4 VM à la fois (SHUFFLE, THEHIVE, CORTEX,
MISP).
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

Conditions : les 5 VM allumées ensemble (WAZUH, SHUFFLE, THEHIVE, CORTEX, MISP), avec la mémoire de
WAZUH, SHUFFLE et MISP réduite pour le test (rétablie ensuite) et le tableau de bord Wazuh arrêté.

**Défaut vu pendant ce test** : une première exécution, à 12:46, a donné une alerte sans
tag MITRE. Au démarrage de Wazuh dans cette configuration réduite, `wazuh-analysisd` n'a
pas pu joindre `wazuh-db` (« Unable to connect to Wazuh-DB for Mitre matrix information »,
12:37:14). Il ne charge la table MITRE qu'une fois : toutes les alertes de la session en
étaient privées. Ce n'est arrivé qu'à ce démarrage sous forte charge (aucune erreur de ce
type le 23/09, ni au démarrage de 12:05). Un redémarrage du manager a rechargé la table,
et l'exécution de 12:51 porte bien `T1053.003`.

## Confinement automatique et boucle DFIR (24/09)

Jusque-là, la chaîne détecte, alerte, enrichit et corrèle avec MISP, mais n'agit jamais
sur l'attaquant, et un `misp:match` posé par `Enrich_With_Cortex` ne déclenche rien côté
Velociraptor : deux limites de process repérées en relisant le workflow au complet, pas
un défaut technique isolé. Deux nœuds supplémentaires ferment ces manques :

```
Wazuh_Webhook → Build_TheHive_Alert → Create_TheHive_Alert → Enrich_With_Cortex
              → Contain_Attacker → Trigger_DFIR_Hunt
```

### Contain_Attacker — confinement réseau

Bloque l'IP observable sur OPNsense si l'alerte est confirmée (sévérité ≥ 3, tag
`misp:match`). Mécanisme partagé avec la CLI :

- [`firewall/segmentation-policy.json`](../../firewall/segmentation-policy.json) : alias
  `BLOCKED_ATTACKERS` (`"dynamic": true` — `apply_policy.py` le crée une fois et ne
  touche plus jamais à son contenu, géré en direct par le confinement) et règle
  `opt4 → any, src BLOCKED_ATTACKERS, block, log` (seq 395, avant les règles purple
  existantes).
- [`firewall/opnsense_client.py`](../../firewall/opnsense_client.py) : client REST
  partagé (TLS vérifié contre la CA du lab, `ExpectedName` pour forcer le contrôle du nom
  même via un tunnel `127.0.0.1`), extrait de `apply_policy.py`.
- [`firewall/contain_attacker.py`](../../firewall/contain_attacker.py) /
  [`uncontain_attacker.py`](../../firewall/uncontain_attacker.py) : ajout/retrait d'une
  IP dans l'alias + `alias/reconfigure` + `filter/apply`. La CLI est indépendante du nœud
  Shuffle et sert aussi à la réversion manuelle.
- [`soar/nodes/contain_attacker.py`](../../soar/nodes/contain_attacker.py) : code du
  nœud `execute_python` (le bac à sable Shuffle ne peut pas importer les fichiers du
  dépôt — logique réimplémentée en ligne, mêmes appels API). Si l'alerte ne remplit pas
  les conditions, ou n'a pas d'observable `ip`, le nœud s'arrête proprement sans rien
  écrire (`SystemExit(0)`) : pas de faux blocage. En cas de confinement, il pose le tag
  `auto-contained` et ajoute une note d'audit horodatée sur l'alerte, avec le rappel que
  `firewall/uncontain_attacker.py` permet de revenir en arrière.

**Preuve (24/09, 21:25 UTC, hors chaîne Shuffle — même mécanisme, exécuté en CLI)** :

| Heure (UTC) | Étape | Preuve |
|---|---|---|
| 21:25:10 | `contain_attacker.py 198.51.100.77` | `{"already_blocked": false, "result": "done"}` |
| 21:25:2x | OPNsense GUI, alias `BLOCKED_ATTACKERS` | `198.51.100.77` listée, capture ci-dessous |
| 21:25:43 | `uncontain_attacker.py 198.51.100.77` | `{"result": "done"}`, alias revérifié vide (`rowCount` 0 ligne) |

Le blocage a d'abord été validé avec du trafic réel (ping à travers OPNsense : passe
avant confinement, tombe à 100 % de perte une fois l'IP dans `BLOCKED_ATTACKERS`, Wazuh
voit le blocage via la règle de log OPNsense, trafic restauré après retrait). Le test du
24/09 ci-dessus revalide le même mécanisme après le passage en nœud Shuffle, avec preuve
écrite (capture GUI) plutôt que trafic éphémère.

Dans la chaîne réelle du 24/09 (alerte `~204804176`, voir plus bas), `Contain_Attacker`
s'est correctement **abstenu** : sévérité 2 (< 3), aucun tag ni note ajoutés — le chemin
négatif du nœud, tel que conçu.

### Trigger_DFIR_Hunt — boucle vers Velociraptor

Un `misp:match` restait une corrélation passive : personne ne relançait la chasse
Velociraptor. `Trigger_DFIR_Hunt` republie dans MISP le ou les événements déjà identifiés
par `Enrich_With_Cortex` (relit les rapports Cortex `MISP_SocForge` déjà produits via
`GET /api/connector/cortex/job/<id>`, extrait les ID d'événement de
`report.full.results[].result[].id`), ce qui déclenche
`Custom.Server.MISP.AutoHunt` côté Velociraptor (sondage MISP toutes les 60 s, clé de
déduplication `(event_id, publish_timestamp)`), puis interroge
`/sightings/index/<id>` toutes les 15 s pendant 150 s. Il pose `dfir:hunted` (sighting
trouvé dans la fenêtre) ou `dfir:hunt-triggered` (chasse relancée mais rien trouvé à
temps — pas une erreur, juste un résultat honnête) avec une note d'audit horodatée.

**Défaut trouvé en le construisant** : `Custom.Server.MISP.Iocs` ne cherchait que les
types `text` et `regkey|value` (`IocTypes` par défaut), plus étroit que ce que l'analyseur
Cortex `MISP_SocForge` matche déjà. Un `misp:match` sur un attribut `filename` (le cas
réel de l'événement #4) ne déclenchait donc **aucune** chasse : la boucle semblait
fonctionner mais n'aurait jamais tourné dans ce cas précis. Corrigé en élargissant
`IocTypes` à `["text", "regkey|value", "filename", "hash"]` dans les trois artefacts
concernés
([`Custom.Server.MISP.Iocs.yaml`](../../velociraptor/artifacts/Custom.Server.MISP.Iocs.yaml),
[`Custom.Server.MISP.IOCHunt.yaml`](../../velociraptor/artifacts/Custom.Server.MISP.IOCHunt.yaml),
[`Custom.Server.MISP.AutoHunt.yaml`](../../velociraptor/artifacts/Custom.Server.MISP.AutoHunt.yaml)),
redéployé sur le serveur Velociraptor en service. `ip` reste volontairement exclu : c'est
le terrain de la NDR/Wazuh, pas de cette chasse fichiers/hôte. `type`
n'est pas resté théorique : événement #4 republié après correction, chasse
`H.DAQO7NJA0I35E` créée.

Validé séparément dans les deux sens avant le déploiement dans la chaîne réelle :
événement #3 (IOC présent sur WIN01) → sighting positif retrouvé par le nœud ;
événement #4 (IOC d'un chemin Linux, absent de WIN01) → chasse relancée, aucune erreur,
`dfir:hunt-triggered` posé sans faux positif.

### Chaîne complète à 5 nœuds — test en conditions réelles (24/09)

Déployée sur le workflow en service par
`SHUFFLE_WORKFLOW_ID=… python soar/create_wazuh_webhook_workflow.py` (les deux nouveaux
nœuds chargent leur code depuis `soar/nodes/`, substituent les URL/clés d'environnement,
et sont raccordés à la suite d'`Enrich_With_Cortex` via `ensure_chain()`, sans toucher au
webhook). Déclencheur : modification de
`/etc/cron.d/socforge-soar-chain-test` sur le manager (même IOC de référence que le test
du 24/09 précédent, événement MISP #4).

| Heure (UTC) | Maillon | Preuve |
|---|---|---|
| 20:47:53 | Wazuh : règle 100210, `modified`, `T1053.003` | alerte `1790282873.…` |
| 20:52:24 | TheHive : alerte `~204804176` créée | tags `wazuh`, `rule-100210`, `T1053.003` (délai dû au démarrage simultané des 5 VM) |
| — | `Enrich_With_Cortex` | tag `misp:match` posé |
| — | `Contain_Attacker` | abstention silencieuse (sévérité 2 < 3) — pas de tag, pas de note |
| 21:01:13 | `Trigger_DFIR_Hunt` : événement MISP #4 republié, sighting non trouvé dans la fenêtre | tag **`dfir:hunt-triggered`** + note d'audit sur l'alerte |

**Incident de charge pendant ce test** : le backend Shuffle (`shuffle-backend`) a été tué
par manque de RAM en cours d'exécution, puis redémarré automatiquement par Docker une
minute plus tard. Le worker de l'exécution a repris le fil, rejouant `Build_TheHive_Alert`
et `Create_TheHive_Alert` avant d'atteindre `Trigger_DFIR_Hunt` — sans dupliquer l'alerte
TheHive : `Create_TheHive_Alert` s'appuie sur `sourceRef` (l'ID d'alerte Wazuh), que
TheHive traite en amont-écrasement plutôt qu'en création. Un second worker orphelin de la
même panne (tempête de conteneurs `Dead` sous Docker, une conséquence du même incident) a été nettoyé après coup (`docker rm -f`) sans avoir rien écrit dans
TheHive. Résultat final : une seule alerte, un seul jeu de tags cohérent, aucune trace
double.

## Isolation de l'hôte (25/09)

`Contain_Attacker` répond au niveau réseau (une IP bloquée sur OPNsense), mais l'hôte
compromis lui-même reste connecté. `Quarantine_Host` ferme ce manque, en s'appuyant sur
l'artefact intégré de Velociraptor `Windows.Remediation.Quarantine` (déjà déployé pour le
DFIR, aucun nouvel agent à installer) :

```
Wazuh_Webhook → Build_TheHive_Alert → Create_TheHive_Alert → Enrich_With_Cortex
              → Contain_Attacker → Quarantine_Host → Trigger_DFIR_Hunt
```

- [`dfir/velociraptor_client.py`](../../dfir/velociraptor_client.py) : client VQL
  partagé — l'API serveur de Velociraptor est en gRPC + mTLS (pas de REST simple), donc
  le mécanisme passe par la CLI `velociraptor query` en SSH sur le serveur lui-même,
  avec la config API déjà provisionnée (`socforge-api`). Même rôle que
  `firewall/opnsense_client.py` pour OPNsense.
- [`dfir/quarantine_host.py`](../../dfir/quarantine_host.py) /
  [`unquarantine_host.py`](../../dfir/unquarantine_host.py) : CLI indépendante, même
  mécanisme que le nœud Shuffle. La politique bloque tout le trafic sauf DNS/DHCP et la
  connexion vers le frontend Velociraptor : l'hôte isolé reste pilotable par l'équipe de
  réponse, ce n'est pas une coupure à l'aveugle.
- [`soar/nodes/quarantine_host.py`](../../soar/nodes/quarantine_host.py) : nœud
  `execute_python`, gated **en plus** de `Contain_Attacker` — il n'agit que si le tag
  `auto-contained` est déjà posé (défense en profondeur : l'hôte n'est isolé que si la
  chaîne a déjà eu confiance en cette alerte au point de bloquer sa sortie réseau) et si
  l'alerte porte un observable `hostname` résolu à un client Velociraptor connu.

**Preuve (25/09, mécanisme testé en direct sur WIN01 avec les scripts réellement
livrés, pas un brouillon)** :

| Étape | Résultat |
|---|---|
| Baseline | `ping 10.10.10.110` depuis DFIR-HUNT : 0 % de perte |
| `python quarantine_host.py C.07dab9364f98e1aa` | flow `F.DAR7GRSD4OGN8` → `FINISHED` |
| `ping 10.10.10.110` pendant la quarantaine | **100 % de perte** |
| Canal Velociraptor pendant la quarantaine | `collect_client` (`Generic.Client.Info`) → `FINISHED` — le C2 survit, seul le reste du trafic est coupé |
| `python unquarantine_host.py C.07dab9364f98e1aa` | flow `F.DAR7H0GGK7ADK` → `FINISHED` |
| `ping 10.10.10.110` après retrait | 0 % de perte, restauré |

**Défaut trouvé en déployant le nœud dans la chaîne** : `ensure_chain()` ajoutait les
nouvelles branches sans jamais retirer les anciennes. En insérant `Quarantine_Host` entre
`Contain_Attacker` et `Trigger_DFIR_Hunt`, l'ancienne branche directe
`Contain_Attacker → Trigger_DFIR_Hunt` est restée en plus de la nouvelle route : sans
correction, `Trigger_DFIR_Hunt` se serait exécuté **deux fois** par alerte (double
republication MISP, note d'audit en double). Repéré en relisant les branches par API
juste après le déploiement, avant tout déclenchement réel. Corrigé à la racine dans
`ensure_chain()` : chaque nœud de la chaîne n'a par construction qu'un seul
prédécesseur, donc toute branche existante qui n'est plus la bonne est retirée avant
d'ajouter la nouvelle. Redéploiement testé : idempotent, 6 branches, aucun doublon.

Ce jour-là, le mécanisme est prouvé en direct sur la cible et le nœud est déployé et vérifié
structurellement par API. Le déclenchement de la chaîne à 6 nœuds sur une alerte réelle a eu lieu
ensuite : voir la section suivante.

## Une seule attaque, toute la chaîne (01/10)

Chaque maillon avait été prouvé séparément. Ce test suit **une seule attaque réelle** de bout en bout : la
même alerte Wazuh traverse les six nœuds de Shuffle, et chacun agit sur elle.

**Le défaut que ce test a révélé.** Aucune alerte du jeu de règles ne pouvait à la fois déclencher le
confinement (sévérité TheHive 3, donc règle Wazuh de niveau ≥ 12) et porter l'IP à bloquer : les règles de
niveau ≥ 12 (`100121`, `100131`, `100155`, `100103`) sont des événements locaux Sysmon sans IP source, et les
règles qui portent une IP (`100111` force brute, `100140` partage d'administration) plafonnent au niveau 10.
Le confinement de `Contain_Attacker` n'aurait donc jamais pu se déclencher sur une alerte naturelle. Corrigé
par la règle **`100141`** (voir [`detection-sheet-windows.md`](../../detections/windows/detection-sheet-windows.md)).

Trois autres défauts trouvés en préparant l'exécution, tous corrigés :

- **`Quarantine_Host` ne trouvait pas la machine** : Wazuh nomme l'agent `WIN01`, Velociraptor connaît le même
  poste sous son nom Windows `DESKTOP-75LAKDV`. Le nœud aurait renvoyé « aucun client » en silence.
  `Build_TheHive_Alert` joint maintenant le nom Windows (`win.system.computer`) en observable, et le nœud
  compare les noms courts sans tenir compte de la casse (6 cas testés hors Shuffle, dont le cas d'origine).
- **WIN01 n'auditait pas les partages** : la sous-catégorie « File Share » était sur « No Auditing », aucun
  événement 5140 n'était journalisé.
- **Des adresses de zone fausses** : WIN01 est en `10.10.30.110` dans sa zone, pas `10.10.30.10` (aucune
  machine ne porte cette dernière ; `docs/lab-registry.md` corrigé). La carte de zone de LINUX01 était
  configurée en `10.10.20.10/24` (le sous-réseau de la zone srv, et l'adresse de DC01) alors qu'elle est
  branchée sur la zone ep ; corrigée en `10.10.30.20/24`.

### Mode d'exécution

La contrainte de mémoire de l'hôte conduit à exécuter la chaîne en deux vagues dans la même session : l'attaque
et sa détection (PURPLE, OpenSense, WIN01, Wazuh), puis la chaîne de réponse (Shuffle, TheHive, Cortex, MISP,
Velociraptor, OpenSense). L'alerte réelle de la première vague a été livrée au webhook de Shuffle **33 minutes**
après sa création, avec le script d'intégration officiel de Wazuh (`/var/ossec/integrations/shuffle.py`,
copié depuis le manager) appliqué au JSON de l'alerte ; les six nœuds ont ensuite agi sur cette alerte, sans
intervention. Les heures ci-dessous sont en UTC (horloge du manager Wazuh et des serveurs).

**Horloge des machines Windows.** Pendant cette exécution, WIN01 et DC01 avançaient d'une heure : leur fuseau
« Morocco Standard Time » n'appliquait pas l'heure d'été (tables de règles anciennes) alors que l'horloge
virtuelle suit l'heure locale de l'hôte, d'où des horodatages Windows (`systemTime`, colonne « Last Active » de
Velociraptor) en avance d'une heure sur les heures de référence ci-dessous. Corrigé ensuite sur les deux
machines (fuseau UTC et horloge virtuelle en UTC, `rtcuseutc`) : WIN01 affiche désormais l'heure UTC réelle à
deux secondes de l'hôte ([capture](../../docs/screenshots/win01-horloge-utc-corrigee.png)). Les preuves de
l'attaque ci-dessous gardent leurs horodatages d'origine.

### Déroulé

Captures : [alerte Wazuh](../../docs/screenshots/wazuh-rule-100141-live.png), [alerte TheHive à l'issue de la chaîne](../../docs/screenshots/thehive-alert-chain-100141.png), [alias OpenSense](../../docs/screenshots/opnsense-blocked-attackers-attack-ip.png), [flows Velociraptor](../../docs/screenshots/velociraptor-win01-flows-isolation.png), [événement MISP #6 et sightings](../../docs/screenshots/misp-event6-sightings.png).

| Heure (UTC) | Maillon | Preuve |
|---|---|---|
| 10:01:23, 10:01:47, 10:01:57 | **Attaque** : PURPLE → WIN01 (`10.10.30.110`), 3 connexions à `IPC$` (`labuser`, `smbclient -n SOCFORGE-PURPLE`), à travers OpenSense | événements `5140` sur WIN01 |
| 10:01:37, 10:01:48 | **Wazuh** : règle `100140` (niveau 10), IP `10.10.50.10` | alertes `1790848897.1591582`, `1790848908.1605262` |
| 10:01:58 | **Wazuh** : règle `100141` (niveau 12, `T1021.002`) | alerte `1790848918.1618438` |
| 10:33:06 | MISP : événement #6 créé et publié (`ip-src 10.10.50.10`, `text SOCFORGE-PURPLE`) | MISP |
| **10:34:45** | **Webhook Shuffle** : l'alerte réelle est livrée (code retour 0) | script officiel de Wazuh |
| 10:34:57 (+12 s) | `Build_TheHive_Alert`, `Create_TheHive_Alert` : alerte TheHive `~286724176`, sévérité 3, 3 observables (IP, agent, nom Windows) | TheHive |
| ≈ 10:35 | `Enrich_With_Cortex` : corrélation avec l'événement #6, tag `misp:match` | TheHive |
| **10:35:21** (+36 s) | `Contain_Attacker` : `10.10.50.10` ajoutée à `BLOCKED_ATTACKERS`, tag `auto-contained` | alias lu sur OpenSense, note d'audit |
| **10:35:26** (+41 s) | `Quarantine_Host` : `WIN01` résolue en `DESKTOP-75LAKDV` (`C.07dab9364f98e1aa`), flow `F.DAV3ETNTNA6N0`, tag `auto-quarantined` | note d'audit, flow Velociraptor |
| **10:35:39 → 10:38:08** | `Trigger_DFIR_Hunt` : événement #6 republié (10:35:39), chasse `H.DAV3F15BPTMII` créée à 10:35:48 (+63 s), attente des sightings sans résultat dans la fenêtre de 150 s, tag `dfir:hunt-triggered` | note d'audit, MISP |

### Ce que Velociraptor a constaté sur WIN01

WIN01 était en sommeil pendant l'exécution de la chaîne : les flows ont attendu sa reprise (10:42:27) et se sont
exécutés à la reconnexion de l'agent (10:43:39). Le journal du flow d'isolation montre la politique posée par
`netsh ipsec` (`VelociraptorQuarantine`) avec un filtre qui n'autorise que le frontend Velociraptor
(`10.10.10.61:8889`).

| Heure (UTC) | Constat |
|---|---|
| 10:44:39 | `ping 10.10.10.110` (réseau mgmt) depuis DFIR-HUNT : **100 % de perte** |
| 10:44:57 | collecte `Generic.Client.Info` (flow `F.DAV3JADCETKMI`) lancée **pendant** l'isolation : `FINISHED`, 27 lignes — le canal Velociraptor survit |
| 10:49:41 | `ping 10.10.10.110` : toujours **100 % de perte** |
| 10:50:33 | `dfir/unquarantine_host.py` (flow `F.DAV3LUMOOAD74`), `FINISHED` avant 10:51:26 |
| 10:51:26 | `ping 10.10.10.110` : **0 % de perte**, réseau rétabli |

Le ping vers l'adresse de zone `10.10.30.110` n'est **pas** cité comme preuve : depuis DFIR-HUNT il est à 100 %
avant comme après l'isolation, la politique du pare-feu refusant la zone dfir vers la zone ep.

**Chasse** : les deux chasses (`EvtxHunter`, IOC `SOCFORGE-PURPLE`, dont `H.DAV3F15BPTMII`) ont retrouvé
**24 événements** sur WIN01 : 12 ouvertures de session réseau `4624` (`LogonType 3`) et 12 événements NTLM
`4022`. Six d'entre eux (3 `4624` et 3 `4022`) sont les traces des trois connexions de cette attaque ; les
dix-huit autres sont des traces d'un essai antérieur sur le même poste. `Custom.Server.MISP.Sightings` a
renvoyé **2 sightings** sur l'attribut `SOCFORGE-PURPLE` de l'événement #6 (10:47:51 UTC). L'attribut `ip-src`
n'a aucun sighting : `ip` est exclu de la chasse par conception (terrain de la NDR et de Wazuh).

## Processus d'investigation formalisé (25/09)

Jusque-là, une alerte promue en cas restait un cas vide : pas de tâches, pas de trace
structurée de l'investigation. Un modèle de cas réutilisable
(`caseTemplate` TheHive, 5 tâches : Triage, Confinement, Éradication, Récupération,
Retour d'expérience) a été créé par API, puis appliqué à un cas réel construit à partir
de l'alerte `~204804176` (voir
[`docs/incident-report-2026-09-24-cron-persistence.md`](../../docs/incident-report-2026-09-24-cron-persistence.md)
pour le récit complet). Les 5 tâches ont été renseignées avec les faits réels de
l'incident (décision de sévérité, abstention justifiée de `Contain_Attacker`, nature
bénigne de la source, absence d'impact, incident d'infrastructure du backend Shuffle),
puis closes. **Cas #10** (`~245764176`), clos en **`TruePositive`**.

TheHive calcule lui-même ses métriques de délai sur ce cas : détection < 1 s,
qualification et accusé de réception à 15 h 58 (délai entre l'incident du 24/09 et son
traitement formel le 25/09 — le cas a été construit le lendemain, pas en direct), et
surtout **résolution en 55 secondes** une fois les 5 tâches ouvertes — cohérent avec un
processus structuré mais rapide sur un incident déjà bien compris.

## Captures

- [`docs/screenshots/shuffle-wazuh-webhook-execution.png`](../../docs/screenshots/shuffle-wazuh-webhook-execution.png) — exécution déclenchée par Wazuh : charge utile reçue (règle 100210, ID d'alerte, horodatage), `Build_TheHive_Alert` en succès, `Create_TheHive_Alert` → 201
- [`docs/screenshots/thehive-alerts-from-wazuh-webhook.png`](../../docs/screenshots/thehive-alerts-from-wazuh-webhook.png) — l'alerte arrivée dans TheHive, avec l'ID de l'alerte Wazuh en référence
- [`docs/screenshots/shuffle-dynamic-trigger-misp-match.png`](../../docs/screenshots/shuffle-dynamic-trigger-misp-match.png) — workflow d'enrichissement : IP extraite en direct, Cortex 200

- [`docs/screenshots/thehive-case9-wazuh-alert-observables.png`](../../docs/screenshots/thehive-case9-wazuh-alert-observables.png) — cas #9 créé depuis une alerte Wazuh automatique : 3 observables (hôte, SHA-256, fichier)
- [`docs/screenshots/thehive-alert-soar-chain-cortex-misp.png`](../../docs/screenshots/thehive-alert-soar-chain-cortex-misp.png) — chaîne complète : alerte `~245788712`, rapports Cortex sur les observables, `MISP:Search="1 event(s)"` sur le fichier

- [`docs/screenshots/opnsense-blocked-attackers-alias.png`](../../docs/screenshots/opnsense-blocked-attackers-alias.png) — `Contain_Attacker` : IP bloquée en direct dans l'alias `BLOCKED_ATTACKERS`, GUI OPNsense
- [`docs/screenshots/thehive-alert-dfir-hunt-triggered.png`](../../docs/screenshots/thehive-alert-dfir-hunt-triggered.png) — alerte `~204804176` à l'issue de la chaîne à 5 nœuds : tags `misp:match` + `dfir:hunt-triggered`, note d'audit avec l'ID d'événement MISP republié
- [`docs/screenshots/thehive-case10-ir-playbook-closed.png`](../../docs/screenshots/thehive-case10-ir-playbook-closed.png) — cas #10 : 5 tâches du modèle IR closes, statut `True Positive`, résolution en 55 s
- [`docs/screenshots/wazuh-rule-100141-live.png`](../../docs/screenshots/wazuh-rule-100141-live.png) — l'attaque vue par Wazuh : règle 100141 (niveau 12) précédée des deux 100140 (niveau 10), agent `WIN01`, IP `10.10.50.10` (le tableau de bord affiche l'heure locale, UTC+1 : 11:01 = 10:01 UTC)
- [`docs/screenshots/thehive-alert-chain-100141.png`](../../docs/screenshots/thehive-alert-chain-100141.png) — l'alerte TheHive à l'issue de la chaîne : sévérité haute, tags `auto-contained`, `auto-quarantined`, `misp:match`, `dfir:hunt-triggered`, et les notes d'audit de chaque nœud
- [`docs/screenshots/opnsense-blocked-attackers-attack-ip.png`](../../docs/screenshots/opnsense-blocked-attackers-attack-ip.png) — l'alias `BLOCKED_ATTACKERS` d'OpenSense contenant `10.10.50.10`, ajouté par Shuffle
- [`docs/screenshots/velociraptor-win01-flows-isolation.png`](../../docs/screenshots/velociraptor-win01-flows-isolation.png) — les flows de WIN01 : isolation, collecte pendant l'isolation, chasse, levée d'isolation (la colonne « Last Active » suit l'horloge de WIN01, en avance)
- [`docs/screenshots/win01-horloge-utc-corrigee.png`](../../docs/screenshots/win01-horloge-utc-corrigee.png) — WIN01 après correction de l'horloge : fuseau UTC, heure UTC 11:56:58, soit l'heure réelle de l'hôte à deux secondes près
- [`docs/screenshots/misp-event6-sightings.png`](../../docs/screenshots/misp-event6-sightings.png) — événement MISP #6 : `SOCFORGE-PURPLE` avec 2 sightings renvoyés par Velociraptor, publié à 10:35:39 par la republication de `Trigger_DFIR_Hunt`

## Nettoyage

Fichiers `/etc/cron.d/socforge-soar-test`, `socforge-soar-obs-test` et
`socforge-soar-chain-test` supprimés du manager (leur suppression a servi de déclencheur
supplémentaire). L'IP de test `198.51.100.77` a été retirée de `BLOCKED_ATTACKERS` après
capture. Les workflows, les alertes, les cas #8 et #9 et l'événement MISP #4 restent
comme preuve.

## Résultats

| Critère | Valeur |
|---|---|
| Alerte Wazuh → Shuffle sans action humaine | ✅ (intégration native, webhook) |
| Shuffle → alerte TheHive (ID Wazuh en référence, tags MITRE) | ✅ (201, 14 s de bout en bout) |
| Enrichissement TheHive → Cortex → MISP, données dynamiques | ✅ (corrélation MISP réelle) |
| Création de cas TheHive | ✅ (cas #8 et #9, depuis des alertes Wazuh automatiques) |
| Observables extraits de l'alerte Wazuh | ✅ (fichier, SHA-256, hôte ; SHA-256 vérifié) |
| Chaîne Wazuh → Shuffle → TheHive → Cortex → MISP en une exécution | ✅ (33 s, tag `misp:match`) |
| Confinement automatique de l'attaquant (Contain_Attacker) | ✅ (blocage + retrait réels sur OPNsense, chemin négatif validé sur alerte réelle) |
| Boucle SOAR → DFIR (`misp:match` → chasse Velociraptor) | ✅ (`Trigger_DFIR_Hunt`, sighting positif et négatif validés séparément) |
| Isolation réseau de l'hôte (Quarantine_Host) | ✅ (100 % de perte pendant la quarantaine, canal Velociraptor conservé, restauration vérifiée — mécanisme prouvé en direct, nœud déployé et vérifié par API) |
| Processus d'investigation formalisé (tâches TheHive) | ✅ (modèle réutilisable, cas #10 clos `TruePositive`, résolu en 55 s) |
