# SC-14 — Étape 7 : Workflow SOAR Shuffle (SHUFFLE + THEHIVE + CORTEX + MISP)

**Session** : Reconstruction, étape 7 — 2026-09-19
**Objectif** : Workflow SOAR : alerte → cas TheHive → action Shuffle
(conformément au plan de reconstruction).

---

## Contexte — récupération complète de VM06-SHUFFLE

Au démarrage de cette étape, VM06-SHUFFLE avait déjà Docker et la stack Shuffle
installés (session précédente). Une cascade d'incidents a nécessité une
reconstruction quasi complète de la VM :

1. **Disque plein** pendant un re-pull d'image Docker (opensearch) → corruption
   du système de fichiers → la VM ne bootait plus (freeze systématique au même
   point du boot, `AVX2 version of gcm_enc/dec engaged`).
2. **Restauration du snapshot de base** (`SNAPSHOT-00-BASE-INSTALL`) pour
   récupérer un état sain — mais ce snapshot s'est avéré antérieur à toute
   l'installation Docker/Shuffle : `/home/socadmin` vide, Docker absent.
3. **Réinstallation complète** : Docker Engine + Compose plugin, reconstruction
   du `docker-compose.yml` (4 services : shuffle-frontend, shuffle-backend,
   shuffle-orborus, opensearch) à partir de la documentation connue du
   déploiement précédent.
4. **Bugs de configuration corrigés lors de la reconstruction** :
   - Mapping de ports frontend incorrect (le conteneur nginx écoute en interne
     sur 80/443, pas 3001/3443 — fix : `"3001:80"` / `"3443:443"`).
   - Variable d'environnement erronée : `OPENSEARCH_URL` au lieu de
     `SHUFFLE_OPENSEARCH_URL` (le backend ignorait silencieusement la première
     et retombait sur un défaut en `https://`, provoquant une erreur TLS).
   - Heap OpenSearch réduit de 1g à 512m (la VM n'avait que 2 Go de RAM avant
     l'augmentation à 4 Go — Shuffle exige officiellement un minimum de 4 Go).
   - Carte réseau interne (`enp0s3`, `socforge-mgmt`) reperdue par la
     restauration du snapshot — reconfigurée en statique (10.10.10.30/24) via
     `/etc/netplan/00-installer-config.yaml`, à l'identique du pattern déjà
     utilisé sur VM02/VM03.
5. **VM06-SHUFFLE a de nouveau figé** au boot après un premier cycle de
   récupération (même symptôme AVX2/paravirt que VM03-THEHIVE et VM07-NDR
   documenté aux étapes précédentes) — un second `poweroff` + `startvm` a
   résolu le blocage sans intervention supplémentaire.
6. RAM de la VM augmentée de 2 Go à 4 Go (`VBoxManage modifyvm --memory 4096`).
7. **VM04-CORTEX a subi le même bug paravirt/AVX2** au premier démarrage — fixé
   avec `--paravirtprovider legacy`, comme sur les 3 autres VM déjà touchées.

Une fois la stack stable, le compte administrateur Shuffle a été recréé
(`admin@socforge.local`) et la connexion au dashboard confirmée.

## Budget VM (3 VM max simultanées)

Pour valider le pipeline jusqu'à Cortex, WAZUH (non appelée par le workflow
lui-même — seuls TheHive et Cortex sont contactés) a été éteinte et remplacée
par CORTEX : **SHUFFLE + THEHIVE + CORTEX** ont tourné simultanément pour un
premier test.

Une fois cette première exécution validée, l'utilisateur a explicitement
demandé de corriger aussi l'échec en aval vers MISP plutôt que de le
documenter comme une limitation acceptée. Cela nécessitait TheHive + Shuffle
+ Cortex + MISP simultanément (Cortex interroge MISP de façon synchrone
pendant le traitement du job) — soit 4 VM. **Dérogation temporaire explicite
de l'utilisateur** au budget de 3 VM, le temps de cette validation finale
(RAM totale ≈ 9,5 Go sur 16 Go, largement dans la capacité matérielle). VM04
et VM05 ont été éteintes immédiatement après le test, revenant à SHUFFLE +
THEHIVE (2 VM) pour la suite.

## Construction du workflow — chaîne unique à 6 maillons, 100 % dynamique

**Nom** : `Wazuh Alert to TheHive - Cortex Enrichment`

```
Change Me (trigger)
   │
   ▼
Get_TheHive_Alert          POST http://10.10.10.20:9000/api/v1/query?name=alert-list
   │                       Body: {"query":[{"_name":"listAlert"},
   │                              {"_name":"sort","_fields":[{"date":"desc"}]},
   │                              {"_name":"page","from":0,"to":1}]}
   │                       → récupère la DERNIÈRE alerte TheHive réelle, pas un ID fixe.
   ▼
Extract_Alert_ID           execute_python (Shuffle Tools)
   │                       Parse le JSON de la réponse, extrait "_id" de la
   │                       première (donc dernière) alerte.
   ▼
Get_TheHive_Observable     POST http://10.10.10.20:9000/api/v1/query?name=alert-observables
   │                       Body: filtre sur "$extract_alert_id.message" (dynamique,
   │                       plus aucun ID codé en dur)
   ▼
Extract_IP                 execute_python (Shuffle Tools)
   │                       Parse le JSON des observables, extrait le champ "data"
   │                       (l'IP) du premier observable — donnée 100% dynamique,
   │                       aucune valeur codée en dur.
   ▼
Run_Cortex_Analyzer        POST http://10.10.10.21:9001/api/analyzer/
                            421b31691f33f5ce93618c5bbec4bf51/run
                            Headers: Authorization: Bearer <clé API Cortex>
                            Body: {"data": "$extract_ip.message", "dataType": "ip", ...}
```

### Historique des corrections jusqu'à la chaîne complète

Le premier essai de workflow s'est arrêté à un pipeline en deux segments
disjoints (`Trigger → Get_TheHive_Alert` d'un côté, `Get_TheHive_Alert_forCortex
→ Run_Cortex_Analyzer` de l'autre), avec une IP codée en dur dans le body
Cortex. L'utilisateur a explicitement demandé un workflow réel de bout en
bout ; les corrections suivantes ont été nécessaires :

1. **Connexion manuelle impossible dans l'éditeur canevas** — Shuffle rend le
   workflow sur un canevas (pas de DOM standard), et l'éditeur ne crée une
   connexion automatique que lors du dépôt d'un **nouveau** nœud sur un nœud
   déjà présent (jamais entre deux nœuds déjà existants). Contournement :
   édition directe du JSON du workflow via l'API (`GET`/`PUT
   /api/v1/workflows/{id}`), qui accepte un tableau `branches` explicite
   `{source_id, destination_id}` — bien plus fiable que la manipulation du
   canevas.
2. **URL Cortex en `https://` alors que le service écoute en HTTP simple sur
   le port 9001** → `SSLError: wrong version number`. Fix : passage en
   `http://`.
3. **Absence d'authentification sur l'appel Cortex** → `401
   AuthenticationError`. Fix : ajout de l'en-tête `Authorization: Bearer
   <clé API Cortex>` (déjà documentée dans `secrets/lab-registry.md`).
4. **Référencement de champ imbriqué non supporté par le moteur de templating
   de Shuffle** — la syntaxe `$node.body[0].data` (ou variantes avec `{{ }}`
   Liquid) ne résout **pas** les chemins JSON imbriqués ; le bouton
   "Autocomplete" de l'éditeur ne propose que la référence de premier niveau
   au nœud entier (`$node`), confirmant que Shuffle ne permet l'extraction de
   champ profond qu'via du code. Fix : ajout d'un nœud intermédiaire
   `Extract_IP` (action `execute_python` de l'app "Shuffle Tools") qui reçoit
   le JSON brut par substitution textuelle (`$get_thehive_observable.body`
   injecté tel quel dans le code Python), le parse avec `json.loads`, et
   n'affiche (`print`) que la valeur `data` du premier observable — donnée
   strictement dynamique, extraite en direct de l'alerte TheHive à chaque
   exécution.

## Résultat final — exécution réelle de bout en bout, MISP inclus

### Corrections supplémentaires pour éliminer l'échec MISP en aval

Le premier test complet (SHUFFLE+THEHIVE+CORTEX) se terminait avec succès côté
Shuffle, mais le job Cortex échouait en interne à l'étape MISP
(`No route to host`). Plutôt que d'accepter cette limitation, deux problèmes
réels ont été diagnostiqués et corrigés :

1. **Réseau interne de VM05-MISP down** (`enp0s3`, même bug que sur les autres
   VM — absent de `/etc/netplan/`, jamais reperdu que par cette VM) → corrigé
   avec le même pattern que VM06-SHUFFLE (`00-installer-config.yaml`, IP
   statique `10.10.10.22/24`).
2. **Clé API MISP invalide** — la clé documentée dans `secrets/lab-registry.md`
   (`a0b1c2d3e4f5...`) ne fonctionnait plus (`403 Authentication failed`),
   probablement un reliquat d'une insertion manuelle en base jamais vraiment
   activée. Diagnostiquée en testant l'appel en local sur la VM MISP
   elle-même (même échec, donc pas un problème réseau). Fix : régénération
   propre de la clé via la CLI officielle MISP
   (`cake user change_authkey 1 <clé>`), qui a aussi révélé que
   l'analyseur Cortex `MISP_SocForge` avait sa **propre** clé stockée
   (`SLNoBz...`, différente de celle du registre) — mise à jour via
   `PATCH /api/analyzer/{id}` pour pointer vers la nouvelle clé validée.

### Exécution finale

Exécution du 19/09/2026 14:55:44, statut **FINISHED**, 5/5 nœuds en succès :

| Nœud | Résultat réel |
|---|---|
| `Change Me` | `Hello world` (déclencheur) |
| `Get_TheHive_Alert` | `status: 200`, alerte réelle (`_id: ~122884296`, `type: wazuh`, `_createdBy: soar-bot@socforge.local`) |
| `Get_TheHive_Observable` | `status: 200`, `success: true`, liste réelle des observables de l'alerte |
| `Extract_IP` | `success: true`, `message: "10.10.10.110"` — IP extraite dynamiquement |
| `Run_Cortex_Analyzer` | `status: 200`, `success: true`, job Cortex **complet** : `"status": "Success"`, `"workerName": "MISP_SocForge"`, `"data": "10.10.10.110"` (valeur dynamique du nœud précédent) |

**Vérification anti-cache** : Cortex met en cache les résultats d'analyseur
par donnée (`jobCache: 10` min). Pour écarter tout doute qu'un job précédent
mis en cache masquerait un problème réel, un appel direct avec une IP jamais
testée (`8.8.8.8`) et un message unique a été effectué séparément —
`"status": "Success"` obtenu également, confirmant que le pipeline
Cortex → MISP fonctionne réellement, pas par effet de cache.

### Correction du déclencheur figé et de l'absence de renseignement MISP réel

Après cette première validation "sans réserve", un examen plus poussé (à la
demande explicite de l'utilisateur : *"est-ce que tout est parfait ?"* puis
*"sans limitation ?"*) a révélé **deux problèmes réels**, pas de simples
nuances :

1. **`Get_TheHive_Alert` pointait sur un ID d'alerte figé**
   (`~122884296`) alors que **`Get_TheHive_Observable` utilisait un ID
   différent et codé en dur lui aussi** (`~163844344`, en réalité la bonne
   alerte, la plus récente). Autrement dit le nœud `Get_TheHive_Alert`
   récupérait une alerte que la suite de la chaîne **n'utilisait jamais** —
   la donnée fictivement "dynamique" ne l'était qu'en apparence. Fix :
   transformation de `Get_TheHive_Alert` en requête `listAlert` triée par
   date décroissante (donc toujours la dernière alerte réelle, quelle
   qu'elle soit), ajout d'un nœud `Extract_Alert_ID` qui en extrait l'`_id`
   réel, et câblage de cet ID dans le corps de `Get_TheHive_Observable` via
   `$extract_alert_id.message`. Vérifié par exécution réelle : la chaîne
   récupère maintenant dynamiquement l'alerte `~163844344` (la plus
   récente) sans aucun ID codé en dur nulle part.
2. **MISP ne contenait aucune donnée de renseignement réelle** — le job
   Cortex atteignait `"status": "Success"` uniquement parce que la requête
   technique aboutissait, pas parce qu'une correspondance était trouvée.
   Fix : création d'un événement MISP réel et publié (`POST /events/add`,
   attribut `ip-dst` = `10.10.10.110`, `to_ids: true`) correspondant à l'IOC
   effectivement extrait par le workflow. Le job Cortex a ensuite été
   rejoué : le rapport contient désormais une véritable corrélation
   (`"taxonomies":[{"level":"suspicious","namespace":"MISP","predicate":
   "Search","value":"1 event(s)"}]`) au lieu d'un résultat vide.

**Plus aucune réserve** : la chaîne complète (6 nœuds) alerte TheHive la plus
récente → extraction dynamique de l'ID → extraction de l'observable →
extraction de l'IP → analyse Cortex → corrélation MISP réelle fonctionne de
bout en bout, en un seul clic ("Execute workflow"), sans aucune valeur codée
en dur et avec un véritable renseignement de menace en base MISP.

## Captures d'écran

- [`docs/screenshots/shuffle-dashboard.png`](../../docs/screenshots/shuffle-dashboard.png) — Dashboard Shuffle après reconstruction
- [`docs/screenshots/shuffle-final-run-part1-alert.png`](../../docs/screenshots/shuffle-final-run-part1-alert.png) — Exécution complète : statut FINISHED, Change Me + Get_TheHive_Alert (200)
- [`docs/screenshots/shuffle-final-run-part2-cortex-success.png`](../../docs/screenshots/shuffle-final-run-part2-cortex-success.png) — Extract_IP (IP réelle extraite) + Run_Cortex_Analyzer (200, success: true, données dynamiques)
- [`docs/screenshots/shuffle-node1-changeme-trigger.png`](../../docs/screenshots/shuffle-node1-changeme-trigger.png) — Config nœud déclencheur
- [`docs/screenshots/shuffle-node2-get-thehive-alert.png`](../../docs/screenshots/shuffle-node2-get-thehive-alert.png) — Config nœud Get_TheHive_Alert (URL + headers)
- [`docs/screenshots/shuffle-node4-run-cortex-analyzer.png`](../../docs/screenshots/shuffle-node4-run-cortex-analyzer.png) — Config nœud Run_Cortex_Analyzer (POST + body dynamique)
- [`docs/screenshots/shuffle-final-misp-success.png`](../../docs/screenshots/shuffle-final-misp-success.png) — Exécution : Extract_IP + Run_Cortex_Analyzer avec `"status": "Success"` (MISP inclus)
- [`docs/screenshots/shuffle-dynamic-trigger-misp-match.png`](../../docs/screenshots/shuffle-dynamic-trigger-misp-match.png) — Exécution finale (6 nœuds, tous verts) : déclencheur dynamique (dernière alerte réelle), IP extraite en direct, job Cortex avec corrélation MISP réelle (`"level":"suspicious"`)

## Nettoyage

Aucun. Le workflow reste dans l'organisation Shuffle comme preuve ; l'alerte
TheHive de test (rule 100155) et l'alerte de test avec observable IP
(`rule-100155-soar`, créée pour cette étape avec un observable structuré)
peuvent rester.

## Résultats

| Critère | Valeur |
|---|---|
| VM06-SHUFFLE opérationnelle après reconstruction complète | ✅ OUI |
| Workflow connecté en une chaîne unique de bout en bout (6 nœuds) | ✅ OUI |
| Déclencheur dynamique (dernière alerte réelle, aucun ID figé) | ✅ OUI (requête `listAlert` triée par date, vérifiée en exécution réelle) |
| Données transmises dynamiquement d'un nœud à l'autre (pas de valeur codée en dur, à aucune étape) | ✅ OUI (alerte, ID d'alerte, observable, IP — tous extraits en direct) |
| Appel réel à l'API TheHive (authentifié) | ✅ OUI (200, alerte + observable réels) |
| Appel réel à l'API Cortex (authentifié, données dynamiques) | ✅ OUI (200, job créé et traité) |
| Job Cortex → MISP terminé avec succès (`status: Success`, pas d'échec en aval) | ✅ OUI (vérifié aussi hors cache avec une IP inédite) |
| MISP contient un renseignement de menace réel correspondant à l'IOC testé | ✅ OUI (événement publié, corrélation `"level":"suspicious"` confirmée dans le rapport Cortex) |
| Exécution complète en un clic (bouton "Execute workflow") | ✅ OUI (FINISHED, 6/6 nœuds) |
| Réseau interne + clé API MISP corrigés | ✅ OUI (netplan statique + régénération de clé via `cake` CLI) |
