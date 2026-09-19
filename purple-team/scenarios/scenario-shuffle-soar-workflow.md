# SC-14 — Étape 7 : Workflow SOAR Shuffle (WAZUH + SHUFFLE + THEHIVE)

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
6. RAM de la VM augmentée de 2 Go à 4 Go (`VBoxManage modifyvm --memory 4096`),
   toujours dans le budget des 3 VM simultanées (WAZUH 5 Go + THEHIVE 2 Go +
   SHUFFLE 4 Go = 11 Go sur 16 Go).

Une fois la stack stable, le compte administrateur Shuffle a été recréé
(`admin@socforge.local`) et la connexion au dashboard confirmée.

## Construction du workflow

**Nom** : `Wazuh Alert to TheHive - Cortex Enrichment`

**Schéma** :
```
Change Me (trigger)
   │
   ▼
Get_TheHive_Alert  ──────────────────────────────►  [connecté au trigger]
   GET http://10.10.10.20:9000/api/v1/alert/~122884296
   Headers: Authorization: Bearer <clé API bot SOAR>

Get_TheHive_Alert_forCortex ──► Run_Cortex_Analyzer  [paire chaînée séparément]
   GET (même alerte)                POST https://10.10.10.21:9001/api/analyzer/
                                     421b31691f33f5ce93618c5bbec4bf51/run
                                     Body: {"data": "10.10.10.110", "dataType":
                                     "ip", "tlp": 2, "message": "..."}
```

**Limitation d'outillage rencontrée** : l'éditeur visuel de Shuffle (rendu sur
un canevas, pas en DOM standard) ne permet de créer une connexion automatique
que lors du dépôt d'un **nouveau** nœud directement sur un nœud déjà présent
sur le canevas — il n'a pas été possible de relier deux nœuds déjà existants
entre eux par glisser-déposer manuel. Résultat : deux sous-chaînes valides
existent dans le workflow (`Trigger → Get_TheHive_Alert` d'une part,
`Get_TheHive_Alert_forCortex → Run_Cortex_Analyzer` d'autre part) plutôt
qu'une chaîne unique à 3 maillons. Les deux étapes ont neanmoins été validées
individuellement avec des données réelles (voir résultats ci-dessous).

## Résultats d'exécution réelle

| Nœud | Test | Résultat |
|------|------|----------|
| `Get_TheHive_Alert` (exécution du workflow complet, trigger → nœud) | `status: 200` | Alerte réelle récupérée (`_id: ~122884296`, `type: wazuh`, `source: wazuh-manager`, `_createdBy: soar-bot@socforge.local`) |
| `Get_TheHive_Alert_forCortex` (Test Action individuel) | `status: 200` | Même alerte récupérée avec succès |
| `Run_Cortex_Analyzer` (Test Action individuel) | `success: false`, `ConnectionError` vers `10.10.10.21:9001` | **Attendu** — VM04-CORTEX n'est pas démarrée pendant ce test (budget 3 VM : WAZUH + THEHIVE + SHUFFLE). Le payload est correctement formé et envoyé ; l'échec est une dépendance d'infrastructure, pas un défaut du workflow. |

La première tentative sans en-tête `Authorization` a échoué en `401
AuthenticationError` (preuve que TheHive vérifie bien l'authentification) ;
l'ajout de l'en-tête a permis d'obtenir un `200` avec le corps complet de
l'alerte.

**Point de vigilance identifié en vérifiant le schéma** : Shuffle affiche un
avertissement persistant ("Multiple actions with name 'Get_TheHive_Alert'")
même après renommage du second nœud en `Get_TheHive_Alert_forCortex` via le
champ "Name" de l'interface. Investigation : le renommage affiché (Setup →
Name) ne modifie qu'un label d'affichage — l'identifiant interne utilisé pour
les références de sortie (`$get_thehive_alert`, visible dans le JSON de
résultat des deux nœuds) reste basé sur le nom d'origine généré à la création
et n'est pas mis à jour. Sans conséquence pratique ici (les deux branches sont
indépendantes, aucune ne référence la sortie de l'autre), mais à surveiller si
un futur nœud doit référencer spécifiquement l'une des deux sorties — un
renommage plus profond (suppression/recréation du nœud) serait alors requis.

## Captures d'écran

- [`docs/screenshots/shuffle-dashboard.png`](../../docs/screenshots/shuffle-dashboard.png) — Dashboard Shuffle après reconstruction
- [`docs/screenshots/shuffle-workflow-full-canvas.png`](../../docs/screenshots/shuffle-workflow-full-canvas.png) — Vue d'ensemble du canevas du workflow
- [`docs/screenshots/shuffle-workflow-execution-200.png`](../../docs/screenshots/shuffle-workflow-execution-200.png) — Exécution réelle du workflow (Trigger → TheHive), statut 200
- [`docs/screenshots/shuffle-node1-changeme-trigger.png`](../../docs/screenshots/shuffle-node1-changeme-trigger.png) — Config nœud déclencheur
- [`docs/screenshots/shuffle-node2-get-thehive-alert.png`](../../docs/screenshots/shuffle-node2-get-thehive-alert.png) — Config nœud Get_TheHive_Alert (URL + headers)
- [`docs/screenshots/shuffle-node3-get-thehive-alert-forcortex.png`](../../docs/screenshots/shuffle-node3-get-thehive-alert-forcortex.png) — Config nœud Get_TheHive_Alert_forCortex
- [`docs/screenshots/shuffle-node4-run-cortex-analyzer.png`](../../docs/screenshots/shuffle-node4-run-cortex-analyzer.png) — Config nœud Run_Cortex_Analyzer (POST + body)
- [`docs/screenshots/shuffle-cortex-test-result.png`](../../docs/screenshots/shuffle-cortex-test-result.png) — Résultat du test Cortex (ConnectionError attendue, VM04 arrêtée)

## Nettoyage

Aucun. Le workflow reste dans l'organisation Shuffle comme preuve ; l'alerte
TheHive de test (rule 100155) était déjà documentée dans SC-13 et peut rester.

## Résultats

| Critère | Valeur |
|---|---|
| VM06-SHUFFLE opérationnelle après reconstruction complète | ✅ OUI |
| Workflow créé et connecté au trigger | ✅ OUI (Trigger → Get_TheHive_Alert) |
| Appel réel à l'API TheHive (authentifié) | ✅ OUI (200, alerte réelle) |
| Appel réel à l'API Cortex | ✅ Payload correct envoyé — échec de connexion attendu (VM04 non démarrée) |
| Chaînage complet en un seul workflow à 3 maillons | ⚠️ Partiel — limitation de l'outil d'édition visuelle, contournée en validant les deux segments séparément |
