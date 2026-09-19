# Plan de reconstruction — 12 VMs, 3 max simultanées

> Document de travail (non destiné aux recruteurs) : trace la séquence d'utilisation des
> 12 VMs prévues dès l'origine du projet, avec leur rôle, et corrige les faiblesses
> identifiées le 2026-09-17 (preuves visuelles dashboard manquantes, VMs jamais utilisées,
> attaques lancées depuis la victime plutôt que depuis Kali).

## Inventaire et rôles

| VM | IP | Rôle | RAM |
|----|----|------|-----|
| VM01-FW | — (OPNsense) | Pare-feu/segmentation réseau | 1024 |
| VM02-WAZUH | 10.10.10.10 | Manager SIEM (permanent) | 5120 |
| VM03-THEHIVE | 10.10.10.20 | Gestion de cas (SOAR) | 2048 |
| VM04-CORTEX | 10.10.10.21 | Analyseurs automatisés (SOAR) | 1536 |
| VM05-MISP | 10.10.10.22 | Threat intel / IOCs | 2048 |
| VM06-SHUFFLE | 10.10.10.30 | Orchestration SOAR | 3072 |
| VM07-NDR | — | Zeek/Suricata (détection réseau) | 3072 |
| VM08-DFIR-HUNT | — | Threat hunting / forensics | 3072 |
| VM09-DC01 | 10.10.10.109 / .50 | Cible Windows Server (victime) | 3072 |
| VM10-WIN01 | — | Cible Windows 11 (victime) | 4096 |
| VM11-LINUX01 | 10.10.10.111 | Cible Linux (victime) | 2048 |
| VM12-PURPLE | — | Kali — **source d'attaque** | 2048 |

## Faiblesses corrigées avant la reprise du planning

1. **Dashboard Wazuh inaccessible** — aucun port-forward vers le 443 de la VM. Corrigé :
   `--natpf2 "wazuh-dash,tcp,127.0.0.1,8443,,443"`. Dashboard accessible sur
   `https://localhost:8443` une fois WAZUH démarrée.
2. **Attaques lancées depuis la console de la victime** (DC01, WIN01) au lieu de PURPLE —
   pas réaliste pour un scénario purple-team. À partir de maintenant : PURPLE est la
   source, la victime est uniquement observée côté logs/Wazuh.
3. **8 VMs sur 12 sans rôle démontré** (FW, THEHIVE, CORTEX, MISP, SHUFFLE, NDR,
   DFIR-HUNT, LINUX01 côté détection). Plan ci-dessous pour couvrir chacune.

## Séquence enchaînée (3 VMs max simultanées)

WAZUH reste allumée en fil rouge (manager permanent, 5 Go) ; on fait tourner au plus 2
autres VMs à côté d'elle.

| Étape | Trio actif | Objectif |
|-------|-----------|----------|
| 1 | WAZUH seule | Vérifier stack complète (manager+indexer+dashboard), capture dashboard des règles déjà prouvées (100153, 100178, 100120/121/131/127) |
| 2 | WAZUH + PURPLE + DC01 | Scan réseau (100101/100102) et brute force (100110/100111) lancés **depuis PURPLE contre DC01** |
| 3 | WAZUH + PURPLE + LINUX01 | sudo abuse (100200) et cron persistence (100210) depuis PURPLE contre LINUX01 |
| 4 | WAZUH + DC01 + WIN01 | Règles restantes nécessitant l'agent local : 100103 (LSASS), 100139/100140 (mouvement latéral DC01↔WIN01), 100147 (registre), 100155 (injection), 100186 (profil PowerShell, re-test) |
| 5 | WAZUH + NDR + PURPLE | Trafic Zeek/Suricata généré par une attaque PURPLE→cible, capture NDR |
| 6 | WAZUH + THEHIVE + CORTEX | Créer un cas depuis une alerte Wazuh, lancer un analyseur Cortex |
| 7 | WAZUH + SHUFFLE + THEHIVE | Workflow SOAR : alerte → cas TheHive → action Shuffle |
| 8 | WAZUH + MISP + DFIR-HUNT | Import IOC MISP, requête de chasse DFIR-HUNT sur un artefact laissé par les tests précédents |
| 9 | WAZUH + FW | Vérifier les règles de segmentation OPNsense (logs de blocage inter-VLAN) |

Chaque étape : démarrer, attendre stabilisation complète (service actif, pas juste port
ouvert), exécuter, capturer la preuve, **éteindre avant l'étape suivante** sauf WAZUH.

## Faiblesses additionnelles trouvées et corrigées en cours de route

4. **PURPLE (Kali) sans SSH exploitable** — `sshd` tournait depuis le boot mais restait
   inaccessible depuis l'hôte. Cause racine : `eth1` (le NIC NAT, nic2) était UP mais
   n'avait jamais reçu de bail DHCP (aucune adresse IP), donc aucune réponse ne pouvait
   partir par cette interface. Corrigé via `nmcli device connect eth1`, avec autoconnect
   activé pour survivre au reboot. Root cause probable : cette VM a été créée/clonée sans
   que le NIC NAT soit inclus dans la configuration réseau initiale (seuls eth0/eth2
   statiques étaient définis dans `/etc/network/interfaces`).
5. **Deux règles NAT dupliquées** sur PURPLE (`ssh`->19022 et `sshtemp`->2244, toutes deux
   vers le port invité 22) — nettoyées, une seule règle `sshpurple`->19023 conservée.
6. **Mot de passe dashboard Wazuh invalide** dans le registre — réinitialisé via
   `wazuh-passwords-tool.sh`, nouvelle valeur documentée dans `secrets/lab-registry.md`.
7. **Sysmon (Sysinternals) jamais installé sur DC01** — installé avec une config réseau-
   inclusive (la config SwiftOnSecurity par défaut exclut trop de trafic pour nos tests).
8. **Deux vrais bugs de règle** trouvés via `wazuh-logtest` : 100103 et 100147
   référençaient des groupes `sysmon_eventN` inexistants (convention réelle :
   `sysmon_event_N` avec underscore pour N≥10 ; séparateur OR = `|`, pas `,`). Corrigés,
   revalidés sans avertissement.
9. **Agent dc01 bloqué en `Pending`** après redémarrage du manager (poignée de main
   incomplète) — corrigé par `Restart-Service WazuhSvc -Force` côté DC01.
10. **Scan FIM WIN01 bloqué à 0% CPU indéfiniment** — root cause : fichiers `.gz`
    orphelins dans `queue\diff\file\`, laissés par des redémarrages forcés antérieurs
    pendant qu'un scan tournait, bloquant tout renommage FIM (`ERROR (1124): File
    exists`). Nettoyé (`queue\diff\file\` + `queue\fim\db\fim.db` supprimés). Aggravé
    par une RAM hôte descendue à ~2 Go libres avec 3 VMs actives.
11. **`wazuh-db` planté sur le manager** (`Unable to connect to socket 'queue/db/wdb'`
    en boucle) — processus zombie malgré `wazuh-control status` l'affichant "running".
    Corrigé par un redémarrage complet du manager (`systemctl restart wazuh-manager`).
12. **Règle 100147 : `if_group` n'a pas fonctionné pour cette règle custom précise**,
    même avec un groupe correctement tagué (confirmé par test A/B contre `if_sid`
    direct) — possiblement lié à l'incident #11. Corrigé en chaînant sur
    `<if_sid>92300</if_sid>` (règle officielle équivalente) plutôt que sur le groupe.
    Voir `detections/windows/detection-sheet-windows.md` pour le détail complet de
    l'investigation.
13. **Même bug `if_group` vs `if_sid` retrouvé sur 100103 et 100155** (chaînage
    `<if_group>sysmon_event_10</if_group>` et `<if_group>sysmon_event8</if_group>`
    respectivement) — corrigé par le même pattern : chaînage direct sur la règle/le
    parent officiel (`92900` pour 100103, `185006` pour 100155). Déployé et validé en
    direct le 2026-09-18 (voir Étape 4 ci-dessous).
14. **Fichier `.restart` orphelin bloquant l'API Wazuh** (`/var/ossec/var/run/.restart`,
    0 octet, jamais nettoyé après un redémarrage précédent) — l'API (port 55000)
    répondait `error 1017: daemons not ready` en boucle, empêchant le dashboard de se
    connecter (`Offline` dans API Connections). Supprimé manuellement ; API et
    dashboard de nouveau opérationnels.

## Statut

- [x] Faiblesse 1 corrigée (port-forward dashboard)
- [x] Faiblesses 4-9 corrigées (PURPLE SSH/NAT, doublons de règles, mdp dashboard, Sysmon
  manquant, 2 bugs de règle, agent bloqué)
- [x] Étape 1 — captures dashboard des règles déjà prouvées (3 captures, référencées dans detection-sheet-windows.md)
- [x] Étape 2 — scan + brute force depuis PURPLE contre DC01 : 100101/100102/100110/100111
  validées en direct, captures dashboard incluses (voir `scenario-T1046-port-scan.md` et
  `scenario-T1110-brute-force.md`). Bug `<same_source_ip/>` trouvé et corrigé sur 100111.
- [x] Étape 3 — LINUX01 depuis PURPLE : 100200/100210 validées en direct (voir
  `scenario-T1548-T1053-linux.md`). Agent recréé dans un groupe `linux` dédié (était dans
  `default`, config Windows sans effet) ; NIC mgmt et redirection SSH réparés/persistés.
- [x] Étape 4 — DC01/WIN01 : 100140/100147/100178 validées en direct depuis WIN01 (voir
  `scenario-T1021-win01-to-dc01.md` et `detection-sheet-windows.md`). 100147 a nécessité
  trois corrections successives (groupe mal nommé, blocage FIM réel dû à des fichiers
  orphelins, puis la vraie root cause : `if_group` ne déclenchait pas cette règle custom
  précise — corrigé en chaînant sur `if_sid` directement). Au passage, un `wazuh-db`
  planté sur le manager a été diagnostiqué et corrigé (redémarrage complet du service).
  - **100103** : root cause identique à 100147 trouvée et corrigée le 2026-09-18 —
    `<if_group>sysmon_event_10</if_group>` chaîné sur `<if_sid>92900</if_sid>` (règle
    officielle LSASS/EventID10). Testé en direct après redémarrage propre de WIN01 :
    `OpenProcess` LSASS (droits 0x1010) exécuté en Administrator → `Handle: 0` (accès
    refusé). **Découverte réelle** : `RunAsPPL = 0x2` (LSA Protection) est actif sur
    WIN01, bloquant l'accès à un stade du noyau antérieur au callback Sysmon — aucun
    EventID 10 n'est généré pour cette tentative, ni pour aucun outil de dump réel
    dans les mêmes conditions. La règle reste logiquement correcte (structure
    identique à 92900, validée en Phase 2 `wazuh-logtest`) ; la valider en direct
    nécessiterait de désactiver une vraie protection OS, jugé non souhaitable. Voir
    `purple-team/scenarios/scenario-T1003-lsass-access.md`.
  - **100155** : même correction appliquée (chaînage sur `<if_sid>185006</if_sid>`, la
    règle de base EventID8 dans `0330-sysmon_rules.xml`). **Testé en direct et
    validé** : injection de thread bénigne (`CreateRemoteThread` → `kernel32!Sleep`)
    depuis PowerShell vers `notepad.exe` (non protégé par PPL) → alerte confirmée,
    18 correspondances sur le dashboard. Voir
    `purple-team/scenarios/scenario-T1055-process-injection.md` et capture
    `docs/screenshots/wazuh-dashboard-rule-100155-live.png`.
  - **Incident annexe corrigé** : un fichier `.restart` orphelin dans
    `/var/ossec/var/run/` bloquait l'API Wazuh (port 55000) en état "restarting"
    indéfiniment, empêchant le dashboard de se connecter. Supprimé manuellement ;
    l'authentification API et le dashboard fonctionnent de nouveau normalement.
- [x] Étape 5 — NDR : deux bugs réels trouvés et corrigés sur VM07-NDR, jamais démarrée
  avec succès jusqu'ici.
  1. **Crash noyau au boot** (trace d'appel complète en boucle sur le test
     `raid6: avx2x4`) — causé par `CPUProfile: host` (AVX2 exposé) combiné à
     `Paravirt. Provider: Default` (détecté comme KVM par le noyau invité). Corrigé
     par `VBoxManage modifyvm SF-VM07-NDR --paravirtprovider legacy`.
  2. **Suricata et Zeek écoutaient sur la mauvaise interface** (`enp0s9`, le NAT, sans
     trafic inter-VM). Après une première correction erronée vers `enp0s3` (dont
     l'adressage IP `10.10.10.40/24` était trompeur — vérification par MAC address :
     `enp0s3` = NIC1 = réseau isolé `socforge-ndr`), la bonne interface s'est révélée
     être `enp0s8` (NIC2 = `socforge-mgmt`, le réseau partagé par toutes les autres
     VMs). Corrigé dans `suricata.yaml` et `node.cfg`, mode promiscuous activé côté OS
     (`ip link set enp0s8 promisc on`) et côté hyperviseur (`--nicpromisc2 allow-all`).
  Testé avec un scan nmap depuis PURPLE contre WAZUH : Suricata et Zeek capturent
  tous les deux exactement les 7 sessions TCP du scan. Voir
  `purple-team/scenarios/scenario-ndr-purple-scan.md`.
- [x] Étape 6 — TheHive + Cortex : même crash noyau que VM07-NDR corrigé sur
  VM03-THEHIVE (`--paravirtprovider legacy`). Alerte créée avec succès depuis un
  test représentant la règle Wazuh 100155 (`POST /api/v1/alert` → 201). **Découverte
  logicielle réelle** : la licence TheHive de ce déploiement (bandeau "invalid
  license" dans l'UI) bloque **toute** opération d'écriture liée aux cas/observables
  (création de cas, ajout d'observable), quel que soit le compte ou profil utilisé —
  confirmé par test sur 3 comptes différents et sur un cas existant, pas seulement à
  la création. La création d'alerte (utilisée pour l'intégration SIEM) n'est pas
  concernée et fonctionne normalement. Cortex : un analyseur configuré
  (`MISP_SocForge`) exécuté avec succès sur une IP de test (job soumis, script
  exécuté, rapport renvoyé) — échec attendu car MISP (étape 8) n'est pas encore
  démarrée. Voir `purple-team/scenarios/scenario-thehive-cortex-100155.md`.
- [x] Étape 7 — Shuffle : reconstruction complète de VM06-SHUFFLE après une
  cascade d'incidents (disque plein → corruption FS → boot bloqué → restauration
  d'un snapshot antérieur à l'installation Docker → réinstallation complète de
  Docker/Compose/Shuffle). Bugs corrigés en repartant de zéro : mapping de ports
  frontend (80/443 réels vs 3001/3443 supposés), nom de variable d'env
  `SHUFFLE_OPENSEARCH_URL` (pas `OPENSEARCH_URL`), heap OpenSearch réduit à 512m,
  RAM de la VM augmentée de 2 à 4 Go (minimum officiel Shuffle), carte réseau
  interne reconfigurée en statique (perdue par la restauration de snapshot).
  Workflow SOAR créé (`Wazuh Alert to TheHive - Cortex Enrichment`), **chaîne
  unique de bout en bout à 5 nœuds** : Change Me → Get_TheHive_Alert (GET
  authentifié, 200) → Get_TheHive_Observable (POST, récupère l'observable IP
  réel de l'alerte) → Extract_IP (execute_python, extrait dynamiquement l'IP,
  aucune valeur codée en dur) → Run_Cortex_Analyzer (POST authentifié vers
  Cortex avec l'IP extraite en direct). Exécution complète en un clic validée :
  FINISHED, 5/5 nœuds en succès, job Cortex réellement créé avec la donnée
  dynamique (`data: "10.10.10.110"` provenant du nœud précédent, pas d'une
  constante). Bugs Cortex corrigés au passage : URL en `https://` alors que le
  service écoute en HTTP simple (`SSLError`), authentification manquante
  (`401`), et limitation du moteur de templating Shuffle qui ne résout pas les
  chemins JSON imbriqués (`$node.body[0].data` ne fonctionne pas — seule la
  référence de premier niveau au nœud entier est supportée, confirmé via le
  bouton Autocomplete de l'éditeur), contournée avec un nœud Python
  intermédiaire. La connexion des nœuds elle-même a nécessité une édition
  directe du JSON du workflow via l'API (`PUT /api/v1/workflows/{id}`),
  l'éditeur canevas ne permettant de connecter que lors du dépôt d'un nouveau
  nœud sur un nœud existant, jamais entre deux nœuds déjà présents.
  **Chaîne complète validée sans réserve, MISP inclus** : job Cortex terminé
  avec `"status": "Success"` (pas seulement soumis) grâce à deux corrections
  supplémentaires sur VM05-MISP (réseau interne statique reperdu par un
  redémarrage, clé API invalide régénérée via la CLI `cake`, et clé
  correspondante mise à jour dans la config de l'analyseur Cortex). Validé
  aussi hors cache Cortex (job indépendant avec IP inédite). Dérogation
  temporaire et explicite de l'utilisateur au budget 3 VM (4 VM : SHUFFLE +
  THEHIVE + CORTEX + MISP, ≈9,5 Go de RAM) le temps de cette vérification
  finale ; retour à 2 VM (SHUFFLE + THEHIVE) immédiatement après. Voir
  `purple-team/scenarios/scenario-shuffle-soar-workflow.md`.
- [ ] Étape 8 — MISP + DFIR-HUNT
- [ ] Étape 9 — FW
