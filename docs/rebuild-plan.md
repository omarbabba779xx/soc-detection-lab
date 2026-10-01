# Plan de reconstruction — 12 VMs

> Journal de reconstruction : séquence d'utilisation des 12 VM prévues dès l'origine du
> projet, rôle de chacune, et faiblesses trouvées puis corrigées en chemin. Point de
> départ : l'audit du 2026-09-17 (preuves visuelles manquantes, VM jamais utilisées,
> attaques lancées depuis la victime plutôt que depuis Kali).

## Inventaire et rôles

| VM | IP mgmt | Rôle | RAM |
|----|----|------|-----|
| VM01-FW | 10.10.10.1 (+ passerelle des 5 zones) | Pare-feu/segmentation réseau | 1024 |
| VM02-WAZUH | 10.10.10.10 | Manager SIEM (permanent) | 5120 |
| VM03-THEHIVE | 10.10.10.20 | Gestion d'incidents | 2048 |
| VM04-CORTEX | 10.10.10.21 | Analyseurs automatisés | 1536 |
| VM05-MISP | 10.10.10.22 | Threat intel / IOCs | 2048 |
| VM06-SHUFFLE | 10.10.10.30 | Orchestration SOAR | 4096 |
| VM07-NDR | 10.10.10.40 | Zeek/Suricata (détection réseau) | 3072 |
| VM08-DFIR-HUNT | 10.10.10.61 | Threat hunting / forensics (Velociraptor) | 3072 |
| VM09-DC01 | 10.10.10.109 | Cible Windows Server (victime) | 3072 |
| VM10-WIN01 | 10.10.10.110 | Cible Windows 11 (victime) | 4096 |
| VM11-LINUX01 | 10.10.10.111 | Cible Linux (victime) | 2048 |
| VM12-PURPLE | — (zone 10.10.50.10 ; 10.10.10.60 retirée le 24/09) | Kali — **source d'attaque** | 2048 |

Réseaux de zone, logiciels et flux : `docs/lab-registry.md`.

## Chronologie du projet

Le projet a été réalisé en plusieurs périodes de travail, séparées par des pauses. Les
dates visibles dans les preuves (journaux, fichiers, identifiants) s'expliquent par ce
calendrier. Ce ne sont pas des incohérences.

| Période | Travail |
|---|---|
| 02/08 → 15/08/2026 | Première réalisation : cadrage, création des 12 VM, Wazuh, premiers scénarios purple-team, premier déploiement Velociraptor/MISP |
| 16/08 → 12/09 | Pause (environ 4 semaines) |
| 13/09 → 19/09 | Reprise : audit de l'existant (17/09), puis reconstruction étape par étape (ce plan) |
| 20/09 → 21/09 | Courte pause |
| 22/09 → 23/09 | Étape 8 (MISP + DFIR-HUNT), intégration native MISP ↔ Velociraptor, puis audit complet : réparation de Wazuh, règles 100139/100186, étape 9 (pare-feu), NDR raccordée au SIEM, déclenchement automatique Wazuh → Shuffle → TheHive |
| 24/09 → 01/10 | Levée des limites restantes : cause de fond de l'instabilité des VM (hyperviseur Windows), TLS vérifié partout (CA du lab), chasse et sightings automatiques, agent DC01, journaux Windows, licence TheHive et cas, chaîne SOAR complète en une exécution, puis quatre limites de process (confinement réseau automatique, boucle SOAR → DFIR, isolation hôte, processus d'investigation formalisé avec métriques et rapport d'incident), et enfin une seule attaque suivie dans toute la chaîne (01/10) |

Conséquences visibles :

- Des éléments datés d'**août** sur les VM viennent de la première réalisation et sont
  normaux : journaux Windows qui remontent au 03/08 et au 13/08, service Velociraptor et
  identité client de WIN01 créés le 04/08, flux MISP activés le 04/08.
- Une VM laissée allumée pendant la veille de l'hôte reprend avec une **horloge en
  retard**. C'est arrivé le 23/09 (environ 14 h sur VM08 et WIN01). Les horloges ont été
  recalées avant les tests, pour que les horodatages des preuves restent justes.

## Faiblesses corrigées avant la reprise du planning

1. **Dashboard Wazuh inaccessible** — aucun port-forward vers le 443 de la VM. Corrigé :
   `--natpf2 "wazuh-dash,tcp,127.0.0.1,8443,,443"`. Dashboard accessible sur
   `https://localhost:8443` une fois WAZUH démarrée.
2. **Attaques lancées depuis la console de la victime** (DC01, WIN01) au lieu de PURPLE —
   pas réaliste pour un scénario purple-team. À partir de maintenant : PURPLE est la
   source, la victime est uniquement observée côté logs/Wazuh.
3. **8 VMs sur 12 sans rôle démontré** (FW, THEHIVE, CORTEX, MISP, SHUFFLE, NDR,
   DFIR-HUNT, LINUX01 côté détection). Plan ci-dessous pour couvrir chacune.

## Séquence enchaînée

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
    par une RAM hôte descendue à ~2 Go libres avec 3 VMs actives. **Cause réelle trouvée
    le 2026-09-23** : `report_changes` sur tout `Program Files` remplissait `queue\diff`
    jusqu'au quota de 1 Go et le scan s'enlisait. Le nettoyage ne faisait que repousser
    le problème (voir faiblesse 17).
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

### Audit du 2026-09-23

15. **Wazuh à l'arrêt depuis le 19/09 à 12:24.** Le disque racine était plein à 100 %
    (`database or disk is full`) : 29 Go de fichiers temporaires laissés par le module de
    vulnérabilités (`queue/vd_updater/tmp`), sur un volume LVM de 49 Go alors que le
    groupe en offrait 98 (l'installeur Ubuntu n'en alloue que la moitié). Volume étendu
    (`lvextend -r`, 20 % utilisés), fichiers temporaires supprimés, module de
    vulnérabilités désactivé (hors périmètre). Indexeur `green`, historique d'alertes
    intact.
16. **Règle 100139 jamais déclenchée** : la règle officielle 67017, sœur au même niveau
    et chargée avant, captait tout le bruit des comptes machine ; son exclusion `IPC$`
    ne correspond jamais à la valeur `\\*\IPC$`. 100139 est chaînée sur 67017 et
    validée en direct.
17. **FIM : quatre défauts qui empêchaient 100186** : chemin `v1.0` masqué par la config
    locale de l'agent, `%USERPROFILE%` résolu vers le profil SYSTEM, `report_changes` sur
    Program Files qui saturait le quota et bloquait le scan, `restrict` non pris en
    compte. Corrigés dans `wazuh/agents/agent.conf`, puis validation en direct.
18. **Horloges** : DC01 était réglé sur le fuseau Pacifique alors que VirtualBox fournit
    l'heure locale de l'hôte (+8 h en UTC), et il dérivait ensuite de 15 min par heure.
    DC01 se synchronise désormais sur `pool.ntp.org` et WIN01 suit le domaine. TheHive
    retardait de 6 min : `timesyncd` ne vérifie plus qu'au plus toutes les 5 minutes sur
    les VM Ubuntu. La cause de fond de la dérive a été trouvée le 24/09 (faiblesse 26).
19. **Aucune segmentation sur OPNsense** : chaque zone avait « allow any ». Politique de
    refus par défaut, versionnée et journalisée vers Wazuh (étape 9).
20. **NDR sans détection** : aucune signature Suricata chargée, IP inversées entre les
    deux cartes, `HOME_NET` englobant l'attaquant (étape 5).
21. **PURPLE** : la carte NAT perdait de nouveau son adresse, car le profil n'était pas lié
    à `eth1` (la correction n°4 n'était pas durable). Corrigé ; routes vers les zones
    ajoutées.
22. **Blocage au démarrage des VM Ubuntu** (`Loading essential drivers`), observé sur
    WAZUH, MISP et SHUFFLE : il survient pendant le test RAID6 AVX2 de l'initramfs quand
    une autre VM démarre en même temps. Contournement : démarrages à froid, une VM
    après l'autre, et cache I/O hôte activé sur les contrôleurs SATA. Cause de fond
    trouvée et corrigée le 24/09 (faiblesse 26) : le contournement n'est plus nécessaire.
23. **Anciens tests non nettoyés** : `profile.ps1` laissés sur WIN01 et DC01 par les tests
    T1546 d'août, retirés (leur suppression a servi de test 100186).
24. **`wazuh-indexer` en échec après un redémarrage à froid de la VM** (`start operation
    timed out`, 3 min écoulées) : sur un hôte chargé, OpenSearch met plus longtemps que le
    délai systemd par défaut à finir son initialisation. Corrigé par un override
    `/etc/systemd/system/wazuh-indexer.service.d/socforge-timeout.conf`
    (`TimeoutStartSec=600`), conforme à la recommandation Wazuh pour les machines lentes.
    Après ce correctif, cluster `green`, tous les services actifs.
25. **Service Velociraptor de WIN01 sans connexion** : l'`ImagePath` du service hérité
    d'août (`Velociraptor.exe service run`) ne passait pas de `--config`. Une comparaison
    A/B sur le même binaire le montre : sans `--config`, il charge sa config par défaut
    (`server_urls: https://localhost:8000/`) et contacte WIN01 elle-même ; avec
    `--config`, il charge celle du lab (`https://10.10.10.61:8889/`). `ImagePath` corrigé,
    démarrage automatique, redémarrage sur échec. Reconnexion seule après un redémarrage
    sans session ; la tâche planifiée qui servait de contournement a été supprimée.
26. **VirtualBox tournait par-dessus l'hyperviseur Windows** (24/09). Un « plantage » de
    l'agent Velociraptor de WIN01, le 23/09 à 23:54, était en réalité un **écran bleu** de
    WIN01 : Kernel-Power 41, `BugcheckCode 10` (0xA `IRQL_NOT_LESS_OR_EQUAL`). Le minidump
    (récupéré par Velociraptor, SHA-256 vérifié, analysé avec WinDbg) situe l'arrêt dans le
    code d'interruption du noyau (`nt!KiIsrThunk`, IRQL `0xFF`), sans aucun pilote tiers
    dans la pile ; WinDbg indique `VIRTUAL_MACHINE: VirtualBox`. Le journal VirtualBox
    donne la cause : `HM: HMR3Init: Attempting fall back to NEM: AMD-V is not available`.
    L'**Intégrité de la mémoire** (HVCI, sécurité basée sur la virtualisation) était
    active sur l'hôte : l'hyperviseur Windows occupait AMD-V, et VirtualBox tournait en
    mode de repli NEM, connu pour ses défauts d'interruptions et d'horloge. C'est la cause
    commune de l'écran bleu, du gel `AHCI port reset` de WIN01, de la dérive des horloges
    (faiblesse 18) et des blocages au démarrage des VM Ubuntu (faiblesse 22).
    HVCI désactivée sur l'hôte (Sécurité Windows → Isolation du noyau). Après
    redémarrage : `HypervisorPresent: False`, chaque VM en `HM: HMR3Init: AMD-V w/ nested
    paging`. Vérifications : DFIR-HUNT et MISP démarrées ensemble sans blocage (test RAID6
    AVX2 passé en 30 s), puis WAZUH et SHUFFLE ensemble ; horloge de DFIR-HUNT à 1,7 ms
    de la référence NTP après 1 h 27, intervalle de vérification de `timesyncd` à son
    maximum (34 min), aucun saut d'horloge.
27. **Journaux Windows trop petits pour la DFIR** (24/09). WIN01 : Security plafonné à
    20 Mo, plein, plus ancien événement de moins de 30 h. DC01 : PowerShell/Operational à
    15 Mo, plein, avec **quelques minutes** d'historique (chaque script PowerShell
    y est journalisé en entier), Security à 128 Mo plein. Tailles portées à Security 512 Mo
    (1 Go sur DC01, contrôleur de domaine), Sysmon et PowerShell 256 Mo, System 128 Mo.
    L'artefact `Custom.Windows.EventLogs.Retention` affiche désormais la taille maximale :
    sur WIN01, le nombre d'événements Security augmente alors que le plus ancien reste le
    même, le journal ne s'écrase plus.
28. **Agent Velociraptor de DC01 hors ligne depuis le 10/08** (24/09). Sa config visait
    encore `https://10.10.10.60:8889/`, l'ancienne adresse du serveur (aujourd'hui celle de
    PURPLE) ; seule celle de WIN01 avait été corrigée à l'étape 8. Config du serveur
    déployée (même SHA-256 que WIN01), `--config` ajouté au service comme sur WIN01. Même
    client `C.c6b3dab429088216`, reconnecté à 11:50:15, collectes acceptées.
29. **Rôles TheHive et Cortex mal attribués** (24/09), trouvés en créant le premier cas :
    `admin@socforge.local` avait le profil `admin` de plateforme (aucun droit sur les
    incidents), et TheHive se connectait à Cortex avec le compte `superadmin` de Cortex,
    qui ne peut pas lancer d'analyseur (connecteur en `AUTH_ERROR`). Profil passé en
    `org-admin` ; compte de service Cortex dédié `thehive` (`read`, `analyze`). Voir SC-14.
30. **`wazuh-manager` en échec au démarrage** (24/09, `start operation timed out` après
    1 min 30 s) : même défaut que la faiblesse 24, corrigé à l'époque pour l'indexeur
    seulement. Même override `TimeoutStartSec=600` pour le manager.
31. **Table MITRE non chargée au démarrage de Wazuh** (24/09, une fois) : sous forte charge,
    `wazuh-analysisd` n'a pas joint `wazuh-db` à temps (« Unable to connect to Wazuh-DB for
    Mitre matrix information ») et ne réessaie pas ; les alertes de la session n'avaient
    pas de champ MITRE. Rechargée par un redémarrage du manager. À surveiller après un
    démarrage à froid : présence de ce message dans `ossec.log`.
32. **Alertes TheHive sans observable** (24/09) : le workflow Shuffle ne joignait que l'IP
    source ; une alerte FIM ou Sysmon arrivait vide, sans rien à analyser. Il extrait
    désormais fichier, SHA-256, hôte, processus, registre et compte.
33. **L'attaquant avait un accès direct au réseau d'administration** (24/09) : PURPLE avait
    une carte sur le réseau mgmt, non filtré (10.10.10.60). Carte retirée ; dans Kali, config
    mgmt supprimée et profils NetworkManager liés à l'adresse MAC (sinon la renumérotation
    `eth1` → `eth0` croise les configs). `10.10.10.0/24` routé par OPNsense : tentatives
    bloquées et journalisées (100301, puis 100302 niveau 12 en 8 s). Voir SC-16.
    Conséquence traitée : la sonde NDR n'écoutait que le réseau mgmt et aurait perdu de vue
    l'attaquant. Prise d'écoute passive ajoutée sur la zone purple (4ᵉ carte sans adresse,
    Suricata sur deux interfaces, Zeek en cluster à deux capteurs), persistante au
    redémarrage, alertes jusqu'à Wazuh (86601). Voir SC-12 et `ndr/`.

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
- [x] Étape 4 — DC01/WIN01 : 100103/100140/100147/100178 validées en direct (voir
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
    dans les mêmes conditions.
    **Validée en direct le 2026-09-23, sur DC01** (protection LSA absente par défaut sur
    Windows Server, vérifié avant tout test). Défaut trouvé en chemin : la config Sysmon
    de DC01 n'avait aucune règle `ProcessAccess` — corrigée. Le masque de droits `0x0410`
    donne un `grantedAccess` réel de `0x1410` (Windows ajoute
    `QUERY_LIMITED_INFORMATION`), que la règle 92900 ne reconnaît pas ; le masque
    `0x1010` (celui d'un vrai outil de dump) donne exactement la valeur attendue →
    `Rule: 100103 (level 14)`, `powershell.exe → lsass.exe`, `grantedAccess=0x1010`,
    2 s après le test. Voir `purple-team/scenarios/scenario-T1003-lsass-access.md`.
  - **100155** : même correction appliquée (chaînage sur `<if_sid>185006</if_sid>`, la
    règle de base EventID8 dans `0330-sysmon_rules.xml`). **Testé en direct et
    validé** : injection de thread bénigne (`CreateRemoteThread` → `kernel32!Sleep`)
    depuis PowerShell vers `notepad.exe` (non protégé par PPL) → alerte confirmée,
    18 correspondances sur le dashboard. Voir
    `purple-team/scenarios/scenario-T1055-process-injection.md` et capture
    `docs/screenshots/wazuh-dashboard-rule-100155-live.png`.
  - **100139 et 100186, complétées le 2026-09-23** (voir faiblesses 16 et 17) :
    100139 n'avait jamais sonné, parce que la règle officielle 67017 captait tout le
    bruit des comptes machine. Elle est chaînée sur 67017 et validée en direct
    (`DESKTOP-75LAKDV$`, `WIN-FJ8RP03U8FK$` sur `IPC$`). Pour 100186, la règle était
    juste mais le profil PowerShell n'était jamais surveillé : quatre défauts FIM
    corrigés, puis validation en direct (`added`, `modified`, `deleted`). 100140 a été
    rejouée le même jour. Capture `docs/screenshots/wazuh-rules-100139-100140-100186-live.png`.
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
  tous les deux exactement les 7 sessions TCP du scan.
  **Complété le 2026-09-23** : la NDR capturait mais ne détectait rien, et rien ne
  remontait au SIEM. Trois défauts corrigés : aucune signature chargée (ET Open installé,
  52 795 règles), adresses IP inversées entre les deux cartes, `HOME_NET` englobant
  l'attaquant. Agent Wazuh installé (groupe `ndr`) et règle 100400 ajoutée. Un scan
  PURPLE → WAZUH donne 6 signatures ET SCAN et 7 alertes 100400 (niveau 10) dans Wazuh.
  Capture `docs/screenshots/wazuh-ndr-suricata-scan.png`. Voir
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
  démarrée. **Cause exacte établie le 2026-09-23** : l'instance n'a plus de licence
  (`/api/v1/license/current` : `plan "No"`, aucune capacité), car la licence d'essai d'août
  a expiré. Depuis TheHive 5.3, l'édition Community gratuite demande une clé obtenue par
  inscription chez StrangeBee (licence obtenue et activée le 24/09, voir SC-14).
  Voir `purple-team/scenarios/scenario-thehive-cortex-100155.md`.
- [x] Étape 7 — Shuffle. VM06-SHUFFLE reconstruite après un disque plein, qui avait
  corrompu le système de fichiers ; le snapshot restauré était antérieur à Docker. Cinq
  défauts corrigés : ports du frontend, variable `SHUFFLE_OPENSEARCH_URL`, heap
  OpenSearch, RAM portée à 4 Go, IP interne statique.
  Workflow d'enrichissement (19/09) : dernière alerte TheHive → ID → observable → IP →
  Cortex `MISP_SocForge`, sans aucune valeur codée en dur, avec une vraie corrélation MISP
  (`"level":"suspicious"`). Pour y arriver, il a fallu corriger l'URL et
  l'authentification de Cortex, contourner le templating de Shuffle avec des nœuds Python,
  relier les nœuds par l'API, réparer le réseau et la clé API de MISP, et remplacer deux
  ID d'alerte figés qui donnaient une fausse impression de dynamisme. Cette validation a
  mobilisé 4 VM en même temps.
  **Déclenchement automatique (23/09)** : intégration native Wazuh → webhook Shuffle
  (alertes de niveau ≥ 10) → alerte TheHive (ID Wazuh en référence, tags MITRE). Test :
  règle 100210 à 17:06:49, exécution Shuffle `webhook` avec un 201 vers TheHive, alerte
  TheHive créée à 17:07:03. Au passage, l'horloge de TheHive, en retard de 6 minutes, a
  été corrigée. Voir `purple-team/scenarios/scenario-shuffle-soar-workflow.md`.
- [x] Étape 8 — MISP + DFIR-HUNT. Deux défauts corrigés sur VM08-DFIR-HUNT
  (Velociraptor) : carte réseau mgmt `enp0s8` jamais configurée (maintenant
  `10.10.10.61/24`, persistante) et URL du frontend annoncée aux clients incorrecte
  (`https://10.10.10.61:8889/`). Ajout d'un utilisateur API (`socforge-api`).
  Agent déployé sur WIN01 après le passage de sa souris en tablette USB (sans Guest
  Additions, la souris PS/2 empêchait l'intégration). Le service Windows hérité d'août
  démarrait mais ne se connectait jamais ; l'agent a d'abord tourné via une tâche
  planifiée SYSTEM. Cause trouvée et corrigée le 23/09 (faiblesse 25) : l'agent tourne
  désormais en service Windows, persistance prouvée par un redémarrage sans session. Chasse 1 : 3 événements 4104 du test T1059 (SC-04), un par exécution de
  la charge ce jour-là, retrouvés dans le `.evtx` de WIN01. Import MISP : événement #2
  publié avec 5 IOC de la campagne. Chasse 2 pilotée par ces IOC : 11 événements, dont la
  chronologie complète de la persistance Run key SC-09 (création puis suppression par le
  nettoyage), alors que la clé n'existe plus. Le 3ᵉ IOC (tâche SC-01) ne donne rien sur
  WIN01, ce qui est attendu puisque SC-01 a été exécuté sur DC01.
  **Intégration native (23/09)** : le script hôte de la chasse 2 est remplacé par trois
  artefacts serveur Velociraptor (`velociraptor/artifacts/`). La clé MISP est dans un
  secret serveur. `Custom.Server.MISP.IOCHunt`, lancé depuis le GUI, crée une vraie chasse
  taguée `misp`. Le monitoring `Custom.Server.MISP.Sightings` renvoie un sighting MISP par
  IOC vu : 4 sightings sur l'événement #2, sans doublon. La seconde chasse ne ramène que
  9 lignes, parce que le journal Security de WIN01 (20 Mo, plein) a écrasé les 4688 du
  18/09. C'est confirmé par l'artefact `Custom.Windows.EventLogs.Retention`, et Sysmon garde
  la chronologie. Incidents : WIN01 figé une fois (`AHCI port reset`, corrigé par le cache
  I/O hôte), horloges de VM08/WIN01 en retard après la veille de l'hôte (recalées).
  Voir `purple-team/scenarios/scenario-dfir-velociraptor-misp-hunt.md`.
- [x] Étape 9 — FW (2026-09-23). Aucune segmentation au départ : chaque zone avait
  « allow any ». Politique de moindre privilège appliquée par l'API
  (`firewall/segmentation-policy.json`, 12 règles, refus par défaut journalisé), anciennes
  règles désactivées, `filterlog` envoyé en syslog vers Wazuh, règles 100300/100301/100302.
  Test depuis la zone purple vers les zones srv et dfir : 19 blocages dans Wazuh, dont
  100302 (niveau 12, scan à travers les zones). Contre-épreuve vers la zone ep, autorisée :
  aucun blocage. Voir `purple-team/scenarios/scenario-firewall-segmentation.md`.
- [x] Étape 10 — réponse automatique et boucle SOAR → DFIR (2026-09-24). La chaîne
  détectait, alertait, enrichissait et corrélait avec MISP, mais n'agissait jamais contre
  l'attaquant, et un `misp:match` ne déclenchait rien côté Velociraptor : deux limites de
  process, pas des bugs isolés. Deux nœuds Shuffle supplémentaires
  (`Contain_Attacker`, `Trigger_DFIR_Hunt`, code dans `soar/nodes/`, déployés par
  `soar/create_wazuh_webhook_workflow.py`) ferment la boucle. Confinement : alias
  dynamique `BLOCKED_ATTACKERS` sur OPNsense (`firewall/contain_attacker.py` /
  `uncontain_attacker.py`, `firewall/opnsense_client.py` partagé avec `apply_policy.py`),
  réversible, déclenché seulement sur alerte confirmée (sévérité ≥ 3 et `misp:match`) —
  validé avec du trafic réel (blocage/rétablissement) puis revalidé en nœud Shuffle
  (`198.51.100.77`, GUI OPNsense). Boucle DFIR : republication de l'événement MISP déjà
  identifié par Cortex, ce qui relance `Custom.Server.MISP.AutoHunt`, puis sondage des
  sightings pendant 150 s. **Défaut trouvé en la construisant** : `IocTypes` par défaut
  des trois artefacts MISP de Velociraptor (`text`, `regkey|value`) était plus étroit que
  ce que l'analyseur Cortex matche déjà — un `misp:match` sur un `filename` ne déclenchait
  aucune chasse. Élargi à `["text", "regkey|value", "filename", "hash"]`, redéployé,
  chasse `H.DAQO7NJA0I35E` obtenue sur l'événement qui échouait. Chaîne à 5 nœuds testée
  en conditions réelles sur une alerte Wazuh authentique (`~204804176`, règle 100210) :
  `Contain_Attacker` s'abstient correctement (sévérité 2 < 3), `Trigger_DFIR_Hunt` pose
  `dfir:hunt-triggered`. **Incident pendant ce test** : le backend Shuffle a été tué par
  manque de RAM en cours d'exécution ; à son redémarrage automatique, le worker a rejoué
  les premiers nœuds sans dupliquer l'alerte TheHive (dédoublonnage par `sourceRef`) ;
  conteneurs orphelins nettoyés après coup. Voir
  `purple-team/scenarios/scenario-shuffle-soar-workflow.md`.
- [x] Étape 11 — isolation hôte, processus d'investigation formalisé, métriques et
  rapport d'incident (2026-09-25). Trois ajouts pour aller au-delà de la chaîne
  technique déjà prouvée. **Isolation hôte** (`Quarantine_Host`, code dans
  `soar/nodes/`, CLI dans `dfir/`) : s'appuie sur l'artefact intégré de Velociraptor
  `Windows.Remediation.Quarantine`, gated en plus sur le tag `auto-contained` (défense en
  profondeur — l'hôte n'est isolé que si la chaîne a déjà bloqué son IP). Prouvé en
  direct sur WIN01 : ping à 0 % avant, 100 % pendant la quarantaine, canal Velociraptor
  toujours fonctionnel pendant l'isolement (collecte réussie), 0 % après levée — avec les
  scripts réellement livrés, pas un brouillon. **Défaut trouvé en déployant le nœud** :
  `ensure_chain()` n'enlevait jamais les anciennes branches ; l'insertion de
  `Quarantine_Host` avant `Trigger_DFIR_Hunt` aurait fait exécuter ce dernier deux fois
  par alerte sans correction. Repéré par lecture des branches via l'API juste après le
  déploiement, avant tout déclenchement réel ; corrigé à la racine (chaque nœud de la
  chaîne n'a par construction qu'un seul prédécesseur). **Processus d'investigation** :
  modèle de cas TheHive réutilisable (5 tâches), appliqué à un cas réel et clos
  (`TruePositive`, 55 s de résolution une fois ouvert). **Métriques et rapport
  d'incident** : MTTD/MTTA/MTTR calculés sur les horodatages déjà documentés
  (`docs/metrics-mttd-mtta-mttr.md`), rapport d'incident complet sur l'alerte réelle
  `~204804176` (`docs/incident-report-2026-09-24-cron-persistence.md`). Voir
  `purple-team/scenarios/scenario-shuffle-soar-workflow.md`.
- [x] Étape 12 — une seule attaque, toute la chaîne (2026-10-01). Chaque maillon avait été prouvé
  séparément ; ce test suit une seule attaque réelle. **Défaut trouvé** : aucune alerte ne pouvait à la fois
  déclencher le confinement (règle de niveau ≥ 12) et porter l'IP à bloquer (les règles de niveau ≥ 12 sont des
  événements Sysmon locaux ; celles qui portent une IP plafonnent à 10). Règle d'escalade `100141` (3 accès à un
  partage d'administration depuis la même IP en 2 minutes → niveau 12). Trois autres défauts corrigés :
  `Quarantine_Host` cherchait le nom Wazuh (`WIN01`) alors que Velociraptor connaît `DESKTOP-75LAKDV`, audit
  « File Share » désactivé sur WIN01, adresses de zone erronées (WIN01 `.110` et non `.10` ; carte de zone de
  LINUX01 sur le mauvais sous-réseau). Résultat : une attaque depuis PURPLE → alerte Wazuh de niveau 12 → alerte
  TheHive (`misp:match`) → `10.10.50.10` dans `BLOCKED_ATTACKERS` → WIN01 isolée par Velociraptor (100 % de perte
  sur le réseau de gestion, 0 % après levée, canal conservé) → chasse : 6 traces de l'attaque retrouvées (24
  événements au total avec un essai antérieur), 2 sightings dans MISP. Exécutée en deux vagues dans la même
  session (contrainte de mémoire) : l'alerte a été livrée à Shuffle 33 minutes après sa création, avec le
  script d'intégration officiel de Wazuh. Voir `purple-team/scenarios/scenario-shuffle-soar-workflow.md`.
34. **Horloge des machines Windows en avance d'une heure** (01/10), vue pendant l'attaque suivie dans
    toute la chaîne : WIN01 et DC01 avaient le fuseau « Morocco Standard Time », dont les tables de règles
    n'appliquaient pas l'heure d'été, alors que VirtualBox fournit l'heure locale de l'hôte (UTC+1) ; leur
    heure « UTC » avançait donc d'une heure. Corrigé sur les deux machines : horloge virtuelle en UTC
    (`rtcuseutc`) et fuseau UTC ; WIN01 vérifiée à 2 s de l'hôte. Les horodatages de l'attaque déjà
    enregistrés ne sont pas modifiés (voir SC-14).

## Reste à faire

- **Licence TheHive** : la licence active est un essai `Platinum` qui expire le
  08/10/2026. La promotion alerte → cas est validée (cas #8 et #9, SC-14) ; pour que le
  lab reste utilisable ensuite, installer une licence Community (portail StrangeBee,
  même procédure par challenge).
