# SocForge

Un laboratoire SOC complet sur un seul PC, avec VirtualBox : douze machines virtuelles, de la détection
jusqu'à la réponse. Chaque détection a été déclenchée par une vraie attaque, bénigne, lancée depuis une machine
Kali, puis observée dans le SIEM et documentée avec ses journaux, ses heures UTC et des captures d'écran.

Le projet va jusqu'au bout d'un incident : une seule attaque est suivie à travers toute la chaîne (détection,
orchestration, enrichissement, blocage réseau, isolation du poste, chasse, clôture du cas). Le détail est dans la
fiche [SC-14](purple-team/scenarios/SC-14-shuffle-soar-workflow.md).

Quelques chiffres : 12 machines, 16 fiches de scénario, 28 règles de détection écrites pour le lab, 5 zones
réseau filtrées, une chaîne d'automatisation de 6 nœuds et 45 captures. Sur l'attaque suivie, Wazuh alerte en
1 à 7 secondes, l'alerte arrive dans TheHive 7 secondes après sa livraison, l'adresse de l'attaquant est bloquée
à 24 secondes, l'ordre d'isolation du poste part à 29 secondes et la chasse est demandée à 35 secondes
([métriques](docs/metrics-mttd-mtta-mttr.md)).

## Architecture

![Architecture du laboratoire](docs/architecture.png)

| Couche | Composants | Rôle |
|---|---|---|
| Attaque | PURPLE (Kali Linux) | lance les attaques, seul dans sa zone |
| Réseau | OPNsense, sonde NDR (Suricata et Zeek) | segmentation avec refus par défaut, détection réseau passive |
| Administration | réseau de gestion `10.10.10.0/24` | héberge les outils (Wazuh, Shuffle, TheHive…). Il n'est pas filtré : ni l'attaquant ni les cibles n'y ont de carte |
| Cibles | DC01, WIN01, LINUX01 | domaine Windows, poste Windows 11 avec Sysmon, serveur Ubuntu ; chacun a un agent Wazuh |
| Détection | Wazuh | reçoit les agents, le syslog du pare-feu et les alertes réseau |
| Réponse | Shuffle, TheHive, Cortex, MISP | orchestration, suivi d'incident, analyse, renseignement sur la menace |
| DFIR | Velociraptor | chasse sur les postes, isolation d'un hôte compromis |

L'inventaire complet (adresses, versions, flux) est dans [`docs/lab-registry.md`](docs/lab-registry.md). Un
rapport d'incident rédigé à partir d'une alerte réelle est dans
[`docs/incident-report-2026-09-24-cron-persistence.md`](docs/incident-report-2026-09-24-cron-persistence.md).

## L'attaque suivie de bout en bout

Depuis PURPLE, trois accès successifs au partage d'administration de WIN01 avec un compte local valide. Wazuh
lève des alertes de niveau 12 (règles `100179`, puis `100141`). Cette même alerte passe ensuite dans les six
nœuds de Shuffle, qui agissent chacun sur elle. Le résultat de la chasse revient sur l'alerte, qui est
transformée en cas, investiguée puis close.

1. Wazuh signale une session distante venue de la zone attaquant dès la première connexion (7 s), puis l'escalade `100141` à 27 s.
2. Shuffle crée l'alerte TheHive avec trois observables : l'adresse, l'agent et le nom Windows du poste (7 s après la livraison).
3. Cortex interroge MISP : l'adresse de l'attaquant figure déjà dans l'événement #6 (21 s).
4. L'adresse entre dans l'alias `BLOCKED_ATTACKERS` d'OPNsense (24 s). Le pare-feu rejette ensuite chaque tentative de PURPLE.
5. Shuffle demande à Velociraptor d'isoler WIN01 (29 s). L'ordre s'applique à la reconnexion du poste : le ping tombe à 100 % de perte, le canal Velociraptor reste ouvert.
6. L'événement MISP est republié (35 s), la chasse retrouve les traces de l'attaque et renvoie deux sightings à MISP. Son résultat est écrit sur l'alerte.
7. L'alerte devient le cas #11, avec cinq tâches renseignées, et il est clos en `TruePositive`.

Les machines sont allumées par groupes, selon leur rôle : d'abord l'attaque et sa détection, puis la chaîne de
réponse. L'alerte réelle a été remise à Shuffle avec le script d'intégration officiel de Wazuh, et les actions
ci-dessus sont les actions réelles de la chaîne.

<table>
<tr>
<td width="50%"><img src="docs/screenshots/wazuh-rule-100141-live.png" alt="Alertes Wazuh 100179, 100140 et 100141"><br><sub>Wazuh : règles 100179, 100140 puis 100141 (niveau 12) sur WIN01, source 10.10.50.10</sub></td>
<td width="50%"><img src="docs/screenshots/thehive-alert-chain-100141.png" alt="Alerte TheHive à l'issue de la chaîne"><br><sub>TheHive : l'alerte à l'issue de la chaîne, avec ses tags et les notes laissées par chaque nœud</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/opnsense-firewall-log-containment.png" alt="Journal du pare-feu OPNsense"><br><sub>OPNsense : connexions de l'attaquant vers WIN01 rejetées par la règle de confinement</sub></td>
<td width="50%"><img src="docs/screenshots/velociraptor-win01-flows-isolation.png" alt="Flows Velociraptor sur WIN01"><br><sub>Velociraptor : isolation de WIN01, deux chasses de 30 lignes, levée de l'isolation</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/misp-event6-sightings.png" alt="Événement MISP 6 et sightings"><br><sub>MISP : événement #6 et ses deux sightings venus de Velociraptor</sub></td>
<td width="50%"><img src="docs/screenshots/thehive-case11-chain-100141-closed.png" alt="Cas TheHive 11 clos"><br><sub>TheHive : cas #11 clos, cinq tâches terminées, métriques de délai calculées par TheHive</sub></td>
</tr>
</table>

L'exécution Shuffle (les six nœuds et leur résultat) est dans
[`shuffle-execution-chain-100141.png`](docs/screenshots/shuffle-execution-chain-100141.png) et l'alias OPNsense dans
[`opnsense-blocked-attackers-attack-ip.png`](docs/screenshots/opnsense-blocked-attackers-attack-ip.png).

## Autres preuves

<table>
<tr>
<td width="50%"><img src="docs/screenshots/wazuh-dashboard-threat-hunting-overview.png" alt="Tableau de bord Wazuh"><br><sub>Le tableau de bord Threat Hunting de Wazuh</sub></td>
<td width="50%"><img src="docs/screenshots/wazuh-ndr-suricata-scan.png" alt="Alertes Suricata dans Wazuh"><br><sub>Un scan détecté par Suricata, alerte de niveau 10 dans Wazuh (<a href="purple-team/scenarios/SC-12-ndr-purple-scan.md">SC-12</a>)</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/opnsense-segmentation-policy.png" alt="Politique de segmentation OPNsense"><br><sub>La politique de segmentation, refus par défaut entre les zones (<a href="purple-team/scenarios/SC-16-firewall-segmentation.md">SC-16</a>)</sub></td>
<td width="50%"><img src="docs/screenshots/wazuh-opnsense-segmentation-blocks.png" alt="Blocages du pare-feu dans Wazuh"><br><sub>Les tentatives de l'attaquant bloquées et journalisées, vues depuis Wazuh</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/velociraptor-misp-sightings-monitor.png" alt="Sightings MISP dans Velociraptor"><br><sub>Les sightings renvoyés à MISP à la fin de chaque chasse (<a href="purple-team/scenarios/SC-15-dfir-velociraptor-misp-hunt.md">SC-15</a>)</sub></td>
<td width="50%"></td>
</tr>
</table>

## Ce que le dépôt démontre

- Détection Windows : 19 règles Wazuh rattachées à MITRE ATT&CK, dont les détections principales ont aussi une forme Sigma dans `detections/sigma/` (15 règles, Windows et Linux). Elles couvrent PowerShell encodé, tâche planifiée, clé Run, injection de processus, accès LSASS, mouvement latéral, session depuis la zone non fiable et profil PowerShell. Voir [`detection-sheet-windows.md`](detections/windows/detection-sheet-windows.md).
- Détection Linux : sudo et persistance cron, dans [`detection-sheet-linux.md`](detections/linux/detection-sheet-linux.md).
- Réseau : Suricata (52 795 signatures ET Open) détecte un scan et Wazuh remonte une alerte de niveau 10, voir [SC-12](purple-team/scenarios/SC-12-ndr-purple-scan.md).
- Segmentation : refus par défaut entre cinq zones filtrées, blocages journalisés et visibles dans Wazuh, voir [SC-16](purple-team/scenarios/SC-16-firewall-segmentation.md).
- Orchestration : une alerte Wazuh devient une alerte TheHive avec ses observables, est enrichie par Cortex et MISP, puis déclenche le blocage de l'attaquant, l'isolation du poste et la chasse, sans intervention. Voir [SC-14](purple-team/scenarios/SC-14-shuffle-soar-workflow.md).
- Garde-fous de la réponse automatique : liste d'adresses jamais bloquées, label qui protège le contrôleur de domaine, blocage temporaire, webhook réservé à Wazuh, accès à Velociraptor par une clé SSH limitée à une commande. Ils sont testés dans la même fiche.
- DFIR : un événement MISP publié lance seul une chasse Velociraptor sur les postes Windows et Linux, et les sightings reviennent dans MISP, voir [SC-15](purple-team/scenarios/SC-15-dfir-velociraptor-misp-hunt.md).
- Chiffrement : les services en HTTPS (MISP, OPNsense) sont appelés avec la CA interne du lab, sans désactiver la vérification. TheHive, Cortex et Shuffle restent en HTTP sur le réseau de gestion.

## Scénarios

Les fiches SC-01 à SC-11 ont été écrites avant le retrait des cartes de gestion des cibles (07/10) : les adresses `10.10.10.109`, `10.10.10.110` et `10.10.10.111` qu'elles citent sont celles que DC01, WIN01 et LINUX01 avaient alors sur le réseau de gestion. Leurs adresses actuelles sont `10.10.20.10`, `10.10.30.110` et `10.10.30.20` (voir l'[inventaire](docs/lab-registry.md)).

| # | Technique | Fiche |
|---|---|---|
| SC-01 | T1053.005 Tâche planifiée | [SC-01-T1053-scheduled-task.md](purple-team/scenarios/SC-01-T1053-scheduled-task.md) |
| SC-02 | T1078 Compte valide, logon réseau | [SC-02-T1078-valid-account.md](purple-team/scenarios/SC-02-T1078-valid-account.md) |
| SC-03 | T1021.002 Partages admin : filtrage du bruit | [SC-03-T1021-lateral-movement.md](purple-team/scenarios/SC-03-T1021-lateral-movement.md) |
| SC-04 | T1059.001 PowerShell encodé | [SC-04-T1059-powershell-encoded.md](purple-team/scenarios/SC-04-T1059-powershell-encoded.md) |
| SC-05 | T1046 Scan de ports depuis Kali | [SC-05-T1046-port-scan.md](purple-team/scenarios/SC-05-T1046-port-scan.md) |
| SC-06 | T1110 Brute force SMB | [SC-06-T1110-brute-force.md](purple-team/scenarios/SC-06-T1110-brute-force.md) |
| SC-07 | T1548.003 / T1053.003 sudo et cron (Linux) | [SC-07-T1548-T1053-linux.md](purple-team/scenarios/SC-07-T1548-T1053-linux.md) |
| SC-08 | T1021.002 + T1078 Mouvement latéral WIN01 → DC01 | [SC-08-T1021-win01-to-dc01.md](purple-team/scenarios/SC-08-T1021-win01-to-dc01.md) |
| SC-09 | T1547.001 Clé Run | [SC-09-T1547-registry-run-key.md](purple-team/scenarios/SC-09-T1547-registry-run-key.md) |
| SC-10 | T1055 Injection de processus | [SC-10-T1055-process-injection.md](purple-team/scenarios/SC-10-T1055-process-injection.md) |
| SC-11 | T1003 Accès LSASS, bloqué sur WIN01 (protection LSA), validé en direct sur DC01 | [SC-11-T1003-lsass-access.md](purple-team/scenarios/SC-11-T1003-lsass-access.md) |
| SC-12 | NDR : capture et détection d'un scan | [SC-12-ndr-purple-scan.md](purple-team/scenarios/SC-12-ndr-purple-scan.md) |
| SC-13 | TheHive + Cortex | [SC-13-thehive-cortex-100155.md](purple-team/scenarios/SC-13-thehive-cortex-100155.md) |
| SC-14 | SOAR Wazuh → Shuffle → TheHive → Cortex → MISP | [SC-14-shuffle-soar-workflow.md](purple-team/scenarios/SC-14-shuffle-soar-workflow.md) |
| SC-15 | Chasse Velociraptor pilotée par MISP | [SC-15-dfir-velociraptor-misp-hunt.md](purple-team/scenarios/SC-15-dfir-velociraptor-misp-hunt.md) |
| SC-16 | Segmentation OPNsense | [SC-16-firewall-segmentation.md](purple-team/scenarios/SC-16-firewall-segmentation.md) |

## Organisation du dépôt

| Dossier | Contenu |
|---|---|
| `wazuh/rules/` | règles SocForge (Windows/Sigma, Linux, pare-feu, NDR) |
| `wazuh/agents/` | configurations centralisées des agents (Windows, Linux, NDR) |
| `wazuh/manager/` | intégration Shuffle et écoute syslog du manager |
| `firewall/` | politique de segmentation OPNsense, script d'application par API, confinement/déconfinement d'un attaquant |
| `dfir/` | isolation/levée d'isolation d'un hôte compromis via Velociraptor (Windows et Linux) ; `server/` : compte restreint utilisé par Shuffle |
| `sysmon/` | configuration Sysmon des contrôleurs de domaine |
| `detections/sigma/` | règles Sigma, validées par la CI |
| `tests/` | tests automatiques (règles, politique du pare-feu, artefacts, nœuds SOAR, liens) |
| `ndr/` | configuration de la sonde : interfaces écoutées, Suricata, cluster Zeek |
| `pki/` | CA interne du lab (certificat public) et script d'émission des certificats |
| `soar/` | création des workflows Shuffle (`nodes/` : code des nœuds de confinement, d'isolation d'hôte, de déclenchement de chasse DFIR et des tâches planifiées de suivi) ; filtre d'accès au webhook |
| `velociraptor/` | artefacts MISP ↔ Velociraptor (serveur) et chasse Linux (client) |
| `detections/` | fiches de détection Windows et Linux |
| `purple-team/scenarios/` | une fiche par scénario (SC-01 à SC-16) |
| `docs/` | plan de reconstruction, inventaire, métriques, rapport d'incident, schéma d'architecture, captures (`screenshots/`) |

## Chronologie

Première réalisation du 2 au 15 août 2026, pause, puis reconstruction et audit du 13 septembre au 7 octobre 2026
(détail dans [`docs/rebuild-plan.md`](docs/rebuild-plan.md)).
