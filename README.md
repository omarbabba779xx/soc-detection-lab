# SocForge — laboratoire SOC de bout en bout

SOC complet monté sur un seul PC (VirtualBox) : 12 machines virtuelles, de la détection à la réponse.
Chaque détection est déclenchée par une attaque réelle mais bénigne, observée dans le SIEM, puis documentée
avec ses preuves : extraits de journaux, heures UTC et captures. Une même attaque est suivie à travers toute la
chaîne : détection, orchestration, enrichissement, blocage réseau, isolation de l'hôte et chasse DFIR.

## En chiffres

| 12 | 16 | 23 | 5 | 6 | 43 |
|:---:|:---:|:---:|:---:|:---:|:---:|
| machines virtuelles | scénarios documentés | règles de détection personnalisées | zones réseau filtrées | nœuds de la chaîne SOAR | captures de preuve |

Détection en **1 à 3 s**, prise en charge automatique en **~24 s**, blocage de l'attaquant, isolation de l'hôte et chasse DFIR déclenchés en **36 à 63 s** après la livraison de l'alerte ([métriques](docs/metrics-mttd-mtta-mttr.md)).

## Architecture

![Architecture du laboratoire](docs/architecture.png)

| Couche | Composants | Rôle |
|---|---|---|
| Attaque | PURPLE (Kali Linux) | émet les attaques, seul dans sa zone |
| Réseau | OPNsense, NDR (Suricata + Zeek) | segmentation par refus par défaut, détection réseau passive |
| Administration | réseau de gestion `10.10.10.0/24` | héberge les outils (Wazuh, Shuffle, TheHive…) ; réseau d'administration hors bande, non filtré, sans carte côté attaquant |
| Cibles | DC01, WIN01, LINUX01 | domaine Windows, poste Windows 11 (Sysmon), serveur Ubuntu, chacun avec un agent Wazuh |
| Détection | Wazuh | reçoit les agents, le syslog du pare-feu et les alertes réseau |
| Réponse | Shuffle, TheHive, Cortex, MISP | orchestration, suivi d'incident, analyse, renseignement sur la menace |
| DFIR | Velociraptor | chasse sur les postes Windows, isolation d'un hôte compromis |

Inventaire complet (adresses, versions, flux) : [`docs/lab-registry.md`](docs/lab-registry.md).
Exemple de rapport d'incident de bout en bout : [`docs/incident-report-2026-09-24-cron-persistence.md`](docs/incident-report-2026-09-24-cron-persistence.md).

## Une seule attaque, toute la chaîne

Depuis PURPLE, trois accès successifs au partage d'administration de WIN01 produisent une alerte Wazuh de
niveau 12 (règle `100141`, T1021.002). Cette **même alerte** traverse ensuite les six nœuds de Shuffle, et
chacun agit sur elle. Détail, heures UTC et preuves : [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md).

| Étape | Ce qui se passe |
|---|---|
| 1. Détection | Wazuh : règle `100140` (niveau 10) deux fois, puis `100141` (niveau 12), 1 à 3 s après chaque accès |
| 2. Orchestration | Shuffle crée l'alerte TheHive, sévérité 3, avec IP, agent et nom Windows en observables (12 s) |
| 3. Enrichissement | Cortex interroge MISP : l'IP de l'attaquant figure dans l'événement #6, tag `misp:match` (33 s) |
| 4. Confinement réseau | l'IP de l'attaquant entre dans l'alias `BLOCKED_ATTACKERS` d'OPNsense (36 s) |
| 5. Isolation de l'hôte | ordre d'isolation de WIN01 émis vers Velociraptor (41 s) ; une fois appliqué : 100 % de perte sur le réseau de gestion, canal conservé |
| 6. Chasse DFIR | l'événement MISP est republié et la chasse est créée (54 à 63 s) ; elle retrouve ensuite les traces de l'attaque et renvoie 2 sightings |

**Mode d'exécution.** La contrainte de mémoire de l'hôte conduit à exécuter la chaîne en deux vagues dans la
même session : l'attaque et sa détection, puis la chaîne de réponse. L'alerte réelle a été livrée à Shuffle avec
le script d'intégration officiel de Wazuh, et les actions ci-dessus sont les actions réelles de la chaîne.

<table>
<tr>
<td width="50%"><img src="docs/screenshots/wazuh-rule-100141-live.png" alt="Alertes Wazuh 100140 puis 100141"><br><sub><b>Détection</b> : règle 100141 (niveau 12) précédée des deux 100140, agent WIN01, IP source 10.10.50.10</sub></td>
<td width="50%"><img src="docs/screenshots/thehive-alert-chain-100141.png" alt="Alerte TheHive à l'issue de la chaîne"><br><sub><b>Orchestration</b> : alerte TheHive de sévérité haute, tags <code>auto-contained</code>, <code>auto-quarantined</code>, <code>misp:match</code>, <code>dfir:hunt-triggered</code></sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/opnsense-blocked-attackers-attack-ip.png" alt="Alias BLOCKED_ATTACKERS d'OPNsense"><br><sub><b>Confinement</b> : l'IP de l'attaquant dans l'alias <code>BLOCKED_ATTACKERS</code>, alimenté par Shuffle</sub></td>
<td width="50%"><img src="docs/screenshots/velociraptor-win01-flows-isolation.png" alt="Flows Velociraptor sur WIN01"><br><sub><b>Isolation</b> : flows de WIN01 (isolation, collecte pendant l'isolation, chasse, levée)</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/misp-event6-sightings.png" alt="Événement MISP 6 et sightings"><br><sub><b>Chasse</b> : événement MISP #6, 2 sightings renvoyés par Velociraptor</sub></td>
<td width="50%" valign="top"><img src="docs/screenshots/shuffle-execution-chain-100141.png" alt="Exécution Shuffle" width="45%"><br><sub><b>Orchestration</b> : l'exécution Shuffle, les six nœuds et leur résultat</sub></td>
</tr>
</table>

## Aperçu des preuves

<table>
<tr>
<td width="50%"><img src="docs/screenshots/wazuh-dashboard-threat-hunting-overview.png" alt="Tableau de bord Wazuh"><br><sub><b>SIEM</b> : tableau de bord Threat Hunting de Wazuh</sub></td>
<td width="50%"><img src="docs/screenshots/wazuh-ndr-suricata-scan.png" alt="Alertes Suricata dans Wazuh"><br><sub><b>Réseau</b> : scan détecté par Suricata, alerte niveau 10 dans Wazuh (<a href="purple-team/scenarios/scenario-ndr-purple-scan.md">SC-12</a>)</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/opnsense-segmentation-policy.png" alt="Politique de segmentation OPNsense"><br><sub><b>Segmentation</b> : politique de refus par défaut entre zones (<a href="purple-team/scenarios/scenario-firewall-segmentation.md">SC-16</a>)</sub></td>
<td width="50%"><img src="docs/screenshots/wazuh-opnsense-segmentation-blocks.png" alt="Blocages du pare-feu dans Wazuh"><br><sub><b>Blocages</b> : tentatives de l'attaquant bloquées et journalisées, visibles dans Wazuh</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/velociraptor-misp-sightings-monitor.png" alt="Sightings MISP dans Velociraptor"><br><sub><b>DFIR</b> : sightings renvoyés à MISP à la fin de chaque chasse (<a href="purple-team/scenarios/scenario-dfir-velociraptor-misp-hunt.md">SC-15</a>)</sub></td>
<td width="50%"><img src="docs/screenshots/thehive-case10-ir-playbook-closed.png" alt="Cas TheHive clos"><br><sub><b>Incident</b> : modèle de cas en 5 tâches, appliqué à un incident réel et clos</sub></td>
</tr>
</table>

## Ce qui est démontré

| Domaine | Résultat | Preuve |
|---|---|---|
| Détection Windows | 17 règles Wazuh écrites sur le modèle de règles Sigma et rattachées à MITRE ATT&CK, toutes validées en direct (PowerShell encodé, tâche planifiée, clé Run, injection, mouvement latéral, profil PowerShell, accès LSASS…) | [`detection-sheet-windows.md`](detections/windows/detection-sheet-windows.md) |
| Détection Linux | sudo, persistance cron | [`detection-sheet-linux.md`](detections/linux/detection-sheet-linux.md) |
| Réseau | Suricata (52 795 signatures ET Open) détecte un scan, alerte niveau 10 dans Wazuh | [SC-12](purple-team/scenarios/scenario-ndr-purple-scan.md) |
| Segmentation | politique de refus par défaut entre 5 zones filtrées, attaquant sans accès au réseau d'administration, blocages visibles dans Wazuh | [SC-16](purple-team/scenarios/scenario-firewall-segmentation.md) |
| SIEM → SOAR → CTI | alerte Wazuh → Shuffle → TheHive (avec observables) → Cortex → MISP, sans action humaine : alerte TheHive créée **12 s** après la livraison, tag `misp:match` posé après corrélation | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Gestion d'incident | alertes Wazuh promues en cas TheHive, observables repris | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| DFIR | publication d'un événement MISP → chasse Velociraptor lancée **automatiquement** sur les postes Windows → sightings renvoyés à MISP dès la fin de la chasse ; persistance retrouvée alors que la clé était supprimée | [SC-15](purple-team/scenarios/scenario-dfir-velociraptor-misp-hunt.md) |
| Réponse automatique (réseau) | une alerte confirmée (sévérité ≥ 3, `misp:match`) fait bloquer son IP sur OPNsense par Shuffle lui-même, sans analyste — réversible par script | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Réponse automatique (hôte) | l'hôte compromis est isolé du réseau par Velociraptor (canal de gestion conservé), une fois le confinement réseau déjà déclenché — réversible par script | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Boucle SOAR → DFIR | un `misp:match` posé par la chaîne SOAR republie l'IOC dans MISP et déclenche la chasse Velociraptor correspondante, sans intervention | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Processus d'investigation | modèle de cas TheHive réutilisable (triage → confinement → éradication → récupération → REX), appliqué à un incident réel et clos | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Chiffrement | TLS vérifié avec la CA interne du lab pour les services en HTTPS (MISP, OPNsense), sans vérification désactivée ; TheHive, Cortex et Shuffle sont en HTTP sur le réseau de gestion | [SC-15](purple-team/scenarios/scenario-dfir-velociraptor-misp-hunt.md), [SC-16](purple-team/scenarios/scenario-firewall-segmentation.md) |

## Scénarios

| # | Technique | Fiche |
|---|---|---|
| SC-01 | T1053.005 Tâche planifiée | [scenario-T1053-scheduled-task.md](purple-team/scenarios/scenario-T1053-scheduled-task.md) |
| SC-02 | T1078 Compte valide, logon réseau | [scenario-T1078-valid-account.md](purple-team/scenarios/scenario-T1078-valid-account.md) |
| SC-03 | T1021.002 Partages admin : filtrage du bruit | [scenario-T1021-lateral-movement.md](purple-team/scenarios/scenario-T1021-lateral-movement.md) |
| SC-04 | T1059.001 PowerShell encodé | [scenario-T1059-powershell-encoded.md](purple-team/scenarios/scenario-T1059-powershell-encoded.md) |
| SC-05 | T1046 Scan de ports depuis Kali | [scenario-T1046-port-scan.md](purple-team/scenarios/scenario-T1046-port-scan.md) |
| SC-06 | T1110 Brute force SMB | [scenario-T1110-brute-force.md](purple-team/scenarios/scenario-T1110-brute-force.md) |
| SC-07 | T1548.003 / T1053.003 sudo et cron (Linux) | [scenario-T1548-T1053-linux.md](purple-team/scenarios/scenario-T1548-T1053-linux.md) |
| SC-08 | T1021.002 + T1078 Mouvement latéral WIN01 → DC01 | [scenario-T1021-win01-to-dc01.md](purple-team/scenarios/scenario-T1021-win01-to-dc01.md) |
| SC-09 | T1547.001 Clé Run | [scenario-T1547-registry-run-key.md](purple-team/scenarios/scenario-T1547-registry-run-key.md) |
| SC-10 | T1055 Injection de processus | [scenario-T1055-process-injection.md](purple-team/scenarios/scenario-T1055-process-injection.md) |
| SC-11 | T1003 Accès LSASS — bloqué sur WIN01 (protection LSA), validé en direct sur DC01 | [scenario-T1003-lsass-access.md](purple-team/scenarios/scenario-T1003-lsass-access.md) |
| SC-12 | NDR : capture et détection d'un scan | [scenario-ndr-purple-scan.md](purple-team/scenarios/scenario-ndr-purple-scan.md) |
| SC-13 | TheHive + Cortex | [scenario-thehive-cortex-100155.md](purple-team/scenarios/scenario-thehive-cortex-100155.md) |
| SC-14 | SOAR Wazuh → Shuffle → TheHive → Cortex → MISP | [scenario-shuffle-soar-workflow.md](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| SC-15 | Chasse Velociraptor pilotée par MISP | [scenario-dfir-velociraptor-misp-hunt.md](purple-team/scenarios/scenario-dfir-velociraptor-misp-hunt.md) |
| SC-16 | Segmentation OPNsense | [scenario-firewall-segmentation.md](purple-team/scenarios/scenario-firewall-segmentation.md) |

## Organisation du dépôt

| Dossier | Contenu |
|---|---|
| `wazuh/rules/` | règles SocForge (Windows/Sigma, Linux, pare-feu, NDR) |
| `wazuh/agents/` | configurations centralisées des agents (Windows, Linux, NDR) |
| `wazuh/manager/` | intégration Shuffle et écoute syslog du manager |
| `firewall/` | politique de segmentation OPNsense, script d'application par API, confinement/déconfinement d'un attaquant |
| `dfir/` | isolation/levée d'isolation d'un hôte compromis via Velociraptor (`Windows.Remediation.Quarantine`) |
| `ndr/` | configuration de la sonde : interfaces écoutées, Suricata, cluster Zeek |
| `pki/` | CA interne du lab (certificat public) et script d'émission des certificats |
| `soar/` | création du workflow Shuffle déclenché par Wazuh (`nodes/` : code des nœuds de confinement, d'isolation d'hôte et de déclenchement de chasse DFIR) |
| `velociraptor/` | artefacts serveur MISP ↔ Velociraptor |
| `detections/` | fiches de détection Windows et Linux |
| `purple-team/scenarios/` | une fiche par scénario (SC-01 à SC-16) |
| `docs/` | plan de reconstruction, inventaire, métriques, rapport d'incident, schéma d'architecture, captures (`screenshots/`) |

## Chronologie

Première réalisation du 2 au 15 août 2026, pause, puis reconstruction et audit du 13 septembre au
1er octobre 2026 (détail dans [`docs/rebuild-plan.md`](docs/rebuild-plan.md)).
