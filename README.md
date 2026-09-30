# SocForge — laboratoire SOC de bout en bout

SOC complet monté sur un seul PC (VirtualBox) : 12 machines virtuelles, de la détection à la
réponse. Chaque détection est déclenchée par une attaque réelle mais bénigne, observée dans le
SIEM, puis documentée avec ses preuves : extraits de journaux, heures UTC et captures.

Le projet documente aussi ce qui n'a **pas** marché du premier coup. Une bonne partie de sa valeur
est là : règles qui ne se déclenchaient jamais sans erreur visible, sonde réseau sans signatures,
pare-feu sans segmentation, SIEM tombé en silence faute de disque. Chaque défaut a été trouvé,
expliqué et corrigé à la racine.

## Présentation en vidéo

Une attaque réelle, suivie de bout en bout à travers les neuf outils du laboratoire (2 min 50,
sans son).

[![Vidéo : une attaque réelle, suivie de bout en bout](docs/media/poster.png)](docs/media/socforge-attaque-reelle.mp4)

## En chiffres

| 12 | 16 | 23 | 6 | 6 | 40 |
|:---:|:---:|:---:|:---:|:---:|:---:|
| machines virtuelles | scénarios d'attaque rejoués | règles de détection personnalisées | zones réseau segmentées | nœuds de la chaîne SOAR | captures de preuve |

Détection en **1 à 3 s**, prise en charge automatique en **~24 s**, blocage de l'attaquant, isolation
de l'hôte et chasse DFIR en **57 à 72 s** après la livraison de l'alerte
([métriques](docs/metrics-mttd-mtta-mttr.md)).

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

Depuis PURPLE, trois accès successifs au partage d'administration de WIN01 produisent une alerte
Wazuh de niveau 12 (règle `100141`, T1021.002). Cette **même alerte** traverse ensuite les six nœuds
de Shuffle, et chacun agit sur elle. Détail, heures UTC et preuves : [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md).

| Étape | Ce qui se passe |
|---|---|
| 1. Détection | Wazuh : règle `100140` (niveau 10) deux fois, puis `100141` (niveau 12) |
| 2. Orchestration | Shuffle crée l'alerte TheHive, sévérité 3, avec IP, agent et nom Windows en observables |
| 3. Enrichissement | Cortex interroge MISP : l'IP et le nom de poste figurent dans l'événement #5, tag `misp:match` |
| 4. Confinement réseau | l'IP de l'attaquant entre dans l'alias `BLOCKED_ATTACKERS` d'OPNsense |
| 5. Isolation de l'hôte | WIN01 est isolée par Velociraptor ; le canal de gestion reste ouvert |
| 6. Chasse DFIR | l'événement MISP est republié, la chasse retrouve 18 traces de l'attaque et renvoie 2 sightings |

<table>
<tr>
<td width="50%"><img src="docs/screenshots/wazuh-rule-100141-lateral-movement.png" alt="Alertes Wazuh 100140 puis 100141"><br><sub><b>Détection</b> : règle 100141 (niveau 12) précédée des 100140, agent WIN01, IP source 10.10.50.10</sub></td>
<td width="50%"><img src="docs/screenshots/thehive-alert-single-attack-chain.png" alt="Alerte TheHive à l'issue de la chaîne"><br><sub><b>Orchestration</b> : alerte TheHive de sévérité haute, tags <code>auto-contained</code>, <code>auto-quarantined</code>, <code>misp:match</code>, <code>dfir:hunt-triggered</code></sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/misp-event5-sightings-velociraptor.png" alt="Événement MISP 5 et sightings"><br><sub><b>Chasse</b> : événement MISP #5, 2 sightings renvoyés par Velociraptor</sub></td>
<td width="50%"><img src="docs/screenshots/opnsense-blocked-attackers-alias.png" alt="Alias BLOCKED_ATTACKERS d'OPNsense"><br><sub><b>Confinement</b> : alias <code>BLOCKED_ATTACKERS</code> d'OPNsense, alimenté par Shuffle (capture du mécanisme lors de son test)</sub></td>
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
| Détection Windows | 17 règles Sigma → Wazuh, toutes validées en direct (PowerShell encodé, tâche planifiée, clé Run, injection, mouvement latéral, profil PowerShell, accès LSASS…) | [`detection-sheet-windows.md`](detections/windows/detection-sheet-windows.md) |
| Détection Linux | sudo, persistance cron | [`detection-sheet-linux.md`](detections/linux/detection-sheet-linux.md) |
| Réseau | Suricata (52 795 signatures ET Open) détecte un scan, alerte niveau 10 dans Wazuh | [SC-12](purple-team/scenarios/scenario-ndr-purple-scan.md) |
| Segmentation | politique de refus par défaut entre 6 zones, attaquant sans accès au réseau d'administration, blocages visibles dans Wazuh | [SC-16](purple-team/scenarios/scenario-firewall-segmentation.md) |
| SIEM → SOAR → CTI | alerte Wazuh → Shuffle → TheHive (avec observables) → Cortex → MISP en **une seule exécution, 33 s**, sans action humaine ; tag `misp:match` sur l'alerte | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Gestion d'incident | alertes Wazuh promues en cas TheHive (licence StrangeBee), observables repris | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| DFIR | publication d'un événement MISP → chasse Velociraptor lancée **automatiquement** sur les postes Windows → sightings renvoyés à MISP dès la fin de la chasse ; persistance retrouvée alors que la clé était supprimée | [SC-15](purple-team/scenarios/scenario-dfir-velociraptor-misp-hunt.md) |
| Réponse automatique (réseau) | une alerte confirmée (sévérité ≥ 3, `misp:match`) fait bloquer son IP sur OPNsense par Shuffle lui-même, sans analyste — réversible par script | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Réponse automatique (hôte) | l'hôte compromis est isolé du réseau par Velociraptor (canal de gestion conservé), une fois le confinement réseau déjà déclenché — réversible par script | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Boucle SOAR → DFIR | un `misp:match` posé par la chaîne SOAR republie l'IOC dans MISP et déclenche la chasse Velociraptor correspondante, sans intervention | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| **Une seule attaque, toute la chaîne** | une attaque réelle depuis PURPLE (accès répétés aux partages d'administration) produit une alerte Wazuh de niveau 12 ; rejouée dans Shuffle, **la même alerte** est corrélée à MISP, bloque l'IP de l'attaquant sur OPNsense, isole WIN01 via Velociraptor (100 % de perte sur le réseau de gestion, canal conservé) et déclenche une chasse qui retrouve les 18 traces de l'attaque dans les journaux de WIN01, renvoyées à MISP en sightings | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Processus d'investigation | modèle de cas TheHive réutilisable (triage → confinement → éradication → récupération → REX), appliqué à un incident réel et clos | [SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md) |
| Chiffrement | TLS vérifié entre les outils (CA interne du lab), aucune vérification désactivée | [SC-15](purple-team/scenarios/scenario-dfir-velociraptor-misp-hunt.md), [SC-16](purple-team/scenarios/scenario-firewall-segmentation.md) |

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

## Quelques défauts trouvés en chemin

- **Règles qui ne sonnaient jamais, sans aucune erreur** : groupes mal nommés
  (`sysmon_event10` au lieu de `sysmon_event_10`), groupe inexistant
  (`windows_powershell`), `<same_source_ip/>` inopérant sur les événements Windows, règle
  de bruit court-circuitée par une règle officielle du même niveau. À chaque fois, la
  preuve a été apportée par `wazuh-logtest`, un test A/B ou la lecture des alertes réelles.
- **FIM** : le profil PowerShell n'était jamais surveillé (chemin masqué par la config
  locale de l'agent), et `report_changes` sur Program Files saturait le quota et bloquait
  le scan.
- **Infrastructure** : SIEM arrêté quatre jours par un disque plein, horloges faussées de
  plusieurs heures, NDR sans signatures, pare-feu sans aucune règle entre zones.
- **Une cause racine derrière plusieurs symptômes** : un écran bleu de WIN01, analysé avec
  WinDbg, a mené au journal VirtualBox : l'hyperviseur Windows (Intégrité de la mémoire)
  occupait AMD-V, et VirtualBox tournait en mode de repli. C'était la cause commune de la
  dérive des horloges, des gels de disque et des blocages au démarrage des VM.
- **Rôles** : TheHive se connectait à Cortex avec un compte `superadmin`, qui ne peut pas
  lancer d'analyseur ; l'administrateur de l'organisation TheHive n'avait aucun droit sur
  les incidents. Comptes corrigés selon le moindre privilège.

Le détail de chaque correction est dans [`docs/rebuild-plan.md`](docs/rebuild-plan.md).

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
| `docs/` | plan de reconstruction, inventaire, métriques, rapport d'incident, schéma d'architecture, captures (`screenshots/`) et vidéo de présentation (`media/`) |

## Limite connue

**Exécution par groupes.** Les machines de l'attaque et celles de la chaîne SOAR ne tiennent pas
ensemble en mémoire sur cet hôte. L'attaque et sa détection ont eu lieu en direct ; l'alerte réelle
a ensuite été livrée au webhook de Shuffle, et chaque maillon a agi sur elle ([SC-14](purple-team/scenarios/scenario-shuffle-soar-workflow.md)).

## Chronologie

Première réalisation du 2 au 15 août 2026, pause, puis reconstruction et audit du 13 au
30 septembre 2026 (détail dans [`docs/rebuild-plan.md`](docs/rebuild-plan.md)).
