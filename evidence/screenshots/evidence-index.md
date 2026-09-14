# Index des Preuves Screenshots — SocForge

> Toutes les captures d'écran sont des preuves réelles de sessions lab.
> Aucune capture n'est simulée ou éditée.

---

## Phase 0 — Installation et déploiement

| Fichier | Description |
|---------|-------------|
| `docs/screenshots/phase0-install/VM02-WAZUH-all-services-active.png` | Services Wazuh actifs |
| `docs/screenshots/phase0-install/VM02-WAZUH-agent-list-dc01-ACTIVE.png` | Agent DC01 connecté |
| `docs/screenshots/phase0-install/VM02-WAZUH-agent-list-win01-ACTIVE.png` | Agent WIN01 connecté |
| `docs/screenshots/phase0-install/VM03-THEHIVE-api-status-5.4.7.png` | TheHive 5.4.7 actif |
| `docs/screenshots/phase0-install/VM04-CORTEX-HTTP303-wizard.png` | Cortex opérationnel |
| `docs/screenshots/phase0-install/VM05-MISP-running-HTTP302.png` | MISP opérationnel |
| `docs/screenshots/phase0-install/VM06-SHUFFLE-HTTP200-running.png` | Shuffle opérationnel |
| `docs/screenshots/phase0-install/VM08-VELOCIRAPTOR-running-port8889.png` | Velociraptor opérationnel |
| `docs/screenshots/phase0-install/VM09-DC01-AD-users-created.png` | AD utilisateurs créés |
| `docs/screenshots/phase0-install/VM09-DC01-wazuh-agent-SUCCESS.png` | Agent DC01 enregistré |
| `docs/screenshots/phase0-install/VM10-WIN01-ip-ping-MGMT.png` | WIN01 connecté au réseau |
| `docs/screenshots/phase0-install/VM10-WIN01-wazuhsvc-RUNNING.png` | Service Wazuh WIN01 actif |
| `docs/screenshots/phase0-install/VM11-LINUX01-wazuh-agent-ENROLLED.png` | Agent LINUX01 enregistré |
| `docs/screenshots/phase0-install/VM11-LINUX01-wazuh-agent-SUCCESS.png` | LINUX01 connecté Wazuh |

---

## Phase 1 — SOAR et gestion des incidents

| Fichier | Description |
|---------|-------------|
| `docs/screenshots/bloc1-soar/shuffle-soar-playbook-5nodes.jpg` | Workflow Shuffle 5 nœuds |
| `docs/screenshots/bloc1-soar/shuffle-execution-finished.jpg` | Exécution playbook terminée |
| `docs/screenshots/bloc1-soar/shuffle-all-workflow-runs.jpg` | Historique exécutions Shuffle |
| `docs/screenshots/bloc1-soar/thehive-alert-from-soar.jpg` | Alerte TheHive créée par SOAR |
| `docs/screenshots/bloc1-soar/thehive-alerts-350.jpg` | 350+ alertes TheHive |

---

## Phase 2 — MISP et Cortex (Enrichissement)

| Fichier | Description |
|---------|-------------|
| `docs/screenshots/bloc2-misp-cortex/cortex-job-misp-socforge-success.jpg` | Job Cortex MISP succès |
| `docs/screenshots/bloc2-misp-cortex/misp-event-2108-attributes.jpg` | Événement MISP attributs |
| `docs/screenshots/bloc2-misp-cortex/misp-event-2108-ioc.jpg` | IOC MISP Purple Team |
| `docs/screenshots/bloc2-misp-cortex/thehive-alert-enriched.jpg` | Alerte TheHive enrichie |

---

## Phase 3 — Purple Team (Scénarios 1-4)

| Fichier | Technique | Règle | Description |
|---------|-----------|-------|-------------|
| `docs/screenshots/scenario1_wazuh_rule100100_list.png` | T1046 | 100100 | Liste alertes nmap scan |
| `docs/screenshots/scenario1_wazuh_rule100100_details.png` | T1046 | 100100 | Détail alerte nmap scan |
| `docs/screenshots/scenario2_wazuh_rule60122_list_15hits.png` | T1110 | 60122 | 15 alertes brute force DC01 |
| `docs/screenshots/scenario2_wazuh_rule60122_dc01_details.png` | T1110 | 60122 | Détail événement DC01 |
| `docs/screenshots/scenario3_dc01_audit_policy_enabled.png` | T1059 | — | Audit policy DC01 activée |
| `docs/screenshots/scenario3_dc01_t1059_run_dialog.png` | T1059 | — | Exécution PowerShell DC01 |
| `docs/screenshots/scenario3_wazuh_rule100131_detection.png` | T1059 | 100131 | Détection PowerShell encodé |
| `docs/screenshots/scenario3_wazuh_rule100131_commandline.png` | T1059 | 100131 | Ligne de commande capturée |
| `docs/screenshots/scenario3_wazuh_rule100131_mitre_details.png` | T1059 | 100131 | Mapping MITRE ATT&CK |
| `docs/screenshots/scenario4_dc01_fileshare_audit_enabled.png` | T1021.002 | — | Audit partage fichiers activé |
| `docs/screenshots/scenario4_wazuh_rule100140_3hits_overview.png` | T1021.002 | 100140 | 3 alertes admin shares |
| `docs/screenshots/scenario4_wazuh_rule100140_list_3hits.png` | T1021.002 | 100140 | Liste hits admin shares |
| `docs/screenshots/scenario4_wazuh_rule100140_admins_document.png` | T1021.002 | 100140 | Accès ADMIN$ documenté |

---

## Phase 4 — DFIR (Velociraptor)

| Fichier | Description |
|---------|-------------|
| `docs/screenshots/phase2-velociraptor/vm08-both-clients-connected.png` | DC01+WIN01 connectés Velociraptor |
| `docs/screenshots/phase4-dfir/velociraptor-clients-connected.jpg` | Clients Velociraptor actifs |
| `docs/screenshots/phase4-dfir/velociraptor-dc01-overview.jpg` | Vue DC01 dans Velociraptor |
| `docs/screenshots/phase4-dfir/velociraptor-pslist-log-dc01.jpg` | Log pslist DC01 |
| `docs/screenshots/phase4-dfir/velociraptor-pslist-results-46rows.jpg` | 46 processus DC01 collectés |
| `docs/screenshots/phase4-dfir/velociraptor-shell-pslist-dc01.jpg` | Shell Velociraptor pslist |

---

## Phase 5 — Purple Team Sessions 1-3 (SC-05 à SC-12)

| Fichier | SC# | Technique | Règle | Description |
|---------|-----|-----------|-------|-------------|
| `docs/screenshots/sc05-wazuh-T1003-lsass-credential-dump.png` | SC-05 | T1003.001 | 100103 | Dump LSASS détecté |
| `docs/screenshots/sc06-wazuh-T1055-process-injection.png` | SC-06 | T1055 | 100155 | Injection processus détectée |
| `docs/screenshots/sc07-wazuh-T1547-registry-persistence.png` | SC-07 | T1547.001 | 92302 | Clé Run registre détectée |
| `docs/screenshots/sc08-wazuh-T1548-sudo-privilege-escalation.png` | SC-08 | T1548.003 | 5503 | Sudo abuse Linux détecté |
| `docs/screenshots/sc09-wazuh-T1053-cron-persistence.png` | SC-09 | T1053.003 | 100210 | Cron persistence détectée |
| `docs/screenshots/sc10-win01-attack-execution.png` | SC-10 | T1053.005 | — | WIN01 : schtasks exécuté (plusieurs erreurs "Access is denied" avant succès — capture montre les retries, pas une exécution propre du premier coup) |
| `docs/screenshots/sc11-win01-net-use.png` | SC-11 | T1078 | — | WIN01 : net use exécuté (idem — plusieurs échecs réseau visibles avant la commande réussie) |
| `docs/screenshots/sc12-win01-profile-modification.png` | SC-12 | T1546.013 | — | WIN01 : profile.ps1 modifié |
| `docs/screenshots/sc10-sc11-sc12-wazuh-detection.png` | SC-10/11/12 | Multiple | 60642/92037/92004 | Dashboard Wazuh : 3 détections |
| `docs/screenshots/phase3-purple/T1059-rule100131-expanded.jpg` | — | T1059 | 100131 | Détail règle étendu |
| `docs/screenshots/phase3-purple/T1059-rule100131.jpg` | — | T1059 | 100131 | Vue règle 100131 |
| `docs/screenshots/phase3-purple/T1059-rule100131-rule-details.jpg` | — | T1059 | 100131 | Détails de la définition de règle |
| `docs/screenshots/phase3-purple/T1110-rule60122-expanded-ip10.10.10.60.jpg` | — | T1110 | 60122 | Brute force depuis Purple VM |
| `docs/screenshots/kpi-mttd-chart.png` | — | — | — | Graphique MTTD par scénario, généré par `hunting/notebooks/threat-hunting-socforge.ipynb` |

---

## Phase 6 — Validation réelle post-déploiement (2026-09-14)

| Fichier | Technique | Règle | Description |
|---------|-----------|-------|-------------|
| `docs/screenshots/sc-real-bruteforce-wazuh-rule60122-dashboard.png` | T1110 | 60122 | Attaque SMB réelle LINUX01→DC01, 6 hits, MTTD < 1s — voir [IR-003](../../reports/incident-reports/IR-003-T1110-real-bruteforce-2026-09-14.md) |

---

## Architecture

| Fichier | Description |
|---------|-------------|
| `docs/screenshots/architecture.png` | Diagramme architecture SocForge |

---

**Total preuves screenshots** : 58 captures réelles de session lab (compte vérifié contre `git ls-files docs/screenshots/`)
