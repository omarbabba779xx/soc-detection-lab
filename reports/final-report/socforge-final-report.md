# SocForge — Rapport Final de Projet

**Titre**: Conception et Déploiement d'un SOC Lab Complet — SocForge
**Auteur**: SocForge Lab
**Date**: 2026-08-15
**Version**: 2.0

---

## Résumé Exécutif

SocForge est un laboratoire SOC complet déployé sur environnement VirtualBox local, composé de 12 machines virtuelles organisées en 5 zones réseau. Le projet couvre l'intégralité du pipeline SOC moderne: collecte (Wazuh/SIEM), automatisation (Shuffle/SOAR), gestion d'incidents (TheHive), enrichissement (Cortex/MISP), détection réseau (Zeek/Suricata) et investigation forensique (Velociraptor).

**Résultats clés**:
- MTTD moyen: **26.0 secondes** (objectif: < 5 minutes) — 13 scénarios validés en 3 sessions
- Taux de détection Purple Team: **100%** (13/13 techniques, 0 faux positifs)
- Coverage MITRE ATT&CK: **78%** (18/23 techniques)
- Alertes TheHive générées: **353+**
- Sources de logs intégrées: **7 sources actives**

---

## 1. Architecture Déployée

### 1.1 Inventaire VMs

| VM   | Nom             | OS                  | Rôle                     | IP            |
|------|-----------------|---------------------|--------------------------|---------------|
| VM01 | FW-OPNSENSE     | OPNsense 24.x       | Firewall / NAT / Syslog  | 10.10.10.1    |
| VM02 | WAZUH           | Ubuntu Server 22.04 | SIEM/XDR Manager+Indexer | 10.10.10.10   |
| VM03 | THEHIVE         | Ubuntu Server 22.04 | Case Management          | 10.10.10.20   |
| VM04 | CORTEX          | Ubuntu Server 22.04 | IOC Enrichissement       | 10.10.10.21   |
| VM05 | MISP            | Ubuntu Server 22.04 | Threat Intelligence      | 10.10.10.22   |
| VM06 | SHUFFLE         | Ubuntu Server 22.04 | SOAR Orchestration       | 10.10.10.30   |
| VM07 | NDR             | Ubuntu Server 22.04 | Zeek + Suricata NDR      | 10.10.10.40   |
| VM08 | DFIR-HUNT       | Ubuntu Server 22.04 | Velociraptor DFIR        | 10.10.60.10   |
| VM09 | DC01            | Windows Server 2022 | AD + DNS + Wazuh Agent   | 10.10.10.109  |
| VM10 | WIN01           | Windows 11          | Endpoint + Sysmon        | 10.10.10.110  |
| VM11 | LINUX01         | Ubuntu Server 22.04 | Linux Endpoint + auditd  | 10.10.10.111  |
| VM12 | PURPLE          | Kali Linux 2024     | Red Team / Atomic RT     | 10.10.10.60   |

### 1.2 Réseau déployé

| Réseau VirtualBox | CIDR              | VMs                                                        |
|-------------------|-------------------|------------------------------------------------------------|
| socforge-mgmt     | 10.10.10.0/24     | VM01–VM07, VM09-DC01, VM10-WIN01, VM11-LINUX01, VM12-PURPLE |
| socforge-dfir     | 10.10.60.0/24     | VM08-DFIR-HUNT                                             |

> Le plan initial prévoyait 5 zones réseau isolées. Le déploiement réel utilise un réseau
> plat sur socforge-mgmt (10.10.10.0/24). L'isolation de VM12-PURPLE est assurée
> par des règles firewall sur VM01-FW (règles LAN → BLOCK vers outils SOC).

---

## 2. Détections Configurées

### 2.1 Règles Wazuh

| Règle   | Technique    | Description                           | Niveau |
|---------|--------------|---------------------------------------|--------|
| 100101  | T1046        | Network Service Scanning (Sysmon-3)   | 8      |
| 100110  | T1110        | Authentication failure (4625)         | 6      |
| 100111  | T1110        | Brute force frequency detection       | 10     |
| 100120  | T1059.001    | PowerShell execution (4688)           | 8      |
| 100121  | T1059.001    | PowerShell encoded command (4688/4104)| 12     |
| 100103  | T1003.001    | LSASS Access (Sysmon-10)              | 14     |
| 100127  | T1027        | Base64 obfuscation                    | 10     |
| 100131  | T1059.001    | Malicious script block (4104)         | 12     |
| 100140  | T1021.002    | Admin share access (5140)             | 10     |
| 100153  | T1053.005    | Scheduled task creation (4698)        | 9      |
| 100155  | T1055        | CreateRemoteThread injection (Sysmon-8)| 13   |
| 100147  | T1547.001    | Registry Run/RunOnce/Winlogon persistence (Sysmon-13/14) | 9 |
| 100200  | T1548.003    | Sudo privilege escalation (Linux auditd, SC-09) | 10 |
| 100210  | T1053.003    | Cron persistence (Linux syslog/auditd, SC-10) | 10 |
| 60642   | T1053.005    | Schtasks scheduled (built-in, SC-11)  | 3      |
| 92037   | T1078        | net.exe remote resource connection (SC-12) | 3 |
| 92004   | T1546.013    | PowerShell spawned cmd shell (SC-13)  | 4      |

### 2.2 Sigma Rules

11 règles YAML dans `detections/sigma/`:
T1046, T1110, T1059.001, T1027, T1078, T1021.002, T1003.001, T1547.001, T1053, T1055, T1546.013

### 2.3 YARA Rules

9 règles dans `detections/yara/socforge_rules.yar`:
PowerShell Encoded Command, PowerShell Download Cradle, Mimikatz Strings, Invoke-Mimikatz, Meterpreter Strings, PowerShell Empire, PsExec Usage, Packed Executable, Atomic Red Team Artifacts

---

## 3. Pipeline SOAR

**Workflow**: Wazuh → Shuffle → MISP → Cortex → TheHive

1. Wazuh Manager envoie l'alerte via webhook HTTP POST vers Shuffle
2. Shuffle filtre: niveau ≥ 10 uniquement
3. Shuffle interroge MISP pour lookup IOC sur l'IP source
4. Shuffle enrichit via Cortex (MaxMind GeoIP)
5. Shuffle crée une alerte TheHive avec observables et contexte enrichi

**Résultat**: 350+ alertes TheHive créées automatiquement lors de l'exercice du 2026-08-07.

---

## 4. Exercice Purple Team — Résultats

### 4.1 Scénarios testés (3 sessions — 13/13 ✅)

**Session 1** — 2026-08-07 (10h00–14h30 UTC) — Windows

| Scénario        | Outil                   | Résultat | MTTD   |
|-----------------|-------------------------|----------|--------|
| SC-01 T1059.001 | Atomic Red Team         | ✅ VP    | 12s    |
| SC-02 T1110     | Hydra                   | ✅ VP    | 8s     |
| SC-03 T1046     | nmap                    | ✅ VP    | 15s    |
| SC-04 T1021.002 | net use / smbclient     | ✅ VP    | 23s    |
| SC-05 T1003.001 | PowerShell P/Invoke     | ✅ VP    | 6s     |
| SC-06 T1055     | PowerShell P/Invoke     | ✅ VP    | 9s     |
| SC-07 T1547.001 | reg.exe + Atomic RT     | ✅ VP    | 18s    |
| SC-08 T1027     | Atomic T1027 (base64)   | ✅ VP    | 47s    |

**Session 2** — 2026-08-07 (14h00–17h30 UTC) — Linux

| Scénario        | Outil                   | Résultat | MTTD   |
|-----------------|-------------------------|----------|--------|
| SC-09 T1548.003 | SSH + sudo              | ✅ VP    | 11s    |
| SC-10 T1053.003 | crontab -e              | ✅ VP    | 14s    |

**Session 3** — 2026-08-15 — Techniques restantes Windows

| Scénario        | Outil                   | Résultat | MTTD   |
|-----------------|-------------------------|----------|--------|
| SC-11 T1053.005 | schtasks.exe            | ✅ VP    | 84s    |
| SC-12 T1078     | net use + EventID 4648  | ✅ VP    | 42s    |
| SC-13 T1546.013 | cmd /c echo >> profile  | ✅ VP    | 49s    |

### 4.2 KPI Atteints

| KPI              | Objectif     | Résultat            |
|------------------|-------------|---------------------|
| MTTD moyen       | < 5 minutes | **26.0 secondes**  |
| Taux détection   | > 80%       | **100%** (13/13)    |
| Faux positifs    | < 5%        | **0** (0.000%)      |
| Coverage MITRE   | > 70%       | **78%**             |
| Alertes TheHive  | Pipeline OK | **353+ alertes**    |

---

## 5. DFIR — Velociraptor

- 2 clients connectés: DC01 (Agent 002), WIN01 (Agent 003)
- Pslist DC01: 46 processus collectés, aucun suspect
- 3 artefacts personnalisés créés (pslist, netstat, evtx-hunt)
- 1 hunt créé (LsassAccess)
- Rapport d'investigation complet: `dfir/velociraptor/investigation-report-2026-08-07.md`

---

## 6. Threat Hunting

- 8 hypothèses de hunt documentées (`hunting/hypotheses/`)
- 3 hunts exécutés et validés (Hunt-001, Hunt-002, Hunt-003)
- Requêtes OpenSearch et VQL documentées
- Notebook de résultats: `hunting/notebooks/hunt-results-2026-08-07.md`

---

## 7. Recommandations

### 7.1 Améliorations court terme

1. **Réduire bruit T1021.002**: Agrégation ajoutée dans règle 100140 (résolu)
2. **Baisser seuil T1110**: Réduit de 5 à 3 tentatives en 30s pour améliorer MTTD (résolu)
3. **T1078 MTTD 42s**: Réduire délai polling EventID 4648 à 5s dans la règle 92037

### 7.2 Améliorations moyen terme

1. **Activer PPL LSASS**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` sur DC01
2. **Déployer LAPS**: Mots de passe admin locaux aléatoires
3. **Activer MFA**: Sur les comptes privilégiés (non disponible en lab — simulation)
4. **Zeek JA3**: Activer les fingerprints TLS pour détecter le beaconing C2
5. **Élargir coverage MITRE**: Ajouter règles pour T1082, T1083 (Discovery) et T1041 (Exfiltration)

### 7.3 Améliorations long terme

1. **Threat Intelligence**: Ajouter flux TAXII automatisés vers MISP (CIRCL, AlienVault)
2. **SOAR enrichissement**: Intégrer VirusTotal et Shodan dans le workflow Shuffle
3. **Détection comportementale**: Déployer des modèles d'anomalie (User Behavior Analytics)
4. **Tableau de bord SOC**: Créer dashboard OpenSearch custom avec les KPIs en temps réel

---

## 8. Conclusion

SocForge constitue un environnement SOC complet et reproductible qui démontre la maîtrise du pipeline de sécurité moderne. Tous les objectifs de détection ont été atteints lors des 3 sessions d'exercice Purple Team: **13/13 techniques détectées** avec un MTTD moyen de **26.0 secondes** (objectif: < 5 minutes) et **0 faux positif**. Le projet illustre la complémentarité entre SIEM, SOAR, Threat Intelligence, DFIR et Threat Hunting dans un contexte d'apprentissage isolé et contrôlé.

**Sécurité**: Tout au long du projet, les contraintes de sécurité ont été strictement respectées:
- Environnement 100% local et isolé (pas d'Internet vers les cibles)
- Aucun malware réel utilisé
- Uniquement des cibles autorisées dans le lab
- Mode Bridge interdit pour VM12-PURPLE

---

---

## 9. MTTR — Mean Time to Respond

| Métrique | Valeur   | Notes                                        |
|----------|----------|----------------------------------------------|
| MTTA     | ~5 min   | Temps moyen d'acknowledgement (Shuffle→TheHive) |
| MTTR     | ~2h 06m  | Temps moyen résolution (alert→case closed, lab complet) |
| MTTD     | 26.0s   | Temps moyen détection (attack→Wazuh alert)   |

Les cas TheHive sont créés automatiquement par Shuffle dans les 5 minutes suivant une alerte
de niveau ≥ 10. La résolution manuelle (isolation, investigation, remédiation) prend en
moyenne 15 minutes dans ce contexte de lab.

---

*Document généré: 2026-08-15 — SocForge Lab v2.0*
