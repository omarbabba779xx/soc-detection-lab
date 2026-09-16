# Inventaire des VM — SocForge

## Tableau complet

| ID | Hostname | OS | Rôle | vCPU | RAM | Disque | Zone | IP |
|---|---|---|---|---|---|---|---|---|
| VM01 | FW | OPNsense 24.x | Firewall, NAT, logs | 1 | 1 Go | 15 Go | Multi | 10.10.10.1 |
| VM02 | WAZUH | Ubuntu 22.04 LTS | SIEM/XDR central | 4 | 5 Go | 100 Go | socforge-mgmt | 10.10.10.10 |
| VM03 | THEHIVE | Ubuntu 22.04 LTS | Gestion des incidents | 2 | 3 Go | 40 Go | socforge-mgmt | 10.10.10.20 |
| VM04 | CORTEX | Ubuntu 22.04 LTS | Analyzers IOC | 2 | 2 Go | 30 Go | socforge-mgmt | 10.10.10.21 |
| VM05 | MISP | Ubuntu 22.04 LTS | Threat Intelligence | 2 | 3 Go | 50 Go | socforge-mgmt | 10.10.10.22 |
| VM06 | SHUFFLE | Ubuntu 22.04 LTS | SOAR | 2 | 2 Go | 30 Go | socforge-mgmt | 10.10.10.30 |
| VM07 | NDR | Ubuntu 22.04 LTS | Zeek + Suricata | 2 | 3 Go | 80 Go | socforge-mgmt | 10.10.10.40 |
| VM08 | DFIR-HUNT | Ubuntu 22.04 LTS | Velociraptor + Jupyter | 2 | 3 Go | 60 Go | socforge-dfir | 10.10.60.10 |
| VM09 | DC01 | Windows Server 2022 Eval | Active Directory, DNS | 2 | 3 Go | 50 Go | socforge-mgmt | 10.10.10.109 |
| VM10 | WIN01 | Windows 11 Eval | Endpoint Windows | 2 | 3 Go | 60 Go | socforge-mgmt | 10.10.10.110 |
| VM11 | LINUX01 | Ubuntu 22.04 LTS | Endpoint Linux | 1 | 2 Go | 30 Go | socforge-mgmt | 10.10.10.111 |
| VM12 | PURPLE | Kali Linux 2024.2 | Adversary emulation | 2 | 2 Go | 40 Go | socforge-mgmt | 10.10.10.60 |

**RAM totale théorique :** ~32 Go — utilisation par blocs uniquement.

## Blocs d'activation RAM

| Bloc | VM actives | RAM totale | Objectif |
|---|---|---|---|
| A — Infrastructure | FW + DC01 + WIN01 | ~7 Go | AD, DNS, GPO |
| B — Collecte endpoint | WAZUH + WIN01 ou LINUX01 | ~8 Go | Agents, Sysmon, auditd |
| C — Détection réseau | WAZUH + NDR + PURPLE + FW | ~11 Go | Zeek, Suricata |
| D — SOAR/Incidents | WAZUH + SHUFFLE + THEHIVE | ~10 Go | Playbooks, TheHive |
| E — DFIR | DFIR-HUNT + WIN01 ou LINUX01 | ~6 Go | Velociraptor |
| F — Purple Team | PURPLE + WAZUH + WIN01 | ~10 Go | Tests ATT&CK |
| G — Reporting | DFIR-HUNT seul | ~3 Go | Jupyter, Grafana, KPI |

## Snapshots obligatoires

| Nom du snapshot | Moment | VM concernées |
|---|---|---|
| SNAPSHOT-00-BASE-INSTALL | Après OS install + mises à jour | Toutes |
| SNAPSHOT-01-WAZUH-INSTALLED | Après Phase 1 | VM02 |
| SNAPSHOT-02-AGENTS-OK | Agents validés | VM02, VM10, VM11 |
| SNAPSHOT-PRE-PURPLE-[DATE] | Avant chaque campagne Purple | Cibles concernées |
