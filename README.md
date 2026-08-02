# SocForge — Production SOC Lab

> Security Operations Center complet : SIEM · EDR · SOAR · Threat Hunting · Purple Team

## Architecture

```
Sources de télémétrie (Windows · Linux · Réseau · Firewall)
        ↓
Wazuh SIEM/XDR  ←  Sysmon · auditd · Zeek · Suricata
        ↓
Règles Wazuh + Sigma + YARA  →  Alerte de sécurité
        ↓
Shuffle SOAR
        ↓
Enrichissement  →  Cortex (analyzers) · MISP (threat intel)
        ↓
TheHive  →  Incident · Tâches · Observables
        ↓
Velociraptor DFIR  →  Collecte artefacts · Hunt distanciel
        ↓
Threat Hunting  →  Jupyter · Python · ATT&CK Navigator
        ↓
Purple Team  →  Atomic Red Team · MITRE Caldera
        ↓
KPI · MTTD · MTTA · MTTR · Couverture ATT&CK
```

## VM du laboratoire

| VM | Rôle | OS | IP |
|---|---|---|---|
| VM01-FW | Firewall / NAT | OPNsense | 10.10.10.1 |
| VM02-WAZUH | SIEM/XDR | Ubuntu 22.04 | 10.10.10.10 |
| VM03-THEHIVE | Gestion incidents | Ubuntu 22.04 | 10.10.10.20 |
| VM04-CORTEX | Analyzers IOC | Ubuntu 22.04 | 10.10.10.21 |
| VM05-MISP | Threat Intelligence | Ubuntu 22.04 | 10.10.10.22 |
| VM06-SHUFFLE | SOAR | Ubuntu 22.04 | 10.10.10.30 |
| VM07-NDR | Zeek + Suricata | Ubuntu 22.04 | 10.10.40.10 |
| VM08-DFIR-HUNT | Velociraptor + Jupyter | Ubuntu 22.04 | 10.10.60.10 |
| VM09-DC01 | Active Directory | Windows Server 2022 | 10.10.20.10 |
| VM10-WIN01 | Endpoint Windows | Windows 11 | 10.10.30.10 |
| VM11-LINUX01 | Endpoint Linux | Ubuntu 22.04 | 10.10.30.20 |
| VM12-PURPLE | Adversary Emulation | Kali Linux | 10.10.50.10 |

## Zones réseau

| Zone | Réseau VirtualBox | Sous-réseau |
|---|---|---|
| Management/SOC | socforge-mgmt | 10.10.10.0/24 |
| Serveurs | socforge-srv | 10.10.20.0/24 |
| Endpoints | socforge-ep | 10.10.30.0/24 |
| NDR | socforge-ndr | 10.10.40.0/24 |
| Purple Team | socforge-purple | 10.10.50.0/24 |
| DFIR | socforge-dfir | 10.10.60.0/24 |

## Progression

- [x] Phase 0 — Cadrage et préparation
- [ ] Phase 1 — Collecte et normalisation des logs
- [ ] Phase 2 — Detection Engineering
- [ ] Phase 3 — SOAR et gestion des incidents
- [ ] Phase 4 — EDR, DFIR et réponse distante
- [ ] Phase 5 — Threat Hunting
- [ ] Phase 6 — Purple Team et validation
- [ ] Phase 7 — KPI, évaluation et hardening

## Contraintes matérielles

- Hôte : Windows, 16 Go RAM
- Hyperviseur : VirtualBox 7.x
- Les 12 VM ne sont jamais toutes actives simultanément
- Blocs de VM A–G selon la phase en cours

## Outils

Wazuh · Sysmon · auditd · Zeek · Suricata · Sigma · YARA · TheHive · Cortex · MISP · Shuffle · Velociraptor · Jupyter · Grafana · Atomic Red Team · MITRE Caldera · OPNsense

## Sécurité

Voir [SECURITY.md](SECURITY.md) — lab 100 % local et isolé, aucun test externe.

---

*Projet éducatif de portfolio cybersécurité.*
