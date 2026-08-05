# SOC Detection Lab — SocForge

> A production-like Security Operations Center built from scratch on a 16 GB laptop.  
> Full pipeline: **SIEM → SOAR → Case Management → Threat Intelligence → DFIR → Purple Team**.

<div align="center">

![Lab Status](https://img.shields.io/badge/status-operational-39d353?style=flat-square)
![Phase](https://img.shields.io/badge/phase-3%20complete-00d4ff?style=flat-square)
![Scenarios](https://img.shields.io/badge/purple%20team-4%2F4%20scenarios-bc8cff?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1046%20%7C%20T1110%20%7C%20T1059.001%20%7C%20T1021.002-f0883e?style=flat-square)
![Wazuh](https://img.shields.io/badge/Wazuh-4.9.2-005571?style=flat-square)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Infrastructure](#infrastructure)
- [Detection Engineering](#detection-engineering)
- [Purple Team Scenarios](#purple-team-scenarios)
  - [Scenario 1 — T1046 Network Reconnaissance](#scenario-1--t1046-network-reconnaissance)
  - [Scenario 2 — T1110 Credential Brute Force](#scenario-2--t1110-credential-brute-force)
  - [Scenario 3 — T1059.001 PowerShell Encoded Command](#scenario-3--t1059001-powershell-encoded-command)
  - [Scenario 4 — T1021.002 SMB Lateral Movement](#scenario-4--t1021002-smb-lateral-movement)
- [KPI Dashboard](#kpi-dashboard)
- [Tech Stack](#tech-stack)
- [Project Phases](#project-phases)

---

## Overview

**SocForge** is a self-hosted, fully isolated SOC lab built on VirtualBox with 12 virtual machines, designed to demonstrate end-to-end detection, response, and threat-hunting capabilities.

The lab covers:
- **Detection Engineering** — custom Sigma/YARA rules mapped to MITRE ATT&CK
- **Purple Team Operations** — realistic attack simulations with verified detections
- **SOAR Automation** — Wazuh → Shuffle → TheHive alert pipeline
- **Threat Intelligence** — MISP feeds + Cortex enrichment
- **DFIR** — Velociraptor remote artifact collection

Every result shown in this repository is backed by a real screenshot taken from a live lab session. No simulated output.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ATTACK SIMULATION                            │
│              VM12-PURPLE (Kali Linux) — 10.10.10.60                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ socforge-mgmt (host-only)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         TARGET ENVIRONMENT                          │
│   DC01 (Windows Server 2022 AD) ──── WIN01 (Windows 11 Endpoint)  │
│   10.10.10.109                        10.10.10.110                  │
│         │ Wazuh Agent 002                   │ Wazuh Agent 003       │
└─────────┼─────────────────────────────────┬─┘─────────────────────┘
          │                                 │
          ▼                                 ▼
┌───────────────────────────────────────────────────────────────────┐
│                    VM02-WAZUH  (10.10.10.10)                      │
│   wazuh-manager ─── wazuh-indexer (OpenSearch) ─── Dashboard     │
│   11 custom Sigma rules · YARA integration · 2004+ alerts         │
└───────────────────────────┬───────────────────────────────────────┘
                            │
              ┌─────────────┴──────────────┐
              ▼                            ▼
┌─────────────────────┐      ┌─────────────────────────────────┐
│ VM06-SHUFFLE SOAR   │      │  VM03-THEHIVE (10.10.10.20)     │
│ 10.10.10.30         │─────▶│  Case Management · 16+ alerts   │
│ Webhook integration │      └────────────┬────────────────────┘
└─────────────────────┘                   │
                                          ▼
                             ┌─────────────────────────────────┐
                             │  VM04-CORTEX (10.10.10.21)      │
                             │  238 analyzers · MISP connector │
                             └────────────┬────────────────────┘
                                          │
                                          ▼
                             ┌─────────────────────────────────┐
                             │  VM05-MISP  (10.10.10.22)       │
                             │  CIRCL OSINT + Botvrij.eu feeds │
                             └─────────────────────────────────┘
```

---

## Infrastructure

| VM | Role | IP | OS | Status |
|---|---|---|---|---|
| `SF-VM02-WAZUH` | SIEM / XDR | 10.10.10.10 | Ubuntu 22.04 | ✅ Active |
| `SF-VM03-THEHIVE` | Case Management | 10.10.10.20 | Ubuntu 22.04 | ✅ Active |
| `SF-VM04-CORTEX` | Enrichment Engine | 10.10.10.21 | Ubuntu 22.04 | ✅ Active |
| `SF-VM05-MISP` | Threat Intelligence | 10.10.10.22 | Ubuntu 22.04 | ✅ Active |
| `SF-VM06-SHUFFLE` | SOAR | 10.10.10.30 | Ubuntu 22.04 | ✅ Active |
| `SF-VM08-DFIR` | DFIR / Velociraptor | 10.10.60.10 | Ubuntu 22.04 | ✅ Configured |
| `SF-VM09-DC01` | Active Directory DC | 10.10.10.109 | Windows Server 2022 | ✅ Active |
| `SF-VM10-WIN01` | Endpoint | 10.10.10.110 | Windows 11 | ✅ Domain-joined |
| `SF-VM12-PURPLE` | Red Team | 10.10.10.60 | Kali Linux 6.19.14 | ✅ Active |

**Network segmentation:**
- `socforge-mgmt` (10.10.10.0/24) — management plane, all VMs
- `socforge-srv` — DC01 primary service interface
- NAT adapters for host SSH access only — no internet exposure during lab sessions

---

## Detection Engineering

### Custom Sigma Rules

11 rules deployed to Wazuh, mapped to MITRE ATT&CK:

| Rule ID | Level | Technique | Description |
|---|---|---|---|
| 100100 | 10 | T1046 | Network scan detected (nmap signatures) |
| 100110 | 10 | T1110 | SMB brute-force — multiple failures |
| 100120 | 12 | T1078 | Valid account used after brute-force |
| 100130 | 12 | T1059.001 | PowerShell ScriptBlock encoded command |
| **100131** | **12** | **T1059.001 + T1027** | **PowerShell encoded command via EventID 4688** |
| 100135 | 8 | T1086 | PowerShell download cradle |
| **100140** | **10** | **T1021.002** | **Admin share access — ADMIN$ / C$** |
| 100150 | 10 | T1003 | LSASS access attempt |
| 100160 | 8 | T1547 | Registry run key persistence |
| 100165 | 10 | T1053 | Scheduled task creation |
| 100170 | 12 | T1055 | Process injection patterns |

**Detection chain example (Scenario 3):**
```
Windows EventID 4688 (Process Creation with command line logging)
    → Wazuh parent rule 67027
        → Rule 100131 fires: commandLine matches -EncodedCommand regex
            → Alert level 12 → Shuffle webhook → TheHive case created
```

---

## Purple Team Scenarios

All scenarios executed from `SF-VM12-PURPLE` (Kali Linux, 10.10.10.60) targeting `SF-VM09-DC01` (Windows Server 2022, 10.10.10.109). Every detection is verified with a live Wazuh dashboard screenshot.

---

### Scenario 1 — T1046 Network Reconnaissance

| | |
|---|---|
| **MITRE** | T1046 — Network Service Scanning |
| **Tool** | nmap 7.99 |
| **Command** | `nmap -sS -T4 10.10.10.109` |
| **Result** | Open ports: DNS/53, Kerberos/88, MSRPC/135, NetBIOS/139, LDAP/389, SMB/445 |
| **Detection** | Wazuh network intrusion signatures |

---

### Scenario 2 — T1110 Credential Brute Force

| | |
|---|---|
| **MITRE** | T1110 — Brute Force / T1078 — Valid Accounts |
| **Tool** | smbclient |
| **Command** | `smbclient //10.10.10.109/IPC$ -U 'SOCFORGE/john.doe%wrongpass'` × 6 |
| **Windows Event** | EventID 4625 (Logon Failure) — 12 events generated |
| **Detection** | Rule 60122 (level 5) — **18 hits** in alerts.log |
| **Forensic** | Source IP 10.10.10.60, Workstation: PURPLE identified |

---

### Scenario 3 — T1059.001 PowerShell Encoded Command

| | |
|---|---|
| **MITRE** | T1059.001 (PowerShell) + T1027 (Obfuscation) |
| **Wazuh Rule** | **100131 — Level 12** |
| **Windows Event** | **EventID 4688 — Process Creation** |
| **Detections** | **5 hits confirmed in Wazuh** |

#### Attack

```bash
# Payload: whoami; hostname; Get-Date
powershell -EncodedCommand dwBoAG8AYQBtAGkAOwAgAGgAbwBzAHQAbgBhAG0AZQA7ACAARwBlAHQALQBEAGEAdABlAA==
```

Executed via `Win+R` on DC01 — simulating an interactive user-run malicious command.

**Audit prerequisites enabled on DC01:**
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

#### Evidence

**Attack execution — Run dialog with encoded command:**

![Run dialog with encoded PowerShell command](docs/screenshots/scenario3_dc01_t1059_run_dialog.png)

**Audit policy change — Process Creation = Success:**

![Process Creation audit enabled](docs/screenshots/scenario3_dc01_audit_policy_enabled.png)

**Wazuh Threat Hunting — `rule.id:100131` — 3 hits — agent dc01:**

![Wazuh detection rule 100131](docs/screenshots/scenario3_wazuh_rule100131_detection.png)

**Document Details — MITRE T1059.001 + T1027 mapping:**

![MITRE details rule 100131](docs/screenshots/scenario3_wazuh_rule100131_mitre_details.png)

#### Alert Document (Wazuh OpenSearch — `wazuh-alerts-4.x-2026.08.05`)

| Field | Value |
|---|---|
| `rule.id` | `100131` |
| `rule.level` | `12` |
| `rule.description` | Sigma T1059.001: PowerShell encoded command via process creation (4688) |
| `rule.mitre.id` | `T1059.001`, `T1027` |
| `rule.mitre.tactic` | Execution, Defense Evasion |
| `rule.mitre.technique` | PowerShell, Obfuscated Files or Information |
| `rule.groups` | `socforge, sigma, execution, obfuscation, socforge_purple` |
| `data.win.system.eventID` | `4688` |
| `data.win.eventdata.newProcessName` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `data.win.eventdata.commandLine` | `powershell.exe -EncodedCommand YQB1...` |
| `data.win.eventdata.subjectDomainName` | `SOCFORGE` |
| `data.win.eventdata.subjectUserName` | `Administrator` |
| `agent.name` | `dc01` |
| `agent.ip` | `10.10.10.109` |

---

### Scenario 4 — T1021.002 SMB Lateral Movement

| | |
|---|---|
| **MITRE** | T1021.002 — SMB/Windows Admin Shares |
| **Wazuh Rule** | **100140 — Level 10** |
| **Windows Event** | **EventID 5140 — Network Share Object Accessed** |
| **Detections** | **9 hits confirmed in Wazuh** |

#### Attack

```bash
# From SF-VM12-PURPLE (10.10.10.60)
smbclient //10.10.10.109/ADMIN$ \
  -U 'SOCFORGE/Administrator%<password>' \
  -c 'ls'
# Result: Full C:\Windows directory listing obtained
```

**Audit prerequisite enabled on DC01:**
```cmd
auditpol /set /subcategory:"File Share" /success:enable
```

#### Evidence

**DC01 — File Share audit = Success:**

![File Share audit enabled](docs/screenshots/scenario4_dc01_fileshare_audit_enabled.png)

**Wazuh Threat Hunting — `rule.id:100140` — 3 hits — timeline spike:**

![Wazuh detection rule 100140](docs/screenshots/scenario4_wazuh_rule100140_3hits_overview.png)

**Document Details — ADMIN$ forensic evidence — source 10.10.10.60:**

![ADMIN$ document details](docs/screenshots/scenario4_wazuh_rule100140_admins_document.png)

#### Alert Document (Wazuh OpenSearch — `wazuh-alerts-4.x-2026.08.05`)

| Field | Value |
|---|---|
| `rule.id` | `100140` |
| `rule.level` | `10` |
| `rule.description` | Sigma T1021.002: Admin share access - possible lateral movement |
| `rule.mitre.id` | `T1021.002` |
| `rule.mitre.tactic` | Lateral Movement |
| `rule.mitre.technique` | SMB/Windows Admin Shares |
| `rule.groups` | `socforge, sigma, lateral_movement, socforge_purple` |
| `data.win.system.eventID` | `5140` |
| `data.win.eventdata.shareName` | `\\*\ADMIN$` |
| `data.win.eventdata.shareLocalPath` | `\\??\C:\Windows` |
| `data.win.eventdata.ipAddress` | `10.10.10.60` |
| `data.win.eventdata.subjectUserName` | `Administrator` |
| `data.win.eventdata.subjectDomainName` | `SOCFORGE` |
| `agent.name` | `dc01` |
| `agent.ip` | `10.10.10.109` |

---

## KPI Dashboard

All metrics extracted from live systems on 2026-08-05:

| KPI | Value | Source |
|---|---|---|
| Total Wazuh alerts (session) | **2,004** | `alerts.log` line count |
| Purple Team scenarios completed | **4 / 4** | Manual validation |
| Custom Sigma rules deployed | **11** | `socforge_sigma_rules.xml` |
| T1059.001 rule 100131 hits | **5** | `grep 'Rule: 100131' alerts.log` |
| T1021.002 rule 100140 hits | **9** | `grep 'Rule: 100140' alerts.log` |
| T1110 rule 60122 hits | **18** | `grep 'Rule: 60122' alerts.log` |
| TheHive alerts created | **16+** | TheHive REST API |
| Cortex analyzers available | **238** | Cortex admin panel |
| MISP threat feeds active | **2** | CIRCL OSINT + Botvrij.eu |
| Velociraptor agents enrolled | **2** | DC01 + WIN01 |
| Wazuh agents active | **2** | Agent IDs 002 + 003 |

---

## Tech Stack

| Category | Technology | Version |
|---|---|---|
| SIEM / XDR | Wazuh | 4.9.2 |
| Search / Indexing | OpenSearch | bundled with Wazuh |
| Case Management | TheHive | 5.4.7 |
| Enrichment | Cortex | 3.x |
| Threat Intelligence | MISP | 2.4.x |
| SOAR | Shuffle | 2.2.1 |
| DFIR | Velociraptor | 0.77.1 |
| Active Directory | Windows Server 2022 | — |
| Endpoint | Windows 11 | — |
| Red Team | Kali Linux | 6.19.14 |
| Hypervisor | Oracle VirtualBox | 7.x |
| Detection Language | Sigma (custom rules) | — |
| Detection Language | YARA | — |
| ATT&CK Framework | MITRE ATT&CK | v14 |

---

## Project Phases

| Phase | Description | Status |
|---|---|---|
| **Phase 0** | Lab design, 12 VM provisioning, network segmentation, Active Directory | ✅ Complete |
| **Phase 1** | Tool installation: Wazuh, TheHive, Cortex, MISP, Shuffle, Velociraptor | ✅ Complete |
| **Phase 2** | Agent deployment, Wazuh→TheHive pipeline, Cortex/MISP integration | ✅ Complete |
| **Phase 3** | Purple Team scenarios 1–4, custom Sigma rules, live detections verified | ✅ Complete |
| **Phase 4** | KPI metrics, portfolio documentation, GitHub publication | ✅ Complete |

---

## Repository Structure

```
.
├── wazuh/
│   ├── rules/              # Custom Sigma rules
│   ├── agents/             # Agent configuration (agent.conf)
│   ├── decoders/           # Custom decoders
│   └── dashboards/         # Dashboard exports
├── purple-team/
│   ├── scenarios/          # Attack playbooks
│   ├── atomic-tests/       # Atomic Red Team mappings
│   └── validation-matrix/  # Detection results
├── detections/
│   ├── sigma/              # Sigma rule source files
│   ├── yara/               # YARA rules
│   ├── windows/            # Windows detections
│   └── linux/              # Linux detections
├── infrastructure/         # Network diagrams, VM specs
├── incident-response/      # IR playbooks
├── threat-intelligence/    # MISP configs, IOC lists
├── dfir/                   # Velociraptor artifacts
├── docs/
│   ├── screenshots/        # All evidence screenshots
│   └── portfolio.html      # Self-contained portfolio page
└── scripts/                # Automation scripts
```

---

## Security Notice

This lab is **fully isolated** from the internet during all attack simulations:
- Bridge adapters disabled during Purple Team sessions
- All attack traffic confined to the `socforge-mgmt` host-only network (10.10.10.0/24)
- No real malware — all techniques are benign simulations (Atomic Red Team methodology)
- No external systems targeted at any point

---

*Built by **Omar Babba** — Cybersecurity Engineering Student*  
*omarbabba27@gmail.com*
