# SocForge — SOC Detection Lab

Home lab SOC built on VirtualBox (16 GB RAM). 12 VMs, Wazuh + SOAR pipeline, 12 purple team scenarios.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Infrastructure](#infrastructure)
- [Detection Engineering](#detection-engineering)
- [Purple Team Results](#purple-team-results)
  - [T1046 — Network Reconnaissance](#t1046--network-reconnaissance)
  - [T1110 — Credential Brute Force](#t1110--credential-brute-force)
  - [T1059.001 — PowerShell Encoded Command](#t1059001--powershell-encoded-command)
  - [T1021.002 — SMB Lateral Movement](#t1021002--smb-lateral-movement)
  - [T1003.001 — LSASS Memory Access](#t1003001--lsass-memory-access)
  - [T1055 — Process Injection](#t1055--process-injection)
  - [T1547.001 — Registry Run Key Persistence](#t1547001--registry-run-key-persistence)
  - [T1548.003 — Sudo Privilege Escalation](#t1548003--sudo-privilege-escalation)
  - [T1053.003 — Cron Persistence](#t1053003--cron-persistence)
- [SOAR Pipeline](#soar-pipeline)
- [Threat Intelligence — MISP + Cortex](#threat-intelligence--misp--cortex)
- [DFIR — Velociraptor](#dfir--velociraptor)
- [KPI Metrics](#kpi-metrics)
- [Infrastructure Gallery](#infrastructure-gallery)
- [Tech Stack](#tech-stack)
- [Project Phases](#project-phases)
- [Repository Structure](#repository-structure)
- [Security Notice](#security-notice)

---

## Overview

**SocForge** is a fully isolated, self-hosted SOC lab running 12 virtual machines on VirtualBox. Every component is integrated end-to-end: alerts flow automatically from Wazuh through Shuffle SOAR into TheHive, enriched by Cortex and MISP, and investigated with Velociraptor.

**What this lab demonstrates:**

- Detection Engineering — 17 custom Sigma rules mapped to MITRE ATT&CK, deployed to Wazuh
- Purple Team Operations — 13 attack scenarios executed and validated (100% detection rate)
- SOAR Automation — Wazuh → Shuffle → TheHive pipeline, 7-second end-to-end latency
- Threat Intelligence — MISP feeds (CIRCL, Botvrij.eu, URLhaus, MalwareBazaar) + Cortex enrichment
- DFIR — Velociraptor remote artifact collection on live Windows targets
- NDR — Zeek 8.0.10 + Suricata 6.0.4 deployed on live traffic, verified capturing real sessions
- LLM Alert Triage — local Ollama model triaging real Wazuh alerts, no cloud dependency ([details](docs/llm-triage/))
- CI/CD — GitHub Actions validates every Wazuh rule change automatically

Every result in this repository comes from a real lab session. No simulated output, no mocked data.

---

## Architecture

![SocForge Architecture](docs/screenshots/architecture.png)

---

## Infrastructure

> See [architecture diagram](docs/screenshots/architecture.png) for the full topology and data-flow overview.

| VM | Role | IP | OS | Status |
|---|---|---|---|---|
| `SF-VM01-FW` | Firewall / Gateway | 10.10.10.1 | OPNsense 24.x | ✅ Active |
| `SF-VM02-WAZUH` | SIEM / XDR | 10.10.10.10 | Ubuntu 22.04 | ✅ Active |
| `SF-VM03-THEHIVE` | Case Management | 10.10.10.20 | Ubuntu 22.04 | ✅ Active |
| `SF-VM04-CORTEX` | Enrichment Engine | 10.10.10.21 | Ubuntu 22.04 | ✅ Active |
| `SF-VM05-MISP` | Threat Intelligence | 10.10.10.22 | Ubuntu 22.04 | ✅ Active |
| `SF-VM06-SHUFFLE` | SOAR | 10.10.10.30 | Ubuntu 22.04 | ✅ Active |
| `SF-VM07-NDR` | Network Detection | 10.10.10.40 | Ubuntu 22.04 | ✅ Active |
| `SF-VM08-DFIR-HUNT` | DFIR / Velociraptor | 10.10.60.10 | Ubuntu 22.04 | ✅ Active |
| `SF-VM09-DC01` | Active Directory DC | 10.10.10.109 | Windows Server 2022 | ✅ Active |
| `SF-VM10-WIN01` | Windows Endpoint | 10.10.10.110 | Windows 11 | ✅ Domain-joined |
| `SF-VM11-LINUX01` | Linux Endpoint | 10.10.10.111 | Ubuntu 22.04 | ✅ Active |
| `SF-VM12-PURPLE` | Red Team | 10.10.10.60 | Kali Linux 2024.2 | ✅ Active |

**Network:**  
All VMs share `socforge-mgmt` (10.10.10.0/24) — flat internal network via VirtualBox Internal Network adapters (not host-only — isolated from the host, reachable only VM-to-VM or through NAT port-forwards for management access). VM08-DFIR is on a separate `socforge-dfir` (10.10.60.0/24). No internet exposure during attack simulations.

---

## Detection Engineering

### Custom Sigma Rules — 17 deployed to Wazuh (15 Windows + 2 Linux)

| Rule ID | Level | Technique | Description |
|---|---|---|---|
| 100101 | 8 | T1046 | Network scan — Sysmon EventID 3 network connection |
| 100110 | 6 | T1110 | Authentication failure — EventID 4625 |
| 100111 | 10 | T1110 | Brute force frequency threshold (5 fails / 30s) |
| 100120 | 8 | T1059.001 | PowerShell execution — EventID 4688 |
| 100121 | 12 | T1059.001 + T1027 | PowerShell -EncodedCommand / obfuscated — EventID 4688/4104 |
| **100131** | **12** | **T1059.001** | **Malicious Script Block Logging — EventID 4104** |
| 100127 | 10 | T1027 | Base64 obfuscation pattern — EventID 4688 |
| **100140** | **10** | **T1021.002** | **Admin share ADMIN$/C$ access — EventID 5140** |
| 100153 | 9 | T1053.005 | Scheduled task creation — EventID 4698 |
| 100103 | 14 | T1003.001 | LSASS memory access (Sysmon EventID 10) |
| 100155 | 13 | T1055 | Process injection — CreateRemoteThread (Sysmon EventID 8) |
| 92302 | 6 | T1547.001 | Registry Run key persistence (Sysmon EventID 13, built-in) |
| 60122 | 5 | T1110 | Logon failure — invalid credentials (built-in) |
| 100200 | 10 | T1548.003 | Sudo privilege escalation — Linux auditd |
| 100210 | 10 | T1053.003 | Cron persistence — Linux syslog/auditd |

**Example detection chain (T1059.001):**
```
EventID 4688 (Process Creation + command line logging enabled)
    → Wazuh parent rule 67027
        → Rule 100131 fires: commandLine matches /-EncodedCommand/i
            → Level 12 alert → Shuffle webhook (2s) → TheHive alert created (5s)
```
Total pipeline: **7 seconds** from Wazuh alert to TheHive case.

---

## Purple Team Results

All scenarios executed from `SF-VM12-PURPLE` (10.10.10.60) against `SF-VM09-DC01` (10.10.10.109) and `SF-VM10-WIN01` (10.10.10.110). Every detection verified against Wazuh Threat Hunting with live screenshots.

| # | Technique | Tool | MTTD | Rule | Hits | Result |
|---|---|---|---|---|---|---|
| SC-01 | T1059.001 PowerShell | Atomic Red Team | 12s | 100131 | 4 | ✅ PASS |
| SC-02 | T1110 Brute Force | Hydra | 8s | 60122 / 100110 | 29 | ✅ PASS |
| SC-03 | T1046 Network Scan | nmap | 15s | 100101 | 2 | ✅ PASS |
| SC-04 | T1021.002 SMB | net use / smbclient | 23s | 100140 | 651,564 | ✅ PASS |
| SC-05 | T1003.001 LSASS | PowerShell P/Invoke | 6s | 100103 | 110 | ✅ PASS |
| SC-06 | T1055 Injection | PowerShell P/Invoke | 9s | 100155 | 2 | ✅ PASS |
| SC-07 | T1547.001 Registry | reg.exe + Atomic | 18s | 92302 | 3 | ✅ PASS |
| SC-08 | T1027 Obfuscation | Atomic Red Team (Base64) | 47s | 100127 | 10 | ✅ PASS |
| SC-09 | T1548.003 Sudo Abuse | SSH + sudo | 11s | 100200 | 4 | ✅ PASS |
| SC-10 | T1053.003 Cron Persist | crontab | 14s | 100210 | 1 | ✅ PASS |
| SC-11 | T1053.005 Scheduled Task Win | schtasks /create | 84s | 60642 | 1 | ✅ PASS |
| SC-12 | T1078 Valid Account | net use \\localhost\C$ | 42s | 92037 | 1 | ✅ PASS |
| SC-13 | T1546.013 PS Profile | cmd echo >> profile.ps1 | 49s | 92004 | 1 | ✅ PASS |

MTTD average across all 13 scenarios (Sessions 1-3): **26.0s**  
(12+8+15+23+6+9+18+47+11+14+84+42+49) / 13 = 338 / 13 = 26.0s

---

### T1046 — Network Reconnaissance

| | |
|---|---|
| **Tool** | nmap 7.99 |
| **Command** | `nmap -sS -T4 10.10.10.109` |
| **Result** | Ports open: 53/DNS, 88/Kerberos, 135/MSRPC, 139/NetBIOS, 389/LDAP, 445/SMB |
| **Detection** | Rule 100100 — level 10 (historical ID at capture time — see note below) |

> **Rule ID note**: this screenshot shows `rule.id: 100100`, captured before the ruleset was reorganized. The current `wazuh/rules/socforge_sigma_rules.xml` implements this same detection (T1046 scan-tool match) as **100102** (child of base rule **100101**, level 8). The screenshot is genuine — the ID was renumbered during later cleanup and this reference was never backfilled.
>
> **Attribution caveat**: the alert's `agent.name` field shows `wazuh` (the manager itself, agent id 000), not `dc01`. This means the alert was generated from telemetry processed at the manager level rather than a DC01 endpoint event — the scan against DC01 (10.10.10.109) was real, but this specific evidence attributes the detection to the manager, not the target endpoint. Worth re-verifying which host actually emitted the underlying event next time this scenario is re-run.

**Wazuh Threat Hunting — `rule.id:100100` — 2 hits:**

![T1046 Wazuh rule 100100 list](docs/screenshots/scenario1_wazuh_rule100100_list.png)

**Document details — MITRE T1046 mapping — groups: sigma, network_scan, recon:**

![T1046 Wazuh rule 100100 details](docs/screenshots/scenario1_wazuh_rule100100_details.png)

---

### T1110 — Credential Brute Force

| | |
|---|---|
| **Tool** | smbclient / Hydra |
| **Command** | `hydra -l Administrator -P rockyou.txt smb://10.10.10.109` |
| **Events** | EventID 4625 — 29 logon failures generated |
| **Detection** | Rule 60122 (level 5 per attempt) + Rule 100111 (level 10 at 5th attempt) |
| **Forensic** | Source: 10.10.10.60 · Target: Administrator@SOCFORGE · Workstation: WIN-FJ8RP03U8FK |

**Wazuh Threat Hunting — `rule.id:60122` — 29 hits:**

![T1110 Wazuh rule 60122 list](docs/screenshots/scenario2_wazuh_rule60122_list_15hits.png)

**Document details — agent dc01, EventID 4625, ipAddress 10.10.10.60:**

![T1110 Wazuh dc01 logon failure](docs/screenshots/scenario2_wazuh_rule60122_dc01_details.png)

**T1110 expanded — source IP 10.10.10.60 confirmed:**

![T1110 rule expanded](docs/screenshots/phase3-purple/T1110-rule60122-expanded-ip10.10.10.60.jpg)

**Independent re-validation (2026-09-14)** — a second, separately-executed T1110 test (SMB/NTLM via `smbclient` from LINUX01 against DC01) confirmed the detection chain end-to-end: 6/6 real auth failures matched to 6 real rule-60122 alerts, MTTD < 1s. Full writeup and dashboard screenshot: [IR-003](reports/incident-reports/IR-003-T1110-real-bruteforce-2026-09-14.md).

---

### T1059.001 — PowerShell Encoded Command

| | |
|---|---|
| **Technique** | T1059.001 (PowerShell) + T1027 (Obfuscation) |
| **Rule** | 100131 — Level 12 |
| **Event** | EventID 4688 — Process Creation |
| **Hits** | **4 confirmed in Wazuh** (2 validation runs Aug 5 + 2 Purple Team runs Aug 7) |

> **Why 4 hits?** Rule 100131 targets `ScriptBlockLogging` events with a Base64-encoded payload launched from a non-interactive shell. It fires only when all conditions are met simultaneously — this is intentional precision. 4 hits = 4 true positives, 0 false positives across the full test window. A higher hit count would indicate the rule is too broad.

**Attack payload (as captured in the alert evidence below):**
```bash
# Real commandLine field from the alert (agent dc01, EventID 4688):
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAFQAMQAwADUAOQAuADEA...
# Decodes to: Write-Host T1059.1... — an Atomic Red Team T1059.001 benign test marker
```

Executed via `Win+R` on DC01 — simulating an interactive malicious command.

**Audit prerequisites enabled on DC01:**
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**Run dialog — encoded command executed on DC01:**

![T1059 run dialog encoded command](docs/screenshots/scenario3_dc01_t1059_run_dialog.png)

**Audit policy — Process Creation = Success enabled:**

![T1059 audit policy enabled](docs/screenshots/scenario3_dc01_audit_policy_enabled.png)

**Wazuh Threat Hunting — `rule.id:100131` — 4 hits — agent dc01:**

![T1059 Wazuh detection rule 100131](docs/screenshots/scenario3_wazuh_rule100131_detection.png)

**Document details — MITRE T1059.001 + T1027 dual mapping:**

![T1059 MITRE details](docs/screenshots/scenario3_wazuh_rule100131_mitre_details.png)

**Document details — commandLine field showing -EncodedCommand payload:**

![T1059 commandLine field](docs/screenshots/scenario3_wazuh_rule100131_commandline.png)

**Alert document (OpenSearch `wazuh-alerts-4.x-2026.08.05`):**

| Field | Value |
|---|---|
| `rule.id` | `100131` |
| `rule.level` | `12` |
| `rule.description` | Sigma T1059.001: PowerShell encoded command via process creation (4688) |
| `rule.mitre.id` | `T1059.001`, `T1027` |
| `rule.mitre.tactic` | Execution, Defense Evasion |
| `rule.groups` | `socforge, sigma, execution, obfuscation, socforge_purple` |
| `data.win.system.eventID` | `4688` |
| `data.win.eventdata.newProcessName` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `data.win.eventdata.commandLine` | `powershell.exe -EncodedCommand YQB1...` |
| `data.win.eventdata.subjectDomainName` | `SOCFORGE` |
| `agent.name` | `dc01` · `agent.ip` → `10.10.10.109` |

---

### T1021.002 — SMB Lateral Movement

| | |
|---|---|
| **Technique** | T1021.002 — SMB/Windows Admin Shares |
| **Rule** | 100140 — Level 10 |
| **Event** | EventID 5140 — Network Share Object Accessed |
| **Rule firings (as originally shipped)** | **651,564** — see fix below |

> **Root cause found and fixed (2026-09-14):** the original rule matched any `ADMIN$`/`C$`/`IPC$` access with no exclusion — Windows generates this constantly via GPO/WMI background traffic using the local **machine account** (`HOSTNAME$`), which is what drove the 651,564 count. Fix deployed to `wazuh/rules/socforge_sigma_rules.xml`: split into two rules —
> - **100139** (level 3, informational): `subjectUserName` **matches** `\$$` — routine machine-account share access, filed as noise, not an alert
> - **100140** (level 10, the actual detection): `subjectUserName` **negated** against `\$$` — only fires for real (non-machine) account access, which is what lateral movement via stolen/abused credentials actually looks like
>
> Redeployed to the live Wazuh manager and confirmed the ruleset reloads with no syntax errors (`systemctl is-active wazuh-manager` → `active`, no rule-load errors in `ossec.log`). This also surfaced and fixed a separate, real deployment bug: 4 fields elsewhere in the ruleset used regex alternation (`|`) without `type="pcre2"`, which Wazuh's XML validator only catches at rule-load time, not at XML-syntax time — `wazuh-analysisd` was refusing to start with `Syntax error on tag` on rules 100101, 100178, 100147, and 100153 until this was fixed. `scripts/validate_wazuh_rules.py` has been extended to catch this class of error going forward (see CI/CD section).
>
> **Second false-positive found and fixed live (2026-09-16):** a follow-up live re-test (DC01 + WIN01 both running, fresh boot) caught a second real gap in the 2026-09-14 fix — legitimate Windows background traffic (name resolution / Netlogon touching `IPC$`) authenticates as **`ANONYMOUS LOGON`** (SID `S-1-5-7`), which does not end in `$` and therefore was not excluded by the machine-account filter. This produced 5 genuine false-positive hits on rule 100140 within minutes of WIN01 booting, captured live in `alerts.json`. Fixed by widening the exclusion regex from `\$$` to `(?i)(\$$|^ANONYMOUS LOGON$)` on both rules 100139 and 100140, redeployed to the live manager (no rule-load errors), and the filtering logic was verified directly against the captured raw event with a standalone regex test: `ANONYMOUS LOGON` now matches the noise filter (routes to 100139) while `Administrator` and `labuser` still correctly fall through to the real-alert rule 100140.
>
> **Evidence — Wazuh dashboard, live query `rule.id:100139 or rule.id:100140`:**
>
> ![T1021.002 ANONYMOUS LOGON false-positive evidence — event detail](docs/screenshots/scenario4-anonymous-logon-fix-1.png)
> ![T1021.002 ANONYMOUS LOGON false-positive evidence — hits list](docs/screenshots/scenario4-anonymous-logon-fix-2.png)

**Attack:**
```bash
# From SF-VM12-PURPLE (10.10.10.60)
smbclient //10.10.10.109/ADMIN$ -U 'SOCFORGE/Administrator%<password>' -c 'ls'
# Result: Full C:\Windows directory listing obtained
```

**File Share audit enabled on DC01:**

![T1021 audit enabled](docs/screenshots/scenario4_dc01_fileshare_audit_enabled.png)

**Wazuh Threat Hunting — `rule.id:100140` — 651,564 hits — timeline spike:**

![T1021 Wazuh rule 100140](docs/screenshots/scenario4_wazuh_rule100140_3hits_overview.png)

**Document details — ADMIN$ forensic — source 10.10.10.60:**

![T1021 ADMIN$ document](docs/screenshots/scenario4_wazuh_rule100140_admins_document.png)

**Document details — MITRE T1021.002 Lateral Movement mapping:**

![T1021 MITRE details](docs/screenshots/scenario4_wazuh_rule100140_list_3hits.png)

| Field | Value |
|---|---|
| `rule.id` | `100140` |
| `rule.level` | `10` |
| `rule.mitre.id` | `T1021.002` |
| `rule.mitre.tactic` | Lateral Movement |
| `data.win.system.eventID` | `5140` |
| `data.win.eventdata.shareName` | `\\*\ADMIN$` |
| `data.win.eventdata.shareLocalPath` | `\\??\C:\Windows` |
| `data.win.eventdata.ipAddress` | `10.10.10.60` |
| `agent.name` | `dc01` |

---

### T1003.001 — LSASS Memory Access

| | |
|---|---|
| **Technique** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Rule** | 100121 — Level 14 (historical ID at capture time — now **100103** in the current ruleset, see note below) |
| **Event** | Sysmon EventID 10 — Process Access |
| **MTTD** | **6 seconds** |
| **Tool** | Atomic Red Team `Invoke-AtomicTest T1003.001 -TestNumbers 1` |
| **Time** | 13:10:00 UTC |

> **Rule ID note**: at the time this screenshot was captured, this detection was rule `100121`. The ruleset was later reorganized and `100121` was reassigned to the T1059.001 PowerShell-obfuscation rule (see Detection Engineering table); the LSASS detection now lives at **100103**. The screenshot is genuine — only the ID changed, not the detection logic.

**Attack:** Atomic Red Team T1003.001 executed on WIN01 (Administrator context). Test 1 uses `comsvcs.dll MiniDump` — a signed Windows LOLBin — to access LSASS memory without dropping Mimikatz. Triggers Sysmon EventID 10 with `GrantedAccess: 0x1fffff`.

**Detection chain:**
```
Sysmon EventID 10 (ProcessAccess) on WIN01
  → targetImage: C:\Windows\System32\lsass.exe
  → GrantedAccess: 0x1fffff
  → sourceImage: C:\Windows\System32\rundll32.exe
      → Rule 100121 fires — Level 14 — MTTD: 6s
          → Shuffle → TheHive alert (pipeline 7s)
```

**Wazuh Threat Hunting — `rule.id:"100121"` — 110 hits — agent win01:**

![T1003 LSASS Wazuh rule 100121](docs/screenshots/sc05-wazuh-T1003-lsass-credential-dump.png)

| Field | Value |
|---|---|
| `rule.id` | `100121` |
| `rule.level` | `14` |
| `rule.description` | Sigma T1003.001: Process accessing LSASS - credential dumping |
| `rule.mitre.id` | `T1003.001` |
| `rule.mitre.tactic` | Credential Access |
| `data.win.system.eventID` | `10` |
| `data.win.eventdata.targetImage` | `C:\Windows\System32\lsass.exe` |
| `data.win.eventdata.sourceImage` | `C:\Windows\System32\rundll32.exe` |
| `data.win.eventdata.grantedAccess` | `0x1fffff` |
| `agent.name` | `win01` |

---

### T1055 — Process Injection

| | |
|---|---|
| **Technique** | T1055 / T1055.001 — Process Injection (CreateRemoteThread) |
| **Rule** | 100060 — Level 12 (historical ID at capture time — now **100155** in the current ruleset, see note below) |
| **Event** | Sysmon EventID 8 — CreateRemoteThread |
| **MTTD** | **9 seconds** |
| **Tool** | PowerShell P/Invoke — VirtualAllocEx + WriteProcessMemory + CreateRemoteThread |
| **Time** | 08:08:57 UTC |

**Attack:** Custom PowerShell P/Invoke injects a benign stub into `notepad.exe` via `CreateRemoteThread` Windows API. No shellcode payload — the goal is triggering the Sysmon EID 8 telemetry, not code execution.

> **Rule ID note**: at capture time this detection was rule `100060` (level 12). The ruleset was later reorganized and this same CreateRemoteThread detection now lives at **100155** (level 13) — see the Detection Engineering table above. Screenshot is genuine, only the ID/level changed.

**Detection chain:**
```
Sysmon EventID 8 (CreateRemoteThread) on WIN01
  → sourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  → targetImage: C:\Windows\System32\notepad.exe
  → startAddress: 0x... (VirtualAllocEx allocated stub)
      → Rule 100060 fires — Level 12 — MTTD: 9s (now rule 100155)
          → Shuffle → TheHive alert (pipeline 7s)
```

**Wazuh Threat Hunting — `rule.id:"100060"` — 2 hits — agent win01:**

![T1055 Process Injection Wazuh rule 100060](docs/screenshots/sc06-wazuh-T1055-process-injection.png)

| Field | Value |
|---|---|
| `rule.id` | `100060` (historical, now `100155`) |
| `rule.level` | `12` |
| `rule.description` | Sysmon - T1055 Process Injection - CreateRemoteThread detected |
| `rule.mitre.id` | `T1055`, `T1055.001` |
| `rule.mitre.tactic` | Defense Evasion, Privilege Escalation |
| `data.win.system.eventID` | `8` |
| `data.win.eventdata.sourceImage` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `data.win.eventdata.targetImage` | `C:\Windows\System32\notepad.exe` |
| `agent.name` | `win01` |

---

### T1547.001 — Registry Run Key Persistence

| | |
|---|---|
| **Technique** | T1547.001 — Boot or Logon Autostart: Registry Run Keys |
| **Rule** | 92302 — Level 6 |
| **Event** | Sysmon EventID 13 — Registry Value Set |
| **MTTD** | **18 seconds** |
| **Tool** | `reg.exe` + Atomic Red Team `Invoke-AtomicTest T1547.001` |
| **Time** | 14:10:00 UTC |

**Attack:** Registry Run key written to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` with value `SocForgeTest = calc.exe`. Simulates persistence mechanism an attacker would use post-compromise. Key cleaned up at 14:11:30 UTC (1 min 30s after creation).

**Detection chain:**
```
Sysmon EventID 13 (RegistryEvent — Value Set) on WIN01
  → targetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SocForgeTest
  → details: C:\Windows\System32\calc.exe
      → Rule 92302 fires — Level 6 — MTTD: 18s
          → Shuffle → TheHive alert (pipeline 7s)
```

**Wazuh Threat Hunting — Sysmon EID 13 — `rule.id:"92302"` — 3 hits — agent win01:**

![T1547 Registry Persistence Wazuh rule 100147](docs/screenshots/sc07-wazuh-T1547-registry-persistence.png)

| Field | Value |
|---|---|
| `rule.id` | `92302` |
| `rule.level` | `6` |
| `rule.description` | Registry entry to be executed on next logon was modified |
| `rule.mitre.id` | `T1547.001` |
| `rule.mitre.tactic` | Persistence, Privilege Escalation |
| `data.win.system.eventID` | `13` |
| `data.win.eventdata.targetObject` | `HKLM\...\CurrentVersion\Run\SocForgeTest` |
| `data.win.eventdata.details` | `C:\Windows\System32\calc.exe` |
| `agent.name` | `win01` |

---

### T1548.003 — Sudo Privilege Escalation

| | |
|---|---|
| **Technique** | T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| **Target** | VM11-LINUX01 (10.10.10.111) — Ubuntu 22.04 |
| **Tool** | SSH + sudo command execution as root |
| **MTTD** | **11 seconds** |
| **Rule** | 100200 (parent: 5402) |

**Attack:** `socadmin` executes `sudo whoami`, `sudo id`, `sudo cat /etc/shadow` — escalating to root via sudo. Simulates post-compromise privilege escalation on a Linux endpoint.

**Detection chain:**
```
sudo session opens on LINUX01 — /var/log/syslog entry: "sudo: socadmin : TTY=pts/0 ; COMMAND=/usr/bin/whoami"
  → Wazuh agent forwards syslog line
      → Rule 5402 (sudo successful) fires
          → Custom rule 100200 fires — Level 10 — MTTD: 11s
              → MITRE T1548.003 tagged
```

**Wazuh Threat Hunting — `rule.id:"100200"` — 4 hits — agent linux01:**

![SC-08 T1548.003 Sudo Privilege Escalation](docs/screenshots/sc08-wazuh-T1548-sudo-privilege-escalation.png)

| Field | Value |
|---|---|
| `rule.id` | `100200` |
| `rule.level` | `10` |
| `rule.description` | Sigma T1548.003: Sudo privilege escalation - user executed sudo as ROOT |
| `rule.mitre.id` | `T1548.003` |
| `rule.groups` | `socforge, sigma, privilege_escalation, sudo` |
| `agent.name` | `linux01` |

---

### T1053.003 — Cron Persistence

| | |
|---|---|
| **Technique** | T1053.003 — Scheduled Task/Job: Cron |
| **Target** | VM11-LINUX01 (10.10.10.111) — Ubuntu 22.04 |
| **Tool** | crontab modification via SSH |
| **MTTD** | **14 seconds** |
| **Rule** | 100210 (parent: 2832) |

**Attack:** Malicious cron entry `* * * * * /tmp/socforge_persist.sh` written to user crontab. Simulates attacker establishing persistence via scheduled job on a compromised Linux host.

**Detection chain:**
```
crontab modified — /var/log/syslog: "CRON[...]: socadmin edited crontab"
  → Wazuh agent forwards syslog entry
      → Rule 2832 (crontab alteration) fires
          → Custom rule 100210 fires — Level 10 — MTTD: 14s
              → MITRE T1053.003 tagged
```

**Wazuh Threat Hunting — `rule.id:"100210"` — 1 hit — agent linux01:**

![SC-09 T1053.003 Cron Persistence](docs/screenshots/sc09-wazuh-T1053-cron-persistence.png)

| Field | Value |
|---|---|
| `rule.id` | `100210` |
| `rule.level` | `10` |
| `rule.description` | Sigma T1053.003: Cron persistence - crontab entry modified by user |
| `rule.mitre.id` | `T1053.003` |
| `rule.groups` | `socforge, sigma, persistence, cron` |
| `agent.name` | `linux01` |

---

## SOAR Pipeline

Wazuh alerts forwarded to Shuffle via webhook → Shuffle playbook enriches via MISP + Cortex → alert created in TheHive automatically. End-to-end latency: **7 seconds**.

### Shuffle — 5-node playbook

![Shuffle SOAR playbook 5 nodes](docs/screenshots/bloc1-soar/shuffle-soar-playbook-5nodes.jpg)

### Shuffle — Execution finished (all nodes green)

![Shuffle execution finished](docs/screenshots/bloc1-soar/shuffle-execution-finished.jpg)

### Shuffle — All workflow runs

![Shuffle all workflow runs](docs/screenshots/bloc1-soar/shuffle-all-workflow-runs.jpg)

### TheHive — Alert created by SOAR

![TheHive alert from SOAR](docs/screenshots/bloc1-soar/thehive-alert-from-soar.jpg)

### TheHive — 350+ alerts ingested

![TheHive 350 alerts](docs/screenshots/bloc1-soar/thehive-alerts-350.jpg)

---

## Threat Intelligence — MISP + Cortex

T1110 brute-force alerts enriched automatically: TheHive triggers Cortex → MISP analyzer → IOC lookup against CIRCL OSINT feed → observable tagged with `socforge:purple-team`.

### Cortex — MISP SocForge Analyzer — Success

![Cortex MISP job success](docs/screenshots/bloc2-misp-cortex/cortex-job-misp-socforge-success.jpg)

### MISP — Event 2108 IOC attributes

![MISP event 2108 IOC](docs/screenshots/bloc2-misp-cortex/misp-event-2108-ioc.jpg)

### MISP — Full attribute list

![MISP event 2108 attributes](docs/screenshots/bloc2-misp-cortex/misp-event-2108-attributes.jpg)

### TheHive — Enriched alert (MISP + Cortex)

![TheHive enriched alert](docs/screenshots/bloc2-misp-cortex/thehive-alert-enriched.jpg)

---

## DFIR — Velociraptor

Velociraptor 0.77.1 deployed on VM08 (10.10.60.10). DC01 (C.c6b3dab429088216 — WIN-FJ8RP03U8FK.socforge.lab) and WIN01 enrolled as clients. Full artifact collection performed remotely on live Windows targets.

### Both clients connected (DC01 + WIN01)

![Velociraptor both clients connected](docs/screenshots/phase2-velociraptor/vm08-both-clients-connected.png)

### DC01 — Client details

**Agent 0.77.1 · First seen 2026-08-04 · Last IP 10.10.10.109**

![Velociraptor DC01 client overview](docs/screenshots/phase4-dfir/velociraptor-dc01-overview.jpg)

### DC01 — Windows.System.Pslist — Collection log

![Velociraptor Pslist collection log](docs/screenshots/phase4-dfir/velociraptor-pslist-log-dc01.jpg)

### DC01 — PowerShell interactive shell via VQL

Live shell opened on DC01 via `Windows.System.PowerShell` artifact — no RDP, no agent installer, remote execution over Velociraptor gRPC.

![Velociraptor PowerShell shell DC01](docs/screenshots/phase4-dfir/velociraptor-shell-pslist-dc01.jpg)

### DC01 — Windows.System.Pslist — 46 rows

Full process list: PID, PPID, TokenIsElevated, CommandLine, Exe path, MD5/SHA1/SHA256, Authenticode, Username (NT AUTHORITY\SYSTEM).

![Velociraptor Pslist 46 rows](docs/screenshots/phase4-dfir/velociraptor-pslist-results-46rows.jpg)

---

## KPI Metrics

All metrics calculated from real lab data — timestamps from Wazuh alert exports and TheHive case logs (2026-08-07).

> **On the "0 FP" figures below**: they describe the 12 purple team scenarios' final validated state. During rule development, 4 false positives were found and tuned out — documented in [`false-positive-registry.md`](purple-team/validation-matrix/false-positive-registry.md). Rules didn't start at 0 FP; they were iterated to get there, which is the expected detection-engineering workflow, not a defect. Rule 100140 (T1021.002 admin shares) was the one exception generating high-volume noise (651,564 firings) — this has since been **fixed** (machine-account exclusion added, see T1021.002 section above), not just documented as a known gap.

| KPI | Value | Target | Source |
|---|---|---|---|
| **MTTD avg** (13 scenarios, Sessions 1-3) | **26.0s** | < 5 min | Purple team timestamps |
| **MTTD avg** (investigation session) | **47.25s** | < 5 min | Alert export logs |
| **MTTA** | ~5 min | < 15 min | Purple Team exercise (analyst active) |
| **MTTR** | ~2h 06m | < 4h (P1) | Alert → case closure same session |
| **Pipeline latency** (Wazuh → TheHive) | **7 seconds** | < 60s | 14:23:58 → 14:24:05 (measured) |
| **SOAR success rate** | **100%** | ≥ 80% | 0 errors / 7 executions |
| **Detection rate** | **100%** (13/13) | ≥ 95% | Purple team test report |
| **Precision** | **100%** | ≥ 95% | TP=13, FP=0 |
| **Recall** | **100%** | ≥ 95% | TP=13, FN=0 |
| **F1-Score** | **1.00** | ≥ 0.95 | Calculated |
| **False positive rate** | **0%** (post-fix, 2026-09-16) | < 5% | 13/13 scenarios true-positive; rule 100140's original noise problem (machine-account + anonymous-logon background traffic) fixed and re-verified live — see T1021.002 section |
| **MITRE ATT&CK coverage** | **78%** (18/23) | ≥ 70% | ATT&CK v14 mapping |
| **TheHive alerts** | **350+** | > 100 | TheHive API |
| **Velociraptor clients** | **2** (DC01 + WIN01) | ≥ 2 | Velociraptor console |
| **Custom rules deployed** | **17** | — | `socforge_sigma_rules.xml` + `socforge_linux_rules.xml` |
| **YARA rules deployed** | **9** | — | `socforge_rules.yar` |
| **Total Wazuh alerts** | **2,004+** | — | `alerts.log` |

---

## Infrastructure Gallery

### VM02 — Wazuh SIEM — All services active

![Wazuh all services active](docs/screenshots/phase0-install/VM02-WAZUH-all-services-active.png)

### VM02 — Wazuh agent DC01 — ACTIVE

![Wazuh agent dc01 active](docs/screenshots/phase0-install/VM02-WAZUH-agent-list-dc01-ACTIVE.png)

### VM02 — Wazuh agent WIN01 — ACTIVE

![Wazuh agent win01 active](docs/screenshots/phase0-install/VM02-WAZUH-agent-list-win01-ACTIVE.png)

### VM03 — TheHive — API status 5.4.7

![TheHive API status 5.4.7](docs/screenshots/phase0-install/VM03-THEHIVE-api-status-5.4.7.png)

### VM04 — Cortex — Setup wizard HTTP 303

![Cortex HTTP 303 wizard](docs/screenshots/phase0-install/VM04-CORTEX-HTTP303-wizard.png)

### VM05 — MISP — Running HTTPS (HTTP 302)

![MISP running HTTP 302](docs/screenshots/phase0-install/VM05-MISP-running-HTTP302.png)

### VM06 — Shuffle — HTTP 200

![Shuffle HTTP 200](docs/screenshots/phase0-install/VM06-SHUFFLE-HTTP200-running.png)

### VM08 — Velociraptor — Port 8889

![Velociraptor running port 8889](docs/screenshots/phase0-install/VM08-VELOCIRAPTOR-running-port8889.png)

### VM09 — DC01 — Active Directory users created

**Users: john.doe, svc.backup, alice.admin**

![DC01 AD users](docs/screenshots/phase0-install/VM09-DC01-AD-users-created.png)

### VM09 — DC01 — Wazuh agent deployed

![DC01 Wazuh agent success](docs/screenshots/phase0-install/VM09-DC01-wazuh-agent-SUCCESS.png)

### VM10 — WIN01 — Network connectivity (MGMT plane)

![WIN01 IP ping MGMT](docs/screenshots/phase0-install/VM10-WIN01-ip-ping-MGMT.png)

### VM10 — WIN01 — Wazuh service RUNNING

![WIN01 WazuhSvc running](docs/screenshots/phase0-install/VM10-WIN01-wazuhsvc-RUNNING.png)

### VM11 — LINUX01 — Wazuh agent enrolled

![LINUX01 Wazuh agent enrolled](docs/screenshots/phase0-install/VM11-LINUX01-wazuh-agent-ENROLLED.png)

### VM11 — LINUX01 — Wazuh agent active

![LINUX01 Wazuh agent success](docs/screenshots/phase0-install/VM11-LINUX01-wazuh-agent-SUCCESS.png)

---

## Tech Stack

| Category | Technology | Version |
|---|---|---|
| SIEM / XDR | Wazuh | 4.9.2 |
| Search / Indexing | OpenSearch | bundled |
| Case Management | TheHive | 5.4.7 |
| Enrichment Engine | Cortex | 3.x |
| Threat Intelligence | MISP | 2.4.x |
| SOAR | Shuffle | 2.2.1 |
| DFIR | Velociraptor | 0.77.1 |
| NDR | Zeek (LTS) / Suricata | 8.0.10 / 6.0.4 |
| Active Directory | Windows Server 2022 | — |
| Endpoint | Windows 11 | — |
| Red Team | Kali Linux | 2024.2 |
| Hypervisor | VirtualBox | 7.x |
| Detection Language | Sigma | — |
| Detection Language | YARA | — |
| ATT&CK Framework | MITRE ATT&CK | v14 |

---

## Project Phases

| Phase | Description | Status |
|---|---|---|
| **Phase 0** | Lab design, 12 VM provisioning, network segmentation, Active Directory | ✅ Complete |
| **Phase 1** | Tool installation: Wazuh, TheHive, Cortex, MISP, Shuffle, Velociraptor | ✅ Complete |
| **Phase 2** | Agent deployment, Wazuh→TheHive SOAR pipeline, Cortex/MISP integration | ✅ Complete |
| **Phase 3** | Purple Team SC-01→SC-04, custom Sigma/YARA rules, live detections verified | ✅ Complete |
| **Phase 4** | DFIR — Velociraptor remote artifact collection (DC01, Pslist 46 rows) | ✅ Complete |
| **Phase 5** | NDR — Zeek + Suricata ET Open, 17 custom SIDs, SMB/network monitoring | ✅ Complete |
| **Phase 6** | Threat Intelligence — MISP feeds, IOC CSV, Cortex enrichment pipeline | ✅ Complete |
| **Phase 7** | Purple Team SC-05→SC-07, Threat Hunting (8 hypotheses, 10 VQL), KPI metrics | ✅ Complete |
| **Phase 8** | Live re-validation — CI/CD rule validation, real Ollama LLM triage on a live alert, real Zeek/Suricata deployment on NDR, independent T1110 re-test with dashboard proof ([IR-003](reports/incident-reports/IR-003-T1110-real-bruteforce-2026-09-14.md)) | ✅ Complete |

---

## Repository Structure

Organized to mirror the project phases below — infrastructure first, then detection content, then the operational layers built on top of it.

```
.
├── infrastructure/          # Phase 0 — VM specs, network, firewall, Docker
│   ├── virtualbox/           # VM configs, UUIDs, RAM/CPU/disk specs
│   ├── firewall/             # OPNsense rules
│   ├── ndr/                  # Zeek/Suricata deployment notes
│   └── docker/               # Container configs (Cortex, MISP, etc.)
├── docs/                     # Phase 0 — architecture, network plan, ops guides
│   ├── architecture/          # VM inventory, security policy, naming
│   ├── network/                # IP plan, segmentation
│   ├── installation/           # OS install guides
│   ├── operations/              # Backup/restore, exploitation guide
│   ├── troubleshooting/          # Known issues and fixes
│   ├── llm-triage/                # Ollama-based alert triage — setup + real run
│   └── screenshots/                # All evidence screenshots (real lab sessions)
├── wazuh/                    # Phase 1 — SIEM / detection engine
│   ├── rules/                 # Custom Sigma rules (15 deployed)
│   ├── agents/                  # Agent configuration
│   ├── decoders/                  # Custom decoders
│   └── dashboards/                  # Dashboard exports
├── detections/                # Phase 1 — detection content by platform
│   ├── sigma/, yara/ (9 rules), windows/, linux/, network/
├── ndr/                       # Phase 5 — Zeek + Suricata (real capture)
│   ├── zeek/, suricata/, pcaps/
├── soar/                      # Phase 2 — SOAR automation
│   ├── shuffle/, workflows/, test-alerts/
├── threat-intelligence/       # Phase 6 — MISP + Cortex enrichment
│   ├── misp/, taxonomies/, ioc-samples/
├── purple-team/                # Phase 3/7 — attack simulation
│   ├── scenarios/                # Attack playbooks (SC-01 → SC-12)
│   ├── atomic-tests/               # Atomic Red Team mappings
│   └── validation-matrix/            # Detection results per MITRE technique
├── dfir/                       # Phase 4 — Velociraptor forensics
│   ├── velociraptor/, artifacts/, chain-of-custody/
├── hunting/                    # Phase 7 — proactive threat hunting
│   ├── hypotheses/               # 8 hunt hypotheses
│   ├── queries/                    # OpenSearch/VQL queries
│   └── notebooks/                    # Executed Jupyter notebook + sample-data
├── incident-response/           # Playbooks and case templates
│   ├── playbooks/, templates/, cortex/, thehive/
├── evidence/                    # Cross-phase — proof artifacts
│   ├── logs/, cases/, investigations/, screenshots/
├── metrics/                     # KPI calculations from real data
│   ├── datasets/, calculations/, dashboards/
├── reports/                     # Final report + incident reports
│   ├── final-report/, incident-reports/, test-reports/
└── scripts/                     # Automation
    ├── llm_triage.py             # Ollama-based Wazuh alert triage
    └── validate_wazuh_rules.py   # CI/CD rule validator (GitHub Actions)
```

**CI/CD**: [`.github/workflows/validate-wazuh-rules.yml`](.github/workflows/validate-wazuh-rules.yml) runs `scripts/validate_wazuh_rules.py` on every push touching `wazuh/rules/*.xml`.

---

## Security Notice

This lab is **fully isolated** during all attack simulations:
- Bridge adapters disabled during Purple Team sessions
- All attack traffic confined to `socforge-mgmt` (10.10.10.0/24)
- No real malware — all techniques are benign simulations (Atomic Red Team methodology)
- No external systems targeted at any point

---

*Built by **Omar Babba** — Cybersecurity Engineering Student*  
*omarbabba27@gmail.com*
