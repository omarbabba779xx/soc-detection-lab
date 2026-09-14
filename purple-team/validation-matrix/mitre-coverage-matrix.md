# Matrice de Couverture MITRE ATT&CK — SocForge

**Périmètre**: Environnement lab local isolé, 12 VMs, Windows/Linux/Network

---

## Matrice de couverture par tactique

### TA0001 — Initial Access
| Technique   | Nom                         | Couverture | Règle        | Source       |
|-------------|----------------------------|------------|--------------|--------------|
| T1078       | Valid Accounts              | ✅ Complète  | 92037        | Win-4648/net.exe |
| T1190       | Exploit Public-Facing App   | ⚠️ NDR only  | Suricata ET  | VM07-NDR     |

### TA0002 — Execution
| Technique      | Nom                         | Couverture  | Règle           | Source              |
|----------------|-----------------------------|-------------|-----------------|---------------------|
| T1059.001      | PowerShell                  | ✅ Complète  | 100120, 100121, 100131 | Win-4688, 4104 |
| T1059.003      | Windows Command Shell       | ⚠️ Partielle | 100120 (cmd)    | Win-4688            |
| T1053.005      | Scheduled Task              | ✅ Complète  | 60642           | Win-4698/schtasks   |

### TA0003 — Persistence
| Technique      | Nom                         | Couverture  | Règle    | Source         |
|----------------|-----------------------------|-------------|----------|----------------|
| T1547.001      | Registry Run Keys           | ✅ Complète  | 92302    | Sysmon-13      |
| T1053.005      | Scheduled Task              | ✅ Complète  | 60642    | Win-4698/schtasks (SC-10)  |
| T1053.003      | Cron Job                    | ✅ Complète  | 100210   | VM11-LINUX01/syslog (SC-09) |
| T1546.013      | PowerShell Profile          | ✅ Complète  | 92004    | Win-4688/cmd.exe (SC-12)   |

### TA0004 — Privilege Escalation
| Technique      | Nom                         | Couverture  | Règle    | Source         |
|----------------|-----------------------------|-------------|----------|----------------|
| T1055          | Process Injection           | ✅ Complète  | 100155   | Sysmon-8       |
| T1548.003      | Sudo Abuse (Linux)          | ✅ Complète  | 100200   | VM11-LINUX01/syslog (SC-08) |
| T1078          | Valid Accounts              | ✅ Complète  | 92037    | Win-4648/net.exe (SC-11)   |

### TA0005 — Defense Evasion
| Technique      | Nom                         | Couverture  | Règle    | Source         |
|----------------|-----------------------------|-------------|----------|----------------|
| T1027          | Obfuscated Files            | ✅ Complète  | 100127   | Win-4688       |
| T1027.010      | Command Obfuscation         | ✅ Complète  | 100121   | PS-4104        |

### TA0006 — Credential Access
| Technique      | Nom                         | Couverture  | Règle           | Source         |
|----------------|-----------------------------|-------------|-----------------|----------------|
| T1003.001      | LSASS Memory Dump           | ✅ Complète  | 100103          | Sysmon-10      |
| T1110          | Brute Force                 | ✅ Complète  | 100110, 100111, 60122 | Win-4625 |
| T1110.001      | Password Guessing           | ✅ Complète  | 100111          | Win-4625       |

**Validation réelle (2026-09-14)** : test SMB/NTLM authentifié (`smbclient`, LINUX01 → DC01), 6 échecs réels détectés via règle 60122, MTTD < 1s. Voir [IR-003](../../reports/incident-reports/IR-003-T1110-real-bruteforce-2026-09-14.md). Limite observée : la règle de corrélation fréquence 100111 ne s'est pas déclenchée car les 6 tentatives sont arrivées en moins d'une seconde (plus rapide que la fenêtre d'agrégation) — seule la règle atomique 60122 s'est déclenchée à chaque tentative.

### TA0007 — Discovery
| Technique      | Nom                         | Couverture  | Règle           | Source         |
|----------------|-----------------------------|-------------|-----------------|----------------|
| T1046          | Network Service Discovery   | ✅ Complète  | 100101, 100102  | Sysmon-3       |
| T1082          | System Information Discov.  | ❌ Manquant  | —               | —              |
| T1083          | File and Directory Discov.  | ❌ Manquant  | —               | —              |

### TA0008 — Lateral Movement
| Technique      | Nom                         | Couverture  | Règle    | Source         |
|----------------|-----------------------------|-------------|----------|----------------|
| T1021.002      | SMB/Admin Shares            | ✅ Complète  | 100140   | Win-5140       |
| T1021.001      | RDP                         | ⚠️ Partielle | 60105    | Win-4624 type10 |

### TA0010 — Exfiltration
| Technique      | Nom                         | Couverture  | Règle          | Source         |
|----------------|-----------------------------|-------------|----------------|----------------|
| T1041          | Exfil Over C2 Channel       | ⚠️ NDR only  | Suricata/Zeek  | VM07-NDR       |

---

## Score de couverture global

| Tactique                  | Techniques couvertes | Total techniques lab | Couverture % |
|---------------------------|---------------------|----------------------|--------------|
| Initial Access            | 1                   | 2                    | 50%          |
| Execution                 | 2                   | 3                    | 67%          |
| Persistence               | 4                   | 4                    | 100%         |
| Privilege Escalation      | 3                   | 3                    | 100%         |
| Defense Evasion           | 2                   | 2                    | 100%         |
| Credential Access         | 3                   | 3                    | 100%         |
| Discovery                 | 1                   | 3                    | 33%          |
| Lateral Movement          | 2                   | 2                    | 100%         |
| Exfiltration              | 0                   | 1                    | 0%           |
| **TOTAL**                 | **18**              | **23**               | **78%**      |

---

## Légende

| Symbole | Signification                                          |
|---------|--------------------------------------------------------|
| ✅       | Détection active avec règle Wazuh validée             |
| ⚠️       | Couverture partielle (NDR seulement ou non testée)    |
| ❌       | Technique sans couverture (hors scope lab actuel)     |
