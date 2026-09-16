# SocForge — Configuration des Tests Atomic Red Team

**VM Attaquant**: VM12-PURPLE (10.10.10.60) et WIN01 (10.10.10.110)
**Framework**: Atomic Red Team v4.x (Invoke-AtomicRedTeam)
**Prérequis**: PowerShell 5.1+, droits Administrator

---

## Installation Atomic Red Team (WIN01)

```powershell
# Depuis WIN01 — PowerShell Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force

# Install IEx Invoke-AtomicRedTeam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

# Installer les atomics
Install-AtomicRedTeam -getAtomics -Force
```

---

## Tests configurés par technique

### T1059.001 — PowerShell Execution

```powershell
# Test 1: PowerShell encodé (Base64)
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Test 2: Téléchargement de payload (simulation — URL lab uniquement)
Invoke-AtomicTest T1059.001 -TestNumbers 2

# Nettoyage
Invoke-AtomicTest T1059.001 -Cleanup
```

**Règle Wazuh attendue**: 100131 (niveau 12)
**EventID Sysmon**: 1 (Process Create), 3 (Network Connect)

---

### T1110 — Brute Force (Hydra depuis VM12-PURPLE)

```bash
# Depuis VM12-PURPLE Kali (10.10.10.60)
# Cible autorisée: DC01 (10.10.10.109)

# RDP brute force
hydra -L /usr/share/wordlists/rockyou.txt \
      -P /usr/share/wordlists/rockyou.txt \
      -t 4 rdp://10.10.10.109 \
      -V -f -o /tmp/hydra-rdp.log

# SMB brute force
hydra -l administrator \
      -P /usr/share/wordlists/rockyou.txt \
      smb://10.10.10.109
```

**Règle Wazuh attendue**: 100110 (niveau 10)
**EventID Windows**: 4625 (Logon Failure)

---

### T1046 — Network Service Discovery (nmap depuis VM12)

```bash
# Depuis VM12-PURPLE
nmap -sV -p 22,80,443,445,3389,8080,8443 10.10.10.0/24 -oN /tmp/nmap-lab.txt

# SYN scan (plus furtif)
nmap -sS -T4 10.10.10.109 -oX /tmp/nmap-dc01.xml
```

**Règle Wazuh attendue**: 100102 (niveau 10)
**Détection Zeek**: `notice.log` + Suricata SID 9100001

---

### T1021.002 — SMB Lateral Movement

```powershell
# Depuis WIN01 vers DC01
net use \\10.10.10.109\C$ /user:SOCFORGE\administrator Password1

# Via PowerShell
$cred = Get-Credential  # SOCFORGE\administrator
New-PSDrive -Name Z -PSProvider FileSystem -Root \\10.10.10.109\ADMIN$ -Credential $cred

# Nettoyage
net use \\10.10.10.109\C$ /delete
Remove-PSDrive Z
```

**Règle Wazuh attendue**: 100140 (niveau 10)
**EventID Windows**: 5140 (Network Share Object Accessed), 4624 Type 3

---

### T1003 — Credential Dumping (Mimikatz-like via Atomic)

```powershell
# Test safe — pas de vraie exfiltration, déclenche seulement les EventIDs
Invoke-AtomicTest T1003.001 -TestNumbers 1
# EventID 10 Sysmon: TargetImage = lsass.exe

# Procédure d'urgence: nettoyer immédiatement après le test
Invoke-AtomicTest T1003.001 -Cleanup
```

**Règle Wazuh attendue**: 100103 (niveau 14)
**EventID Sysmon**: 10 (ProcessAccess — LSASS)

---

### T1547.001 — Registry Run Key Persistence

```powershell
# Test contrôlé — clé de test inoffensive
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run `
    /v SocForgeTest /t REG_SZ /d "C:\Windows\System32\calc.exe" /f

Invoke-AtomicTest T1547.001 -TestNumbers 1,2

# Nettoyage
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SocForgeTest" -ErrorAction SilentlyContinue
Invoke-AtomicTest T1547.001 -Cleanup
```

**Règle Wazuh attendue**: 100147 (niveau 9)
**EventID Sysmon**: 13 (Registry Value Set)

---

### T1055 — Process Injection

```powershell
Invoke-AtomicTest T1055 -TestNumbers 1
# Déclenche EventID 8 Sysmon: CreateRemoteThread

Invoke-AtomicTest T1055 -Cleanup
Stop-Process -Name notepad -ErrorAction SilentlyContinue
```

**Règle Wazuh attendue**: 100155 (niveau 13)
**EventID Sysmon**: 8 (CreateRemoteThread)

---

## Matrice d'exécution des tests

| Technique  | TestNum | VM Source      | VM Cible  | Durée | Reset |
|------------|---------|----------------|-----------|-------|-------|
| T1059.001  | 1,2     | WIN01          | WIN01     | ~2min | Auto  |
| T1110      | -       | VM12-PURPLE    | DC01      | ~5min | Auto  |
| T1046      | -       | VM12-PURPLE    | Réseau    | ~3min | N/A   |
| T1021.002  | 1       | WIN01          | DC01      | ~2min | Manuel|
| T1003.001  | 1       | WIN01          | WIN01     | ~1min | Auto  |
| T1547.001  | 1,2     | WIN01          | WIN01     | ~1min | Auto  |
| T1055      | 1       | WIN01          | WIN01     | ~2min | Auto  |

---

## Contraintes de sécurité (IMPÉRATIVES)

- VM12-PURPLE ne peut cibler que DC01 (10.10.10.109) et WIN01 (10.10.10.110)
- Interdiction totale de cibler des systèmes externes
- Mode Bridge INTERDIT sur VM12-PURPLE
- Toujours exécuter le `Cleanup` après chaque test
- Ne pas utiliser de vraies credentials prod
- Pas de malware réel — uniquement les payloads Atomic (benignes)
