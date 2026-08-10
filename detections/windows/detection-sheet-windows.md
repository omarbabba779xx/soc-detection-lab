# Fiche de Détection — Windows (DC01 + WIN01)

## Sources de logs collectés

| Source                            | Canal EventLog                                    | EventIDs clés                                    |
|-----------------------------------|--------------------------------------------------|--------------------------------------------------|
| Windows Security                  | Security                                          | 4624, 4625, 4634, 4648, 4688, 4698, 4720-4726, 5140 |
| PowerShell Script Block           | Microsoft-Windows-PowerShell/Operational          | 4103, 4104, 4105, 4106                          |
| Sysmon                            | Microsoft-Windows-Sysmon/Operational              | 1,2,3,5,7,8,10,11,12-14,15,17-18,22             |
| Windows Defender                  | Microsoft-Windows-Windows Defender/Operational    | 1116, 1117, 1006, 1007                          |

---

## Techniques détectées

### T1046 — Network Service Discovery
- **Source**: Sysmon EventID 3
- **Règle Wazuh**: 100101, 100102
- **Sigma**: `T1046-network-service-discovery.yml`
- **Indicateurs**: Connexions réseau vers multiples ports depuis un même processus
- **Seuil**: >10 connexions différentes en 5 minutes depuis un seul exécutable
- **Faux positifs**: Zabbix, Nagios, PRTG, outils IT

### T1059.001 — PowerShell Execution
- **Source**: EventID 4688, 4104, Sysmon-1
- **Règle Wazuh**: 100120, 100121, 100131
- **Sigma**: `T1059.001-powershell-execution.yml`
- **Indicateurs**: `-enc`, `-EncodedCommand`, `IEX`, `DownloadString`, `-bypass`
- **Faux positifs**: Scripts d'admin légitimes utilisant des paramètres encodés

### T1110 — Brute Force
- **Source**: EventID 4625
- **Règle Wazuh**: 100110, 100111 (60122 natif Wazuh)
- **Sigma**: `T1110-brute-force.yml`
- **Indicateurs**: >5 échecs sur le même compte en 60 secondes
- **Faux positifs**: Mots de passe expirés, comptes de service

### T1021.002 — SMB Admin Shares
- **Source**: EventID 5140
- **Règle Wazuh**: 100140
- **Sigma**: `T1021.002-smb-admin-shares.yml`
- **Indicateurs**: Accès à `ADMIN$`, `C$`, `IPC$` depuis une IP externe
- **Faux positifs**: Administration légale, agents de backup

### T1003 — Credential Dumping
- **Source**: Sysmon EventID 10
- **Règle Wazuh**: 100103
- **Sigma**: `T1003-credential-dumping.yml`
- **Indicateurs**: Accès mémoire LSASS avec `GrantedAccess` 0x1010/0x1410
- **Faux positifs**: Outils AV/EDR (MsMpEng, SentinelOne)

### T1547.001 — Registry Run Keys
- **Source**: Sysmon EventID 13/14
- **Règle Wazuh**: 100147
- **Sigma**: `T1547-autostart-persistence.yml`
- **Indicateurs**: Modification des clés `CurrentVersion\Run`, `Winlogon`
- **Faux positifs**: Installateurs logiciels légitimes

### T1053.005 — Scheduled Task
- **Source**: EventID 4698, 4702
- **Règle Wazuh**: 100153
- **Sigma**: `T1053-scheduled-task.yml`
- **Indicateurs**: Création de tâches en dehors de `\Microsoft\Windows\`
- **Faux positifs**: Logiciels installant des tâches planifiées

### T1055 — Process Injection
- **Source**: Sysmon EventID 8
- **Règle Wazuh**: 100155
- **Sigma**: `T1055-process-injection.yml`
- **Indicateurs**: `CreateRemoteThread` vers n'importe quel processus cible
- **Faux positifs**: AV/EDR injectant des threads de monitoring

---

## Niveaux de sévérité Wazuh

| Niveau | Description             | Règles                        |
|--------|-------------------------|-------------------------------|
| 14     | Critique                | 100103, 100131, 100155        |
| 12     | Élevé                   | 100121, 100131                |
| 10     | Moyen-élevé             | 100111, 100127, 100140        |
| 9      | Moyen                   | 100147, 100153, 100178        |
| 8      | Informationnel élevé    | 100101, 100120                |
| 6      | Informationnel          | 100110                        |
