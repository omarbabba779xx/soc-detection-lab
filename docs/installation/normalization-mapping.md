# SocForge — Normalisation des champs de logs

## Objectif

Ce document décrit le mapping entre les champs bruts des sources de logs (Windows Event Log, Sysmon, auditd, OPNsense) et les champs normalisés utilisés dans Wazuh + OpenSearch.

---

## 1. Windows Security Events

| Champ brut (EventData)       | Champ Wazuh normalisé              | Description                  |
|------------------------------|------------------------------------|------------------------------|
| `TargetUserName`             | `data.win.eventdata.targetUserName`| Compte cible de l'opération  |
| `SubjectUserName`            | `data.win.eventdata.subjectUserName`| Compte initiant l'opération |
| `IpAddress`                  | `data.win.eventdata.ipAddress`     | IP source (logon/share)      |
| `WorkstationName`            | `data.win.eventdata.workstationName`| Poste source                |
| `LogonType`                  | `data.win.eventdata.logonType`     | Type de logon (2=interactif, 3=réseau) |
| `AuthenticationPackageName`  | `data.win.eventdata.authenticationPackageName` | NTLM / Kerberos  |
| `NewProcessName`             | `data.win.eventdata.newProcessName`| Chemin du nouveau processus  |
| `CommandLine`                | `data.win.eventdata.commandLine`   | Ligne de commande complète   |
| `ShareName`                  | `data.win.eventdata.shareName`     | Nom du partage réseau (5140) |
| `ObjectName`                 | `data.win.eventdata.objectName`    | Chemin de l'objet accédé     |
| `FailureReason`              | `data.win.eventdata.failureReason` | Raison échec d'authentification |
| `Status` / `SubStatus`       | `data.win.eventdata.status`        | Code d'erreur Kerberos/NTLM  |

---

## 2. Sysmon

| Champ brut Sysmon            | Champ Wazuh normalisé              | EventID concerné             |
|------------------------------|------------------------------------|------------------------------|
| `Image`                      | `data.win.eventdata.image`         | 1, 5, 7, 8, 10              |
| `CommandLine`                | `data.win.eventdata.commandLine`   | 1                            |
| `ParentImage`                | `data.win.eventdata.parentImage`   | 1                            |
| `ParentCommandLine`          | `data.win.eventdata.parentCommandLine` | 1                        |
| `Hashes`                     | `data.win.eventdata.hashes`        | 1, 7, 15                    |
| `DestinationIp`              | `data.win.eventdata.destinationIp` | 3                            |
| `DestinationPort`            | `data.win.eventdata.destinationPort` | 3                          |
| `TargetImage`                | `data.win.eventdata.targetImage`   | 8, 10                        |
| `GrantedAccess`              | `data.win.eventdata.grantedAccess` | 10 (ProcessAccess)          |
| `TargetFilename`             | `data.win.eventdata.targetFilename`| 11, 15                       |
| `TargetObject`               | `data.win.eventdata.targetObject`  | 12, 13, 14 (Registry)       |
| `QueryName`                  | `data.win.eventdata.queryName`     | 22 (DNS)                     |

---

## 3. auditd (Linux)

| Champ brut auditd            | Champ Wazuh normalisé              | Description                  |
|------------------------------|------------------------------------|------------------------------|
| `key`                        | `data.audit.key`                   | Clé de règle auditd          |
| `auid`                       | `data.audit.auid`                  | UID de l'utilisateur réel    |
| `uid` / `euid`               | `data.audit.uid`                   | UID effectif                 |
| `pid`                        | `data.audit.pid`                   | PID du processus             |
| `exe`                        | `data.audit.exe`                   | Chemin de l'exécutable       |
| `comm`                       | `data.audit.command`               | Nom de la commande           |
| `syscall`                    | `data.audit.syscall`               | Numéro d'appel système       |
| `type`                       | `data.audit.type`                  | Type d'événement (SYSCALL, PATH, EXECVE…) |
| `name`                       | `data.audit.file.name`             | Chemin du fichier surveillé  |
| `addr`                       | `data.audit.addr`                  | Adresse IP (SOCKADDR)        |

---

## 4. OPNsense Firewall

| Champ brut filterlog         | Champ Wazuh normalisé              | Description                  |
|------------------------------|------------------------------------|------------------------------|
| `rule_number`                | `data.firewall.rule_number`        | Numéro de règle PF           |
| `interface`                  | `data.firewall.interface`          | Interface réseau (em0, vtnet0)|
| `reason`                     | `data.firewall.reason`             | match / bad-offset / fragment |
| `action`                     | `data.firewall.action`             | pass / block                 |
| `direction`                  | `data.firewall.direction`          | in / out                     |
| `ip_version`                 | `data.firewall.ip_version`         | 4 / 6                        |
| `src_ip`                     | `data.src_ip`                      | IP source (normalisé Wazuh)  |
| `dst_ip`                     | `data.dst_ip`                      | IP destination               |
| `src_port`                   | `data.src_port`                    | Port source                  |
| `dst_port`                   | `data.dst_port`                    | Port destination             |
| `protocol`                   | `data.protocol`                    | tcp / udp / icmp             |

---

## 5. Règles de corrélation Wazuh

| `rule.id` | Source       | Technique MITRE  | Champs clés utilisés                          |
|-----------|--------------|------------------|-----------------------------------------------|
| 100101    | Sysmon-1     | T1059.001        | `commandLine` contient `powershell`           |
| 100111    | Sysmon-3     | T1046            | `destinationPort` in [22,23,25,3389,445,8080] |
| 100120    | Win-5140     | T1021.002        | `shareName` = `\\*\ADMIN$` ou `IPC$`         |
| 100130    | Win-4688     | T1059            | `newProcessName` contient `powershell`        |
| 100131    | Win-4688     | T1059.001        | `commandLine` contient encodage Base64        |
| 100140    | Win-5140     | T1021.002        | `shareName` admin share + `ipAddress` externe |
| 60122     | Win-4625     | T1110            | `targetUserName` + `logonType=3` + échec      |

---

## 6. Champs communs (toutes sources)

| Champ normalisé              | Description                                     |
|------------------------------|-------------------------------------------------|
| `agent.name`                 | Nom de l'agent Wazuh (`dc01`, `win01`, `linux01`) |
| `agent.ip`                   | IP de l'agent qui envoie le log                 |
| `rule.id`                    | ID de la règle Wazuh déclenchée                 |
| `rule.level`                 | Niveau de sévérité (1-15)                       |
| `rule.description`           | Description humaine de la règle                 |
| `rule.groups`                | Tags de règle (ex: `windows_security`, `socforge_purple`) |
| `timestamp`                  | Horodatage ISO 8601 de l'événement              |
| `full_log`                   | Log brut complet (avant décodage)               |
