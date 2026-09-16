# Fiche de Détection — Linux (VM11-LINUX01)

## Sources de logs collectés

| Source              | Format               | Destination Wazuh      |
|---------------------|----------------------|------------------------|
| auditd              | syslog/audit.log     | /var/log/audit/audit.log |
| syslog / auth.log   | syslog               | /var/log/auth.log       |
| /var/log/syslog     | syslog               | via Wazuh agent         |

## Règles auditd actives (socforge.rules)

| Clé (`-k`)           | Cible surveillée                              | Technique MITRE      |
|---------------------|-----------------------------------------------|----------------------|
| `auth_log`          | /var/log/auth.log, /var/log/secure            | T1078                |
| `privilege_escalation` | /bin/su, /usr/bin/sudo                     | T1548.003            |
| `sudoers_change`    | /etc/sudoers, /etc/sudoers.d/                 | T1548.003            |
| `user_accounts`     | /etc/passwd, /etc/shadow                      | T1136                |
| `group_accounts`    | /etc/group, /etc/gshadow                      | T1136                |
| `user_mgmt`         | useradd, userdel, usermod                     | T1136.001            |
| `cron_config`       | /etc/cron.*                                   | T1053.003            |
| `cron_user`         | /var/spool/cron/                              | T1053.003            |
| `hosts_file`        | /etc/hosts                                    | T1565.001            |
| `ssh_config`        | /etc/ssh/sshd_config                          | T1098                |
| `network_recon`     | nmap, nc, tcpdump                             | T1046                |
| `process_injection` | ptrace syscall                                | T1055                |
| `kernel_module`     | insmod, rmmod, modprobe                       | T1215                |
| `privilege_change`  | setuid/setgid syscalls                        | T1548                |

## Techniques détectées

### T1110 — Brute Force SSH
- **Source**: /var/log/auth.log
- **Règle Wazuh**: 5710, 5712 (natives) + seuil fréquence
- **Indicateurs**: Multiple `Failed password` pour un même utilisateur/IP
- **Commande de test**: `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.111`

### T1548.003 — Abus sudo
- **Source**: auditd key `privilege_escalation`, /var/log/auth.log
- **Indicateurs**: `sudo` exécuté par utilisateur non-autorisé, modification /etc/sudoers
- **Règle Wazuh**: 5402 (native sudo, succès) → règle custom **100200** (niveau 10, T1548.003)

### T1053.003 — Cron Job
- **Source**: auditd key `cron_config`
- **Règle Wazuh**: 100210 (niveau 10, T1053.003)
- **Indicateurs**: Modification fichiers /etc/cron.* par utilisateur non-root

### T1046 — Network Scanning
- **Source**: auditd key `network_recon`
- **Indicateurs**: Exécution de nmap, nc, tcpdump

### T1136 — Create Account
- **Source**: auditd key `user_accounts`, `user_mgmt`
- **Indicateurs**: useradd exécuté, modification /etc/passwd
