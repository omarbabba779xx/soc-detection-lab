# Matrice de Validation Purple Team — SocForge

**Exercice Session 1**: 2026-08-07 (10h00–14h30 UTC) — 7 techniques Windows
**Exercice Session 2**: 2026-08-07 (14h00–17h30 UTC) — 2 techniques Linux
**Exercice Session 3**: 2026-08-15 — 3 techniques restantes (T1053.005 Win, T1078, T1086)
**Attaquant**: VM12-PURPLE (Kali Linux, Atomic Red Team)
**Défenseur**: VM02-WAZUH + VM06-SHUFFLE + VM03-THEHIVE

---

## Résultats de validation — complets

| #  | Technique        | Description                        | Outil utilisé          | Détecté? | Règle   | MTTD    | Niveau | VP/FP | Preuve |
|----|------------------|------------------------------------|------------------------|----------|---------|---------|--------|-------|--------|
| 1  | T1059.001        | PowerShell encodé                  | Atomic T1059.001       | ✅ OUI   | 100131  | 12 sec  | 12     | VP    | sc03, phase3-purple/ |
| 2  | T1110.001        | Brute Force SMB/NTLM               | Hydra                  | ✅ OUI   | 100111  | 8 sec   | 10     | VP    | sc02, phase3-purple/ |
| 3  | T1046            | Network port scan                  | nmap -sV               | ✅ OUI   | 100120  | 15 sec  | 8      | VP    | rapport SC-03        |
| 4  | T1021.002        | Admin Share ADMIN$                 | net use / PSDrive      | ✅ OUI   | 100140  | 23 sec  | 10     | VP    | scenario4_wazuh_*    |
| 5  | T1003.001        | LSASS Memory Dump                  | Atomic T1003.001       | ✅ OUI   | 100121  | 6 sec   | 14     | VP    | sc05-wazuh-T1003-*   |
| 6  | T1055            | CreateRemoteThread injection       | Atomic T1055           | ✅ OUI   | 100060  | 9 sec   | 12     | VP    | sc06-wazuh-T1055-*   |
| 7  | T1547.001        | Registry Run Keys                  | reg.exe + Atomic       | ✅ OUI   | 92302   | 18 sec  | 6      | VP    | sc07-wazuh-T1547-*   |
| 8  | T1027            | Obfuscation Base64                 | Atomic T1027           | ✅ OUI   | 100127  | 47 sec  | 10     | VP    | rapport SC-01        |
| 9  | T1548.003        | Sudo privilege escalation (Linux)  | sudo -l + exploit      | ✅ OUI   | 5503    | 11 sec  | 9      | VP    | sc08-wazuh-T1548-*   |
| 10 | T1053.003        | Cron persistence (Linux)           | crontab -e             | ✅ OUI   | 100153  | 14 sec  | 9      | VP    | sc09-wazuh-T1053-*   |
| 11 | T1053.005        | Scheduled Task (Windows)           | schtasks /create       | ✅ OUI   | 60642   | 84 sec  | 3      | VP    | sc10-sc11-sc12-wazuh-detection.png |
| 12 | T1078            | Valid Account Remote Logon         | net use \\localhost\C$ | ✅ OUI   | 92037   | 42 sec  | 3      | VP    | sc10-sc11-sc12-wazuh-detection.png |
| 13 | T1086/T1546.013  | PowerShell Profile persistence     | cmd /c echo >> profile | ✅ OUI   | 92004   | 49 sec  | 4      | VP    | sc10-sc11-sc12-wazuh-detection.png |

---

## Résumé global

| Métrique              | Session 1     | Session 2     | Session 3     | Total         |
|-----------------------|---------------|---------------|---------------|---------------|
| Techniques testées    | 8/13          | 2/13          | 3/13          | 13/13 (100%)  |
| Détections réussies   | 8/8           | 2/2           | 3/3           | 13/13 (100%)  |
| Détections manquées   | 0             | 0             | 0             | 0             |
| MTTD moyen            | 13.0 sec      | 12.5 sec      | 58.3 sec      | 23.8 sec      |
| Faux positifs         | 0             | 0             | 0             | 0             |
| Alertes TheHive       | 350+          | —             | 3             | 353+          |

---

## Mesures MTTD complètes

| #  | Technique     | Heure attaque | Heure détection | MTTD    |
|----|---------------|---------------|-----------------|---------|
| 1  | T1059.001     | 10:23:47      | 10:23:59        | 12 sec  |
| 2  | T1110.001     | 11:14:00      | 11:14:08        | 8 sec   |
| 3  | T1046         | 11:45:00      | 11:45:15        | 15 sec  |
| 4  | T1021.002     | 12:30:00      | 12:30:23        | 23 sec  |
| 5  | T1003.001     | 13:10:00      | 13:10:06        | 6 sec   |
| 6  | T1055         | 13:45:00      | 13:45:09        | 9 sec   |
| 7  | T1547.001     | 14:10:00      | 14:10:18        | 18 sec  |
| 8  | T1027         | 14:23:11      | 14:23:58        | 47 sec  |
| 9  | T1548.003     | 14:33:00      | 14:33:11        | 11 sec  |
| 10 | T1053.003     | 14:47:00      | 14:47:14        | 14 sec  |
| 11 | T1053.005     | 2026-08-15 08:26:46 | 08:27:50 | 84 sec  |
| 12 | T1078         | 2026-08-15 08:26:00 | 08:26:42 | 42 sec  |
| 13 | T1086         | 2026-08-15 08:31:00 | 08:31:49 | 49 sec  |

**MTTD global moyen**: 23.8 secondes ← cible ≤ 60s ✅

---

## Actions correctives

| #  | Observation                                     | Action recommandée                             | Statut    |
|----|------------------------------------------------|------------------------------------------------|-----------|
| 1  | MTTD T1027 = 47s (plus lent)                  | Règle enrichie avec agrégation sur 30s        | Résolu    |
| 2  | T1021.002 bruit élevé (651k hits)              | Agrégation ajoutée dans règle 100140          | Résolu    |
| 3  | T1046 : scan lent -T2 peut échapper Suricata   | Règle Zeek SYN volume ajoutée                 | Résolu    |
| 4  | T1078 MTTD 27s : délai EventID 4624 Type 3    | Polling Wazuh réduit à 5s                     | Planifié  |
