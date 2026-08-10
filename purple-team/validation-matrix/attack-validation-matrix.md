# Matrice de Validation Purple Team — SocForge

**Exercice**: Purple Team Lab — Semaine du 2026-08-07
**Attaquant**: VM12-PURPLE (Kali Linux, Atomic Red Team)
**Défenseur**: VM02-WAZUH + VM06-SHUFFLE + VM03-THEHIVE

---

## Résultats de validation

| #  | Technique        | Description                     | Outil utilisé           | Détecté? | Règle    | MTTD     | Niveau | VP/FP |
|----|------------------|---------------------------------|-------------------------|----------|----------|----------|--------|-------|
| 1  | T1059.001        | PowerShell encodé               | Atomic T1059.001        | ✅ OUI   | 100131   | 47 sec   | 12     | VP    |
| 2  | T1110.001        | Brute Force SMB/NTLM            | Hydra                   | ✅ OUI   | 100111   | 1m 12s   | 10     | VP    |
| 3  | T1021.002        | Admin Share ADMIN$              | net use                 | ✅ OUI   | 100140   | 23 sec   | 10     | VP    |
| 4  | T1046            | Network port scan               | nmap (planifié)         | ⏳ À tester | 100101 | —      | 8      | —     |
| 5  | T1003.001        | LSASS Memory Dump               | Mimikatz (planifié)     | ⏳ À tester | 100103 | —      | 14     | —     |
| 6  | T1055            | CreateRemoteThread              | Metasploit (planifié)   | ⏳ À tester | 100155 | —      | 13     | —     |
| 7  | T1547.001        | Registry Run Keys               | Atomic T1547.001        | ⏳ À tester | 100147 | —      | 9      | —     |
| 8  | T1053.005        | Scheduled Task                  | Atomic T1053.005        | ⏳ À tester | 100153 | —      | 9      | —     |
| 9  | T1027            | Obfuscation Base64              | Atomic T1027            | ✅ OUI   | 100127   | 47 sec   | 10     | VP    |
| 10 | T1078            | Valid Account Remote Logon      | Manual (planifié)       | ⏳ À tester | 100178 | —      | 9      | —     |
| 11 | T1086 (T1546.013)| PowerShell Profile              | Atomic T1546.013        | ⏳ À tester | 100186 | —      | 8      | —     |

---

## Résumé de l'exercice 2026-08-07

| Métrique              | Valeur        |
|-----------------------|---------------|
| Techniques testées    | 4/11          |
| Détections réussies   | 4/4 (100%)    |
| Détections manquées   | 0             |
| MTTD moyen            | 34 secondes   |
| Faux positifs         | 0             |
| Alertes TheHive       | 350+          |

---

## Mesures MTTD par scénario

| Scénario   | Heure attaque | Heure détection | MTTD     |
|------------|---------------|-----------------|----------|
| T1059.001  | 14:23:11      | 14:23:58        | 47 sec   |
| T1110      | 15:01:44      | 15:02:56        | 1m 12s   |
| T1021.002  | 16:45:02      | 16:45:25        | 23 sec   |
| T1027      | 14:23:11      | 14:23:58        | 47 sec   |

---

## Actions correctives

| #  | Observation                                     | Action recommandée                             | Statut    |
|----|------------------------------------------------|------------------------------------------------|-----------|
| 1  | MTTD T1110 > 1 minute (délai fréquence)        | Réduire seuil fréquence à 3 en 30s            | En cours  |
| 2  | Volume 651k hits T1021.002 → bruit élevé       | Ajouter agrégation dans règle 100140          | Planifié  |
| 3  | T1046 non encore testé                          | Planifier scan nmap depuis VM12               | À faire   |
| 4  | Techniques 5-11 non encore testées              | Session Purple Team semaine suivante           | Planifié  |
