# Taxonomies MITRE ATT&CK utilisées dans SocForge

## Tags MISP configurés (namespace: mitre-attack)

| Tag MISP                          | Technique     | Description                              |
|-----------------------------------|---------------|------------------------------------------|
| `mitre-attack:t1046`              | T1046         | Network Service Discovery                |
| `mitre-attack:t1059.001`          | T1059.001     | PowerShell                               |
| `mitre-attack:t1110`              | T1110         | Brute Force                              |
| `mitre-attack:t1110.001`          | T1110.001     | Password Guessing                        |
| `mitre-attack:t1021.002`          | T1021.002     | SMB/Windows Admin Shares                 |
| `mitre-attack:t1003`              | T1003         | OS Credential Dumping                    |
| `mitre-attack:t1027`              | T1027         | Obfuscated Files or Information          |
| `mitre-attack:t1078`              | T1078         | Valid Accounts                           |
| `mitre-attack:t1547.001`          | T1547.001     | Registry Run Keys / Startup Folder       |
| `mitre-attack:t1053.005`          | T1053.005     | Scheduled Task                           |
| `mitre-attack:t1055`              | T1055         | Process Injection                        |
| `mitre-attack:t1071.001`          | T1071.001     | Web Protocols (C2)                       |
| `mitre-attack:t1048.003`          | T1048.003     | DNS Exfiltration                         |
| `mitre-attack:t1105`              | T1105         | Ingress Tool Transfer                    |

## Tags TLP configurés

| Tag MISP       | Couleur | Usage dans SocForge                            |
|----------------|---------|------------------------------------------------|
| `tlp:red`      | Rouge   | IOCs du lab — usage interne uniquement         |
| `tlp:amber`    | Ambre   | IOCs partagés avec partenaires SOC             |
| `tlp:green`    | Vert    | IOCs OSINT publics (CIRCL, Botvrij)            |
| `tlp:white`    | Blanc   | IOCs totalement publics                        |

## Tags SocForge custom

| Tag                        | Description                                    |
|----------------------------|------------------------------------------------|
| `socforge:lab`             | Artefact créé dans l'environnement lab        |
| `socforge:purple-team`     | Généré lors d'un exercice Purple Team         |
| `socforge:false-positive`  | IOC confirmé comme faux positif               |
| `socforge:validated`       | IOC validé comme vrai positif                 |
