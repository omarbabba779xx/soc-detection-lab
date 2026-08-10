# Registre des Faux Positifs — SocForge

Chaque entrée identifie un événement déclenché par une règle de détection mais qui s'est avéré légitime lors de la validation.

---

## Format d'entrée

| Champ          | Description                                              |
|----------------|----------------------------------------------------------|
| `FP-ID`        | Identifiant unique (FP-001, FP-002…)                    |
| `Règle Wazuh`  | ID de règle déclenchée                                   |
| `Technique`    | MITRE ATT&CK ID                                         |
| `Description`  | Ce qui a été détecté                                     |
| `Cause`        | Pourquoi c'est un faux positif                           |
| `Résolution`   | Action prise (exclusion, tuning, documentation)          |
| `Agent`        | VM source de l'événement                                 |
| `Date`         | Date de découverte                                       |

---

## Registre

### FP-001
| Champ        | Valeur                                                                 |
|--------------|------------------------------------------------------------------------|
| Règle Wazuh  | 100120                                                                 |
| Technique    | T1059.001                                                              |
| Agent        | win01                                                                  |
| Description  | PowerShell.exe exécuté avec `-ExecutionPolicy Bypass` par Wazuh agent lors de l'active response |
| Cause        | Wazuh active response utilise PowerShell pour exécuter ses scripts    |
| Résolution   | Ajout filtre `ParentImage contains ossec-agent` dans la règle 100120  |
| Date         | 2026-08-01                                                             |

---

### FP-002
| Champ        | Valeur                                                                 |
|--------------|------------------------------------------------------------------------|
| Règle Wazuh  | 100140                                                                 |
| Technique    | T1021.002                                                              |
| Agent        | dc01                                                                   |
| Description  | Accès au share `ADMIN$` depuis 10.10.10.10 (VM02-WAZUH)              |
| Cause        | Wazuh manager accède au share admin pour déployer des mises à jour d'agent |
| Résolution   | Exclusion de l'IP 10.10.10.10 (Wazuh Manager) dans la règle 100140   |
| Date         | 2026-08-01                                                             |

---

### FP-003
| Champ        | Valeur                                                                 |
|--------------|------------------------------------------------------------------------|
| Règle Wazuh  | 100101                                                                 |
| Technique    | T1046                                                                  |
| Agent        | win01                                                                  |
| Description  | Sysmon-3 — connexions multiples depuis `svchost.exe` vers ports 80/443 |
| Cause        | Windows Update effectuant un inventaire de services disponibles       |
| Résolution   | Exclusion de `svchost.exe` + destination Windows CDN dans la règle 100101 |
| Date         | 2026-08-02                                                             |

---

### FP-004
| Champ        | Valeur                                                                 |
|--------------|------------------------------------------------------------------------|
| Règle Wazuh  | 100147                                                                 |
| Technique    | T1547.001                                                              |
| Agent        | win01                                                                  |
| Description  | Modification de `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` par OneDrive |
| Cause        | OneDrive installe une entrée Run lors de sa première configuration    |
| Résolution   | Exclusion `Image contains OneDrive` dans règle 100147                 |
| Date         | 2026-08-02                                                             |

---

### FP-005
| Champ        | Valeur                                                                 |
|--------------|------------------------------------------------------------------------|
| Règle Wazuh  | 60122                                                                  |
| Technique    | T1110                                                                  |
| Agent        | dc01                                                                   |
| Description  | 29+ échecs 4625 sur compte `Administrator` depuis 10.10.10.60 — compte-test Atomic Red Team |
| Cause        | Scénario T1110 volontaire dans le cadre des tests Purple Team         |
| Résolution   | Documenté comme vrai positif de test. Pas d'exclusion — événement attendu. |
| Date         | 2026-08-07                                                             |

---

## Statistiques

| Technique    | Total FP | Exclusions ajoutées | Tuning règle |
|--------------|----------|---------------------|--------------|
| T1059.001    | 1        | 1                   | Oui          |
| T1021.002    | 1        | 1                   | Oui          |
| T1046        | 1        | 1                   | Oui          |
| T1547.001    | 1        | 1                   | Oui          |
| T1110        | 0        | 0                   | Non          |
| **Total**    | **4 FP** | **4**               |              |
