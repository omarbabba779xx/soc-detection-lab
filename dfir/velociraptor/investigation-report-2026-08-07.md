# Rapport d'Investigation DFIR — SocForge

**Date**: 2026-08-07
**Investigateur**: Analyste SOC (SocForge Lab)
**Incident**: Purple Team Exercise — T1059.001 / T1110 / T1021.002
**Statut**: Clôturé

---

## 1. Résumé Exécutif

Dans le cadre de l'exercice Purple Team du 7 août 2026, trois scénarios d'attaque ont été simulés depuis VM12-PURPLE (Kali Linux, 10.10.10.60) vers DC01 (10.10.10.109) et WIN01 (10.10.10.110). Toutes les attaques ont été détectées par Wazuh et remontées via Shuffle vers TheHive.

**Résultats**: 3/3 attaques détectées, 350+ alertes TheHive, MTTD moyen < 3 minutes.

---

## 2. Environnement

| VM             | Rôle         | IP            | Agent Wazuh |
|----------------|--------------|---------------|-------------|
| VM12-PURPLE    | Attaquant    | 10.10.10.60   | —           |
| VM09-DC01      | Cible 1      | 10.10.10.109  | Agent 002   |
| VM10-WIN01     | Cible 2      | 10.10.10.110  | Agent 003   |
| VM02-WAZUH     | SIEM         | 10.10.10.10   | Manager     |
| VM08-DFIR-HUNT | Velociraptor | 10.10.60.10   | Serveur     |

---

## 3. Scénario 1 — T1059.001 PowerShell (WIN01)

**Outil**: Atomic Red Team `Invoke-AtomicTest T1059.001`
**Heure**: 14:23:11 UTC
**Commande exécutée**:
```
powershell.exe -nop -w hidden -enc SQBFAFgA...
```

**Détection Wazuh**:
- Règle 100121 — niveau 12 — "PowerShell encoded command"
- EventID 4688 sur WIN01, `newProcessName: powershell.exe`
- Alerte TheHive créée automatiquement par Shuffle en 47 secondes

**Résultat**: Vrai Positif ✅ — MTTD: 47 secondes

---

## 4. Scénario 2 — T1110 Brute Force (DC01)

**Outil**: Hydra (`hydra -l Administrator -P rockyou.txt smb://10.10.10.109`)
**Heure**: 15:01:44 UTC
**Volume**: 29 tentatives 4625 détectées

**Détection Wazuh**:
- Règle 60122 (native) — niveau 5 par tentative
- Règle 100111 — niveau 10 — fréquence 5 en 60s
- 29 alertes TheHive agrégées

**Résultat**: Vrai Positif ✅ — MTTD: 1 minute 12 secondes (après 5e tentative)

---

## 5. Scénario 3 — T1021.002 SMB Admin Shares (DC01)

**Outil**: `net use \\10.10.10.109\ADMIN$ /user:Administrator PASSWORD`
**Heure**: 16:45:02 UTC
**Volume**: 651,566 événements EventID 5140 détectés au total

**Détection Wazuh**:
- Règle 100140 — niveau 10 — "Admin share access"
- EventID 5140 massivement généré par accès continu

**Résultat**: Vrai Positif ✅ — MTTD: 23 secondes

---

## 6. Investigation Velociraptor

Artefacts collectés sur DC01 (Agent 002):
- `SocForge.Windows.ProcessList` → 46 processus, aucun suspect non signé
- `SocForge.Windows.NetworkConnections` → connexions SMB actives depuis 10.10.10.60
- `SocForge.Windows.EventLogHunt` → export des 4625 et 5140 sur la fenêtre de l'exercice

---

## 7. Chronologie

| Heure (UTC) | Événement |
|-------------|-----------|
| 14:23:11    | T1059.001 — PowerShell encodé exécuté sur WIN01 |
| 14:23:58    | Alerte Wazuh 100121 déclenchée |
| 14:24:05    | Shuffle crée alerte TheHive |
| 15:01:44    | T1110 — Début brute force sur DC01 |
| 15:02:56    | Règle 100111 déclenchée (5e tentative) |
| 16:45:02    | T1021.002 — Accès ADMIN$ depuis 10.10.10.60 |
| 16:45:25    | Règle 100140 déclenchée |

---

## 8. Métriques

| KPI              | Valeur           |
|------------------|------------------|
| MTTD moyen       | 1 min 27 sec     |
| MTTR             | N/A (exercice lab)|
| Vrai positifs    | 3/3 (100%)       |
| Faux positifs    | 0                |
| Alertes TheHive  | 350+             |

---

## 9. Recommandations

1. Activer PPL (Protected Process Light) pour LSASS sur DC01
2. Activer PowerShell Script Block Logging sur WIN01 (policy GPO)
3. Restreindre l'accès SMB admin aux IPs de management uniquement (10.10.10.10)
4. Déployer LAPS pour les mots de passe admin locaux
