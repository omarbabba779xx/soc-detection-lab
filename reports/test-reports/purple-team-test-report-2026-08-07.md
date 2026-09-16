# SocForge — Rapport de Tests Purple Team

**Date**: 2026-08-07
**Durée totale**: 4h30 (10h00–14h30 UTC)
**Testeur Red Team**: VM12-PURPLE (Kali, 10.10.10.60)
**Analyste Blue Team**: WIN01 + Wazuh Dashboard
**Résultat global**: **7/7 techniques validées — 100% de détection**

---

## Récapitulatif des résultats

| SC#  | Technique     | Outil                | Détecté | Règle  | MTTD | Résultat |
|------|---------------|----------------------|---------|--------|------|----------|
| SC-01 | T1059.001    | Atomic RT T1059.001  | Oui     | 100131 | 12s  | PASS     |
| SC-02 | T1110        | Hydra RDP+SMB        | Oui     | 100110 | 8s   | PASS     |
| SC-03 | T1046        | nmap -sV             | Oui     | 100100 | 15s  | PASS     |
| SC-04 | T1021.002    | net use / PSDrive    | Oui     | 100140 | 23s  | PASS     |
| SC-05 | T1003.001    | Atomic RT T1003.001  | Oui     | 100121 | 6s   | PASS     |
| SC-06 | T1055        | Atomic RT T1055      | Oui     | 100060 | 9s   | PASS     |
| SC-07 | T1547.001    | reg.exe + Atomic     | Oui     | 100147 | 18s  | PASS     |

**MTTD moyen**: 13.0 secondes (cible ≤60s) ✓
**Taux de détection**: 100% (7/7) ✓
**Taux de faux positifs**: 0% (0 FP sur les scénarios de test) ✓

---

## Détail par scénario

### SC-01 — T1059.001 PowerShell Exécution
- **Heure**: 10:23:47 UTC
- **Command**: `powershell.exe -EncodedCommand <base64>`
- **Détection**: Règle 100131 niveau 12 en 12s
- **SOAR**: Shuffle → MISP (aucun IOC) → Cortex (GeoIP=RFC1918) → TheHive CASE-001
- **NDR**: Sysmon EventID 1 + connexion réseau EventID 3 vers 10.10.10.60
- **Résultat**: PASS

---

### SC-02 — T1110 Brute Force
- **Heure**: 11:14:00 UTC
- **Command**: `hydra -l admin -P rockyou.txt rdp://10.10.10.109`
- **Détection**: 29 EventID 4625 → Règle 100110 en 8s
- **NDR**: Suricata SID 9100002 en 4s
- **Résultat**: PASS

---

### SC-03 — T1046 Network Scan
- **Heure**: 11:45:00 UTC
- **Command**: `nmap -sV -p 22,80,443,445,3389 10.10.10.0/24`
- **Détection**: Règle 100100 en 15s (historique — ruleset réorganisé depuis, cette détection est maintenant `100101`/`100102`, voir README) (logs OPNsense + Suricata)
- **Zeek**: `notice.log` — PurpleTeam_Unauthorized_Target (non déclenché car IP dans liste autorisée)
- **Résultat**: PASS

---

### SC-04 — T1021.002 Lateral Movement SMB
- **Heure**: 12:30:00 UTC
- **Command**: `net use \\10.10.10.109\C$ /user:SOCFORGE\administrator`
- **Détection**: EventID 5140 + 4624 Type 3 → Règle 100140 en 23s
- **NDR**: Zeek SMB monitor — connexion DC01:445 depuis WIN01
- **Résultat**: PASS

---

### SC-05 — T1003.001 LSASS Access
- **Heure**: 13:10:00 UTC
- **Command**: `Invoke-AtomicTest T1003.001 -TestNumbers 1`
- **Détection**: Sysmon EventID 10 (TargetImage: lsass.exe) → Règle 100121 niveau 14 en 6s (historique — ruleset réorganisé depuis, cette détection est maintenant `100103`, voir README)
- **Velociraptor**: Hunt LSASS détecte l'accès dans le hunt concurrent
- **Résultat**: PASS

---

### SC-06 — T1055 Process Injection
- **Heure**: 13:45:00 UTC
- **Command**: `Invoke-AtomicTest T1055 -TestNumbers 1`
- **Détection**: Sysmon EventID 8 (CreateRemoteThread) → Règle 100060 niveau 12 en 9s (historique — ruleset réorganisé depuis, cette détection est maintenant `100155` niveau 13, voir README)
- **Résultat**: PASS

---

### SC-07 — T1547.001 Registry Persistence
- **Heure**: 14:10:00 UTC
- **Command**: `reg add HKLM\...\Run /v SocForgeTest /d "calc.exe"`
- **Détection**: Sysmon EventID 13 (RegValue Set) → Règle 100147 niveau 9 en 18s
- **Nettoyage**: Clé supprimée à 14:11:30
- **Résultat**: PASS

---

## KPIs extraits de ce test

| KPI                     | Valeur          | Cible   | Statut |
|-------------------------|-----------------|---------|--------|
| MTTD moyen              | 13.0s           | ≤60s    | ✓ PASS |
| Taux de détection       | 100%            | ≥95%    | ✓ PASS |
| Taux de faux positifs   | <0.001%         | <1%     | ✓ PASS |
| SOAR automation rate    | 100%            | ≥80%    | ✓ PASS |
| Couverture MITRE        | 78% (18/23)     | ≥70%    | ✓ PASS |

---

## Observations et améliorations

1. **T1046**: Le scan nmap lent (`-T2`) peut éviter la détection Suricata — envisager une règle Zeek sur le volume de SYN sans réponse
2. **T1021.002**: Délai de 23s dû au polling Wazuh 15s — augmenter à polling 5s en production
3. **T1003.001**: Niveau 15 correct — déclenche immédiatement le SLA P1 (MTTR cible 30min)
4. **Tous scénarios**: Le workflow Shuffle fonctionne parfaitement — 0 timeout, 0 erreur API

---

## Signatures

| Rôle         | Nom            | Date       |
|--------------|----------------|------------|
| Red Team     | VM12-PURPLE    | 2026-08-07 |
| Blue Team    | Analyste SOC   | 2026-08-07 |
| Validation   | SocForge Lab   | 2026-08-07 |
