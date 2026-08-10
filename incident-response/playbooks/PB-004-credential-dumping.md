# PB-004 — Credential Dumping LSASS (T1003)

**Déclencheur**: Règle Wazuh 100103 (niveau 14, critique)
**Priorité**: Critique
**SLA MTTD cible**: < 2 minutes

---

## Phase 1 — Triage immédiat (0–2 min)

> **ALERTE CRITIQUE** — Ne jamais classer en faux positif sans analyse.

1. Identifier:
   - `sourceImage` (processus qui accède LSASS)
   - `grantedAccess` (0x1010 = lecture mémoire, 0x1fffff = accès total)
   - Machine concernée
2. Exclure les faux positifs connus:
   - MsMpEng.exe (Windows Defender)
   - csrss.exe, wininit.exe (processus système)
   - Tout autre processus → **Compromission probable**

---

## Phase 2 — Investigation (2–10 min)

1. **Identifier l'outil**:
   - `sourceImage` = PowerShell → Invoke-Mimikatz possible
   - `sourceImage` = processus inconnu → dropper/injector
   - Chercher Sysmon-8 (CreateRemoteThread) corrélatif

2. **Quelles credentials ont pu être volées?**
   - LSASS contient: hashes NTLM, tickets Kerberos, wdigest (si activé)
   - Tous les comptes connectés à la machine → identifier les sessions actives (4624 récents)

3. **Propagation**:
   - Y a-t-il eu utilisation des credentials volés? (4624 depuis une autre IP)
   - EventID 4648 (explicit credentials used)?

---

## Phase 3 — Confinement (< 15 min)

1. **URGENT**: Isoler la machine immédiatement
2. Ne pas éteindre (préserver la mémoire vive pour analyse)
3. Velociraptor → `Windows.Memory.Acquisition` (capture RAM)
4. Réinitialiser TOUS les mots de passe des comptes qui avaient une session active
5. Révoquer tous les tickets Kerberos (krbtgt si DCSync suspecté)

---

## Phase 4 — Analyse DFIR

1. Analyser la capture mémoire avec Volatility/Rekall
2. Extraire les artefacts de l'outil utilisé
3. Tracer la chaîne complète de compromission

---

## Phase 5 — Rapport critique

Rapport d'incident complet obligatoire incluant:
- Credentials potentiellement compromises
- Machines impactées
- Timeline détaillée
- Actions de remédiation
- Recommandations (PPL LSASS, Windows Credential Guard)
