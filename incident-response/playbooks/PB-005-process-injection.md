# PB-005 — Process Injection (T1055)

**Déclencheur**: Règle Wazuh 100155 (niveau 13)
**Priorité**: Critique
**SLA MTTD cible**: < 2 minutes

---

## Phase 1 — Triage (0–2 min)

1. Identifier:
   - `sourceImage` (processus injecteur)
   - `targetImage` (processus cible)
   - Machine concernée
2. Si `targetImage` = `lsass.exe` → PB-004 en parallèle
3. Si `sourceImage` inconnu ou depuis `\Temp\` → **Vrai positif**

---

## Phase 2 — Investigation (2–15 min)

1. **Technique d'injection**:
   - CreateRemoteThread (Sysmon-8) → technique classique Meterpreter/Cobalt Strike
   - ProcessAccess (Sysmon-10) → lecture/écriture mémoire
   - CreateRemoteThread vers svchost → shellcode injection

2. **Analyser le processus source**:
   - Hash du processus source (Sysmon-1 `Hashes`)
   - VirusTotal via Cortex
   - Origine: téléchargé? depuis `\Temp\`? depuis une macro Office?

3. **Comportement post-injection**:
   - Connexions réseau depuis le processus cible (Sysmon-3)
   - DNS suspects (Sysmon-22)
   - Pipe nommés (Sysmon-17/18) → indicateur Cobalt Strike

---

## Phase 3 — Confinement

1. Isoler la machine
2. Capture mémoire RAM (Velociraptor)
3. Tuer le processus cible si possible sans déstabiliser le système

---

## Phase 4 — Rapport

1. Identifier l'implant / C2 framework
2. Documenter les IOCs (IPs C2, hashes, pipes, mutex)
3. Mettre à jour MISP avec les nouveaux IOCs
