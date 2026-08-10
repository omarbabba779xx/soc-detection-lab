# PB-003 — Mouvement Latéral via SMB (T1021.002)

**Déclencheur**: Règle Wazuh 100140 (niveau 10)
**Priorité**: Haute
**SLA MTTD cible**: < 5 minutes

---

## Phase 1 — Triage (0–5 min)

1. Identifier les détails de l'accès:
   - Machine source (IP) et destination (agent)
   - Share accédé: `ADMIN$`, `C$`, `IPC$`
   - Compte utilisé (`subjectUserName`)
2. L'accès est-il attendu?
   - Backup agent (Veeam, agent Wazuh) → FP probable
   - Admin IT légitime → vérifier le planning de maintenance
   - Inconnu → **Vrai positif** → passer à Phase 2

---

## Phase 2 — Investigation (5–20 min)

1. **Artefacts déposés**:
   - EventID 5145 (accès à des fichiers dans le share)
   - Fichiers `.exe`, `.ps1`, `.bat` copiés?

2. **Exécution à distance**:
   - Sysmon-1 sur la machine cible: nouveau processus parent=`services.exe`?
   - EventID 7045 (nouveau service créé) → PSEXESVC?
   - EventID 4697 (service installé)

3. **Tracer la chaîne**:
   - D'où vient l'attaquant? Quelle est la machine compromise initiale?
   - Velociraptor → `Windows.EventLogs.Evtx` sur la machine source

4. **Recherche Threat Hunting**:
   - OpenSearch: `rule.id:100140` + `agent.name:dc01` + fenêtre 24h
   - Combien de machines ont été ciblées?

---

## Phase 3 — Confinement

1. Isoler la/les machines compromises au niveau OPNsense
2. Snapshot VM pour analyse forensique
3. Rétention des logs Wazuh pour la timeline

---

## Phase 4 — Rapport

1. Timeline complète du mouvement latéral
2. Liste des machines impactées
3. IOCs extraits (IPs, noms de fichiers, hashes)
