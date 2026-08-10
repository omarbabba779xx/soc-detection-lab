# PB-001 — PowerShell Malicieux (T1059.001)

**Déclencheur**: Règle Wazuh 100120 / 100121 / 100131 (niveau ≥ 10)
**Priorité**: Haute
**SLA MTTD cible**: < 5 minutes

---

## Phase 1 — Détection & Triage (0–5 min)

**Analyste SOC**:

1. Ouvrir l'alerte TheHive créée par Shuffle
2. Consulter le log brut dans Wazuh (OpenSearch → Threat Hunting → rule.id: 100121)
3. Évaluer: la commande PowerShell est-elle obfusquée / encodée?
   - Si `-enc` ou `-EncodedCommand` → décoder en Base64
   - Si `IEX` + URL → download cradle → **Escalader immédiatement**
4. Confirmer l'identité de l'utilisateur (`subjectUserName`)

**Décision de triage**:
- Faux positif (admin légitime) → documenter dans FP registry, fermer l'alerte
- Vrai positif → passer à Phase 2

---

## Phase 2 — Investigation (5–20 min)

**Analyste SOC**:

1. **Contexte processus**:
   - Identifier le processus parent (Sysmon EventID 1 → `parentImage`)
   - Exécution depuis `explorer.exe`? `wscript`? → suspect
   - Exécution depuis `powershell.exe` imbriqué? → très suspect

2. **Connexions réseau initiées**:
   - Chercher Sysmon EventID 3 corrélé à la même `ProcessGuid`
   - Y a-t-il une connexion vers une IP externe?

3. **Artefacts de persistance**:
   - Sysmon 13/14 → clés Run créées
   - EventID 4698 → tâche planifiée créée
   - Sysmon 11 → fichier déposé dans `\Startup\` ou `\Tasks\`

4. **Script block logging** (si disponible):
   - EventID 4104 → contenu du scriptblock
   - Chercher: `mimikatz`, `empire`, `invoke-`, `shellcode`

5. **Enrichissement Cortex**:
   - Soumettre l'IP de destination à `MaxMind_GeoIP` et `Abuse_IPdb`
   - Résultats dans TheHive → onglet Observables

---

## Phase 3 — Confinement (20–30 min)

**Si compromission confirmée**:

1. **Isoler la machine** dans OPNsense:
   - Créer une règle firewall bloquant tout trafic depuis l'IP de l'agent concerné
   - Exception: maintenir l'accès Wazuh (port 1514/1515) pour continuer la collecte

2. **Capture mémoire** via Velociraptor:
   ```
   # Dans Velociraptor → New Hunt → Windows.Memory.Acquisition
   # Cibler l'agent concerné
   ```

3. **Préserver les logs**:
   - Export OpenSearch de toute la fenêtre temporelle de l'incident (± 2h)
   - Télécharger les logs PowerShell depuis `C:\Windows\System32\winevt\Logs\`

---

## Phase 4 — Éradication

1. Tuer le processus malveillant (si encore actif) via Velociraptor Shell
2. Supprimer les artefacts de persistance identifiés en Phase 2
3. Réinitialiser les identifiants potentiellement compromis

---

## Phase 5 — Rapport & Retour d'expérience

1. Remplir la timeline complète dans TheHive
2. Calculer MTTD, MTTR
3. Mettre à jour la matrice MITRE si nouvelle technique découverte
4. Proposer une amélioration de règle si FP détecté
