# Scénario Purple Team — T1046 Network Service Discovery

**ID Scénario**: SC-004
**Technique MITRE**: T1046
**Outil**: nmap
**Date test**: Planifié (semaine 2)
**VM Attaquant**: VM12-PURPLE (10.10.10.60)
**VM Cible**: Réseau 10.10.10.0/24

---

## Objectif

Valider que Wazuh (via Sysmon EventID 3) détecte un scan réseau effectué depuis un endpoint compromis vers d'autres machines du réseau interne.

---

## Pré-requis

- [ ] WIN01 démarrée avec Sysmon + Wazuh Agent
- [ ] nmap installé sur WIN01: `choco install nmap` ou téléchargement manuel
- [ ] VM12-PURPLE peut accéder à WIN01 pour l'exécution remote (PSRemoting ou RDP)

---

## Étapes d'exécution (Red Team)

### Test 1 — Scan depuis WIN01 (simuler attaquant sur endpoint)

```powershell
# Depuis WIN01 (attaquant simulé sur endpoint compromis)
# Scan des ports courants sur le réseau interne
nmap -sS -p 22,80,443,445,3389,5985 10.10.10.0/24 -oN scan_results.txt
```

### Test 2 — Scan avec -sV (service version)

```powershell
nmap -sV -p 80,443,445 10.10.10.10,10.10.10.20,10.10.10.30 -T4
```

### Test 3 — Atomic Red Team T1046

```powershell
Invoke-AtomicTest T1046 -TestNumbers 1
```

---

## Vérification Blue Team

1. Wazuh Dashboard → `data.win.system.eventID: "3"` + filtrer sur `agent.name: "win01"`
2. Chercher des connexions multiples depuis `nmap.exe` ou `nmap` vers des ports variés
3. Règle 100101 doit déclencher sur >10 connexions en 5 minutes
4. Règle 100102 doit déclencher si le nom du processus contient "nmap"

---

## Résultats

| Test   | Détecté | Règle  | MTTD | Notes               |
|--------|---------|--------|------|---------------------|
| Test 1 | ⏳      | 100102 | —    | À effectuer         |
| Test 2 | ⏳      | 100101 | —    | À effectuer         |
| Test 3 | ⏳      | 100101 | —    | À effectuer         |
