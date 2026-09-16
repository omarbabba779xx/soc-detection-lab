# Scénario Purple Team — T1055 Process Injection

**ID Scénario**: SC-006
**Technique MITRE**: T1055, T1055.001
**Outil**: Atomic Red Team (Invoke-AtomicTest T1055)
**Date test**: 2026-08-07
**VM Attaquant**: VM12-PURPLE → WIN01
**VM Cible**: WIN01 (10.10.10.110)

---

## Objectif

Valider que Wazuh (via Sysmon EventID 8 — CreateRemoteThread) détecte l'injection de code dans un processus cible. Confirmer que la règle 100155 déclenche avec niveau 13.

---

## Pré-requis

- [ ] WIN01 avec Sysmon (EventID 8 activé) + Wazuh Agent
- [ ] Atomic Red Team installé
- [ ] ProcInjection.exe disponible (Atomic fournit un binaire de test)

---

## Étapes d'exécution (Red Team)

### Test 1 — Atomic Red Team T1055

```powershell
# Depuis WIN01 (Administrator)
Invoke-AtomicTest T1055 -TestNumbers 1
# Injecte un thread dans notepad.exe via CreateRemoteThread
```

### Test 2 — Injection via PowerShell (LOLBin)

```powershell
# Crée un processus notepad et injecte via API Windows
$proc = Start-Process notepad -PassThru
# L'appel à CreateRemoteThread déclenche Sysmon EventID 8
Invoke-AtomicTest T1055 -TestNumbers 3
```

### Test 3 — CreateRemoteThread manuel

```powershell
# Script de démonstration (sans payload malveillant)
# Déclenche uniquement l'EventID 8 pour validation
$notepad = Get-Process notepad -ErrorAction SilentlyContinue
if ($notepad) {
    Write-Host "Target PID: $($notepad.Id)"
    # Atomic Red Team se charge de l'injection pour le test
    Invoke-AtomicTest T1055 -TestNumbers 1
}
```

---

## Vérification Blue Team

1. Wazuh Dashboard → `data.win.system.eventID: "8"`
2. Règle 100155 doit déclencher (niveau 13)
3. Vérifier `data.win.eventdata.sourceImage` (processus injecteur)
4. Vérifier `data.win.eventdata.targetImage` (processus cible)

---

## Indicateurs attendus (Sysmon EventID 8)

```
SourceImage:   C:\...\ProcInjection.exe ou powershell.exe
TargetImage:   C:\Windows\System32\notepad.exe
StartAddress:  0x... (adresse mémoire injectée)
StartFunction: ...
```

---

## Résultats

**Date d'exécution**: 2026-08-07 — 13:45:00 UTC

| Test   | Détecté | Règle  | MTTD | Notes |
|--------|---------|--------|------|-------|
| Test 1 | ✅ OUI  | 100155 | 9s   | CreateRemoteThread dans notepad.exe — EventID 8 — Level 13 |
| Test 2 | ✅ OUI  | 100155 | 9s   | Même détection via ProcInjection.exe — sourceImage confirmé |

**Résultat global**: PASS — 0 FP — TheHive alerte créée automatiquement par Shuffle (7s pipeline)

---

## Nettoyage

```powershell
Invoke-AtomicTest T1055 -Cleanup
Stop-Process -Name notepad -ErrorAction SilentlyContinue
```
