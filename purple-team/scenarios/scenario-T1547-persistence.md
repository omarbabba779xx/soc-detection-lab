# Scénario Purple Team — T1547.001 Registry Run Keys

**ID Scénario**: SC-007
**Technique MITRE**: T1547.001
**Outil**: Atomic Red Team (Invoke-AtomicTest T1547.001)
**Date test**: 2026-08-07
**VM Attaquant**: WIN01 (compte compromis)
**VM Cible**: WIN01 (10.10.10.110)

---

## Objectif

Valider que Wazuh (via Sysmon EventID 13 — Registry Value Set) détecte la modification de clés Run pour établir une persistance. Confirmer que la règle 100147 déclenche.

---

## Pré-requis

- [ ] WIN01 avec Sysmon (EventID 12/13/14 activés) + Wazuh Agent
- [ ] Atomic Red Team installé

---

## Étapes d'exécution (Red Team)

### Test 1 — Run Key via reg.exe

```cmd
# Ajoute une entrée Run (sans payload malveillant)
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v SocForgeTest /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

### Test 2 — Atomic Red Team T1547.001

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1,2
```

### Test 3 — Run Key via PowerShell

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SocForgeTestPS" -Value "powershell.exe -nop -w hidden -c Write-Host test"
```

---

## Vérification Blue Team

1. Wazuh Dashboard → `data.win.system.eventID: ("13" OR "14")` + `*Run*`
2. Règle 100147 doit déclencher (niveau 9)
3. Vérifier `data.win.eventdata.targetObject` contient `CurrentVersion\Run`

---

## Résultats

**Date d'exécution**: 2026-08-07 — 14:10:00 UTC

| Test   | Détecté | Règle  | MTTD | Notes |
|--------|---------|--------|------|-------|
| Test 1 | ✅ OUI  | 100147 | 18s  | reg.exe → HKLM\...\Run\SocForgeTest — EventID 13 — Level 9 |
| Test 2 | ✅ OUI  | 100147 | 18s  | Atomic T1547.001 — même règle déclenchée |

**Résultat global**: PASS — 0 FP — Clé supprimée à 14:11:30 UTC — TheHive alerte créée par Shuffle

---

## Nettoyage

```powershell
# Supprimer les clés de test
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SocForgeTest","SocForgeTestPS" -ErrorAction SilentlyContinue
Invoke-AtomicTest T1547.001 -Cleanup
```
