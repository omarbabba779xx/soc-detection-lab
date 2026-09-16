# Scénario Purple Team — T1027 Obfuscated Files or Information

**ID Scénario**: SC-008
**Technique MITRE**: T1027
**Outil**: Atomic Red Team (`Invoke-AtomicTest T1027`)
**Date test**: 2026-08-07
**VM Attaquant**: VM12-PURPLE / WIN01 (exécution locale Atomic)
**VM Cible**: WIN01 (10.10.10.110)

---

## Objectif

Valider que Wazuh détecte une commande PowerShell contenant un payload encodé en Base64 (technique d'obfuscation courante pour dissimuler une charge malveillante dans les logs).

---

## Étapes d'exécution (Red Team)

```powershell
Invoke-AtomicTest T1027 -TestNumbers 1
```

---

## Vérification Blue Team

1. Wazuh Dashboard → `rule.id: "100127"` → doit montrer le hit
2. Vérifier `data.win.eventdata.commandLine` contient un pattern Base64 (`FromBase64String` ou chaîne longue `[a-zA-Z0-9+/]{100,}`)
3. TheHive → Alertes → `[Wazuh] Base64 obfuscation`

---

## Résultats

| Test   | Détecté | Règle  | MTTD  | Hits |
|--------|---------|--------|-------|------|
| Test 1 | ✅      | 100127 | 47s   | 10   |

**Résultat global**: PASS — 0 FP — TheHive alerte créée automatiquement par Shuffle (pipeline 7s)

---

## Nettoyage

```powershell
Invoke-AtomicTest T1027 -Cleanup
```
