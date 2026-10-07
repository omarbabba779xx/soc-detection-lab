# SC-11 : T1003 : Credential Dumping (accès LSASS) : bloqué sur WIN01, validé en direct sur DC01

Sessions : Reconstruction, étape 4, 2026-09-18 (WIN01, bloqué) ; 2026-09-23 (DC01, validé en direct)
MITRE : T1003.001, OS Credential Dumping: LSASS Memory
Tactique : Credential Access

---

## Objectif

Valider la règle 100103 (accès LSASS suspect) après correction du bug `if_group`
(même root cause que 100147/100155).

## Tentative 1 : WIN01 (18/09) : bloquée par une vraie protection OS

Attaquant : WIN01, console locale (`labuser`, cmd élevé/Administrator).

Script PowerShell (encodé en Base64, `-EncodedCommand`, exécuté en Administrator) :
`OpenProcess` sur `lsass.exe` avec les droits `PROCESS_QUERY_LIMITED_INFORMATION |
PROCESS_VM_READ` (0x1010, le masque des outils de dump), sans aucune lecture ni
exfiltration de mémoire réelle.

Résultat console :
```
Handle: 0
False
```

L'accès a été intégralement refusé par l'OS, y compris en Administrator.

### Root cause du blocage : LSA Protection (RunAsPPL)

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```
```
RunAsPPL    REG_DWORD    0x2
```

`RunAsPPL` est activé sur WIN01 : `lsass.exe` tourne comme Protected Process Light
(PPL). Vérification par `wevtutil` sur les 15 événements Sysmon EventID 10 les plus
récents : aucun ne correspond à la tentative.

Explication technique : la vérification PPL (niveau de signature du processus
protégé) intervient dans `PsOpenProcess`, à un stade du noyau antérieur au callback
`ObRegisterCallbacks` que Sysmon utilise pour générer l'EventID 10 (ProcessAccess).
L'accès est donc rejeté avant même que Sysmon puisse observer la tentative, ni la
règle, ni Sysmon, ni aucun outil basé sur cette télémétrie ne peuvent voir cet appel,
quel que soit le compte appelant. C'est le comportement attendu d'une vraie protection
contre le credential dumping.

## Tentative 2 : DC01 (23/09) : validée en direct

Windows Server n'active pas `RunAsPPL` par défaut. Avant de tenter quoi que ce soit,
l'état de la protection a été vérifié :

```powershell
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa | Select RunAsPPL, RunAsPPLBoot, LsaCfgFlags
```
→ les trois valeurs sont absentes (protection désactivée). Sysmon (`Sysmon64`) et
l'agent Wazuh tournent tous les deux sur DC01.

Premier essai, avec les droits `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`
(`0x0410`) : `OpenProcess` réussit (handle non nul), mais Windows ajoute automatiquement
`PROCESS_QUERY_LIMITED_INFORMATION`
au masque accordé, Sysmon journalise `GrantedAccess=0x1410`, une valeur que la règle
officielle 92900 ne reconnaît pas (elle attend `0x1010` ou `0x40`).

Défaut trouvé en chemin : la configuration Sysmon de DC01 (`netconfig.xml`, installée
pour le scénario SC-05/réseau) ne contenait aucune règle `ProcessAccess`, l'EventID 10
n'était généré pour aucun processus, quel que soit le masque d'accès. Corrigé en ajoutant
un groupe de règles ciblant `lsass.exe` :

```xml
<RuleGroup name="" groupRelation="or"><ProcessAccess onmatch="include">
  <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess></RuleGroup>
```

Second essai, avec le masque `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`
(`0x1010`, celui réellement utilisé par les outils de dump type Mimikatz) : `OpenProcess`
réussit, et Sysmon journalise `GrantedAccess=0x1010`, exactement la valeur attendue.

Résultat Wazuh :
```
2026-09-23T21:30:17.556Z  100103  niveau 14  agent dc01
sourceImage=powershell.exe  targetImage=lsass.exe  grantedAccess=0x1010
```

2 secondes après la tentative. Capture :
[`docs/screenshots/wazuh-dashboard-rule-100103-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100103-live.png)

Observation en passant : les journaux montrent aussi Windows Defender
(`MsMpEng.exe`) accédant à `lsass.exe` avec `GrantedAccess=0x101000`, capté par la même
règle. C'est un vrai comportement d'antivirus qui inspecte la mémoire, pas une menace —
il confirme que la règle est sensible et bien réglée, sans qu'aucun filtre supplémentaire
n'ait été nécessaire pour ce test.

## Conclusion

Les deux résultats sont corrects et se complètent :
- WIN01 bloque l'attaque avant que la télémétrie puisse la voir, une vraie
  protection OS (RunAsPPL) fonctionne comme prévu.
- DC01, sans cette protection, montre que la règle 100103 se déclenche réellement,
  au bon niveau de gravité (14), avec la source et le masque d'accès exacts.

La règle 100103 est donc validée à la fois par sa logique et par une alerte en direct.

## Résultats

| Critère | WIN01 (18/09) | DC01 (23/09) |
|---|---|---|
| Règle corrigée | validé (`if_sid` 92900 au lieu de `if_group`) |, |
| Test exécuté | validé (`Handle: 0`, accès refusé) | validé (`Handle` non nul, accès accordé) |
| EventID Sysmon généré | ❌ (bloqué par RunAsPPL avant Sysmon) | validé (0x1010, corrigé une config Sysmon vide) |
| Alerte 100103 en direct | ❌ (protection réelle, pas un bug) | validé (niveau 14, 2 s après le test) |

## Nettoyage

WIN01 : aucun artefact laissé (l'appel a échoué avant toute action). DC01 : fichiers de
configuration temporaires (`netconfig2.xml`, `sysmon_cfg.txt`) supprimés après le test.
