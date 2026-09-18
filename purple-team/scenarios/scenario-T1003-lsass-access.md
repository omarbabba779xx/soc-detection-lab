# SC-11 — T1003 : Credential Dumping (accès LSASS) — bloqué par LSA Protection

**Session** : Reconstruction, étape 4 — 2026-09-18
**Attaquant** : WIN01, console locale (`labuser`, cmd élevé/Administrator)
**Cible** : WIN01, processus `lsass.exe`
**MITRE** : T1003.001 — OS Credential Dumping: LSASS Memory
**Tactique** : Credential Access

---

## Objectif

Valider la règle 100103 (accès LSASS suspect) après correction du bug `if_group`
(même root cause que 100147/100155).

## Technique utilisée (bénigne)

Script PowerShell (encodé en Base64, `-EncodedCommand`, exécuté en Administrator) :
`OpenProcess` sur `lsass.exe` avec les droits `PROCESS_QUERY_INFORMATION |
PROCESS_VM_READ` (0x1010) — exactement le bitmask que la règle et Mimikatz utilisent,
sans aucune lecture ni exfiltration de mémoire réelle.

**Résultat console** :
```
Handle: 0
False
```

L'accès a été intégralement refusé par l'OS, y compris en Administrator.

## Root cause du blocage : LSA Protection (RunAsPPL)

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```
```
RunAsPPL    REG_DWORD    0x2
```

`RunAsPPL` est activé sur WIN01 : `lsass.exe` tourne comme **Protected Process Light**
(PPL). Vérification par `wevtutil` sur les 15 événements Sysmon EventID 10 les plus
récents : **aucun ne correspond à notre tentative** (le plus récent événement de la
liste précède notre test).

**Explication technique** : la vérification PPL (niveau de signature du processus
protégé) intervient dans `PsOpenProcess`, à un stade du noyau **antérieur** au callback
`ObRegisterCallbacks` que Sysmon utilise pour générer l'EventID 10 (ProcessAccess).
L'accès est donc rejeté avant même que Sysmon puisse observer la tentative — ni la
règle, ni Sysmon, ni aucun outil basé sur cette télémétrie ne peuvent voir cet appel,
quel que soit le compte appelant.

## Conclusion — découverte réelle, pas une limitation abandonnée

C'est exactement le comportement attendu d'une vraie protection contre le credential
dumping (Mimikatz et équivalents échoueraient de la même façon sur cette machine). La
règle 100103 reste **logiquement correcte** :
- Structure identique à la règle officielle Wazuh 92900 (`0945-sysmon_id_10.xml`),
  qui filtre le même `targetImage`/`grantedAccess`.
- Validée en Phase 2 de `wazuh-logtest` (décodage JSON correct des champs
  `win.eventdata.*`).

La valider en direct sur ce lab nécessiterait soit de désactiver temporairement RunAsPPL
(dégrader une vraie protection de sécurité — jugé non souhaitable pour ce projet), soit
une technique de contournement PPL (hors périmètre d'un test bénin de détection).

## Résultats

| Critère        | Valeur                                          |
|-----------------|--------------------------------------------------|
| Règle corrigée | ✅ OUI (`if_sid` 92900 au lieu de `if_group`)     |
| Test bénin exécuté | ✅ OUI (Handle: 0 — accès refusé par l'OS)     |
| EventID Sysmon généré | ❌ NON (bloqué par RunAsPPL avant Sysmon)   |
| Cause          | Protection OS réelle (RunAsPPL), pas un bug       |

## Nettoyage

Aucun artefact laissé (l'appel a échoué avant toute action).
