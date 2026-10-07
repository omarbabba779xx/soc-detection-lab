# SC-11 : T1003, accès à LSASS (bloqué sur WIN01, validé sur DC01)

| | |
|---|---|
| Dates | 2026-09-18 (WIN01, accès bloqué par Windows) ; 2026-09-23 (DC01, alerte en direct) |
| Technique MITRE | T1003.001, OS Credential Dumping: LSASS Memory |
| Tactique | Credential Access |
| Résultat | règle 100103 (niveau 14) validée en direct sur DC01, 2 s après la tentative |

## Objectif

Valider la règle 100103 (accès suspect à la mémoire de LSASS), une fois corrigé son rattachement, le même défaut
que pour 100147 et 100155.

## En résumé

Les deux tentatives donnent deux résultats différents, et tous deux corrects :

- sur WIN01, Windows refuse l'accès avant que Sysmon puisse le voir : la protection de LSASS fonctionne ;
- sur DC01, où cette protection n'est pas activée, l'accès est accordé et la règle sonne au niveau 14.

## Tentative 1, WIN01 (18/09) : bloquée par Windows

Lancée sur la console de WIN01 (`labuser`, invite élevée).

Un script PowerShell demande l'ouverture de `lsass.exe` (`OpenProcess`) avec le masque `0x1010`
(`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`). Il ne lit aucune mémoire.

Sortie de la console :

```
Handle: 0
False
```

L'accès est refusé, y compris pour un administrateur.

### Pourquoi : la protection LSA (RunAsPPL)

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```
```
RunAsPPL    REG_DWORD    0x2
```

`RunAsPPL` est activé sur WIN01 : `lsass.exe` tourne comme processus protégé. Les 15 derniers événements Sysmon 10
du poste ont été relus avec `wevtutil` : aucun ne correspond à la tentative.

Le contrôle de la protection a lieu dans le noyau, avant le point où Sysmon est prévenu d'un accès à un processus.
La demande est donc rejetée avant d'être observée. Ni Sysmon ni la règle ne peuvent la voir, quel que soit le
compte. C'est le comportement attendu de cette protection.

## Tentative 2, DC01 (23/09) : validée en direct

Windows Server n'active pas `RunAsPPL` par défaut. L'état de la protection a été vérifié avant tout test :

```powershell
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa | Select RunAsPPL, RunAsPPLBoot, LsaCfgFlags
```

Les trois valeurs sont absentes : la protection est désactivée. Sysmon et l'agent Wazuh tournent sur DC01.

Deux points ont dû être réglés avant d'obtenir l'alerte.

Le masque d'accès. Avec `0x0410` (`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`), l'ouverture réussit, mais Windows
ajoute de lui-même `PROCESS_QUERY_LIMITED_INFORMATION` au masque accordé. Sysmon journalise alors `0x1410`, une
valeur que la règle officielle 92900 ne reconnaît pas : elle attend `0x1010` ou `0x40`.

La configuration Sysmon. Celle de DC01 (`netconfig.xml`, posée pour SC-05) ne contenait aucune règle
`ProcessAccess` : l'événement 10 n'était produit pour aucun processus. Un groupe visant `lsass.exe` a été ajouté :

```xml
<RuleGroup name="" groupRelation="or"><ProcessAccess onmatch="include">
  <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess></RuleGroup>
```

Avec le masque `0x1010`, l'ouverture réussit et Sysmon journalise `GrantedAccess=0x1010`, la valeur attendue.

Alerte dans Wazuh :

```
2026-09-23T21:30:17.556Z  100103  niveau 14  agent dc01
sourceImage=powershell.exe  targetImage=lsass.exe  grantedAccess=0x1010
```

Deux secondes après la tentative. Capture :
[`wazuh-dashboard-rule-100103-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100103-live.png)

Observation : les journaux montrent aussi Windows Defender (`MsMpEng.exe`) accéder à `lsass.exe` avec
`GrantedAccess=0x101000`, et la même règle le relève. C'est le comportement normal d'un antivirus, pas une menace.
En production, cette source serait à exclure de l'alerte.

## Résultats

| Critère | WIN01 (18/09) | DC01 (23/09) |
|---|---|---|
| Règle corrigée | oui (`if_sid` 92900 au lieu de `if_group`) | - |
| Test exécuté | oui (`Handle: 0`, accès refusé) | oui (accès accordé) |
| Événement Sysmon produit | non (refus avant Sysmon) | oui (`0x1010`, après ajout de la règle `ProcessAccess`) |
| Alerte 100103 | non (protection active, pas un défaut) | oui (niveau 14, 2 s après le test) |

## Nettoyage

WIN01 : rien à retirer, l'appel a échoué. DC01 : les fichiers de configuration temporaires (`netconfig2.xml`,
`sysmon_cfg.txt`) ont été supprimés après le test.
